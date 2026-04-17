package io.jenkins.plugins.omniauth;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTClaimsSet;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import org.jenkinsci.Symbol;
import io.jenkins.plugins.omniauth.util.GraphApiHelper;
import io.jenkins.plugins.omniauth.util.MsalTokenHelper;
import io.jenkins.plugins.omniauth.util.TokenHelper;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import jenkins.security.SecurityListener;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Extends Jenkins' own HudsonPrivateSecurityRealm so that all native behaviour
 * (user database, Manage Users, password reset, self-signup, Remember Me, CSRF, …)
 * is 100 % identical to Jenkins' built-in "Jenkins' own user database" realm.
 *
 * The only addition is a "Sign in with Microsoft" button on the login page, backed
 * by an OAuth2 / OIDC code flow against Microsoft Entra (Azure AD).
 *
 * Strategy: override getLoginUrl() to serve our login.jelly, which is a verbatim
 * copy of Jenkins 2.541.2's login page with the Entra button appended.
 * All other SecurityRealm methods (createSecurityComponents, loadUserByUsername2,
 * allowsSignup, signup page, …) are inherited unchanged from the parent class.
 */
public class OmniAuthSecurityRealm extends HudsonPrivateSecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthSecurityRealm.class.getName());

    static final String SESSION_OAUTH_STATE    = "omniauth_oauth_state";
    static final String SESSION_FROM_URL       = "omniauth_from_url";
    static final String SESSION_CODE_VERIFIER  = "omniauth_code_verifier";
    static final String SESSION_NONCE          = "omniauth_nonce";

    /** Azure AD configuration — may be null when Entra login is not yet configured. */
    private final EntraOAuthConfig entraConfig;

    /**
     * Cached MSAL4J helper — created once on first use and reused for all subsequent logins.
     *
     * Why transient: OmniAuthSecurityRealm is serialised by XStream for Jenkins config
     * persistence. ConfidentialClientApplication (inside MsalTokenHelper) is not
     * serialisable, so the field must be excluded from serialisation and rebuilt lazily
     * after deserialisation.
     *
     * Why volatile: multiple browser sessions can trigger concurrent logins. volatile
     * ensures the double-checked locking pattern below is safe on all JVMs (Java 5+).
     */
    private transient volatile TokenHelper cachedHelper;

    @DataBoundConstructor
    public OmniAuthSecurityRealm(boolean allowsSignup, EntraOAuthConfig entraConfig) {
        super(allowsSignup, false, null);   // enableCaptcha=false, captchaSupport=null
        this.entraConfig = entraConfig;
    }

    public EntraOAuthConfig getEntraConfig() {
        return entraConfig;
    }

    // -------------------------------------------------------------------------
    // Override only the login URL — everything else is inherited from
    // HudsonPrivateSecurityRealm without change.
    // -------------------------------------------------------------------------

    /**
     * Points Stapler at our login.jelly, which lives in:
     *   resources/io/jenkins/plugins/omniauth/OmniAuthSecurityRealm/login.jelly
     *
     * That file is an exact copy of Jenkins 2.541.2's login page with the
     * "Sign in with Microsoft" button added below the native login form.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/login";
    }

    /**
     * Called by Jenkins when validating a username in the authorization matrix UI.
     * We try the native user database first. If not found and Entra is configured,
     * any email-format username is accepted as a valid pre-provisioned Entra user
     * so admins can assign permissions before the user's first login.
     */
    @Override
    public UserDetails loadUserByUsername2(String username) throws org.springframework.security.core.userdetails.UsernameNotFoundException {
        try {
            return super.loadUserByUsername2(username);
        } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
            if (entraConfig != null && username.contains("@")) {
                return new EntraUserDetails(username, username, username, null, new ArrayList<>());
            }
            throw e;
        }
    }

    /**
     * Called by Jenkins when resolving a group name in the authorization matrix UI.
     * When group sync is enabled, we accept any group name as valid so that admins
     * can pre-add Azure AD group names to the Project Matrix before any member logs in —
     * preventing the red strikethrough that would otherwise appear.
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupname, boolean fetchMembers)
            throws org.springframework.security.core.userdetails.UsernameNotFoundException {
        if (entraConfig != null && entraConfig.isEnableGroupSync()) {
            return new GroupDetails() {
                @Override
                public String getName() { return groupname; }
            };
        }
        throw new org.springframework.security.core.userdetails.UsernameNotFoundException(groupname);
    }

    // -------------------------------------------------------------------------
    // Entra OAuth2 endpoints
    // -------------------------------------------------------------------------

    /**
     * Step 1 — redirect browser to Azure AD login page.
     * Called by OmniAuthRootAction at GET /omniauth/commenceLogin[?from=…]
     */
    HttpResponse startEntraLogin(StaplerRequest req)
            throws Exception {
        if (entraConfig == null) {
            return HttpResponses.error(503,
                    "Microsoft Entra is not configured. Ask your Jenkins administrator to set it up.");
        }

        String state = UUID.randomUUID().toString();
        req.getSession().setAttribute(SESSION_OAUTH_STATE, state);

        String from = req.getParameter("from");
        if (from != null && !from.isEmpty() && isSafeRedirectUrl(from)) {
            req.getSession().setAttribute(SESSION_FROM_URL, from);
        }

        // PKCE — generate a cryptographically random code verifier and derive its challenge
        // The verifier stays in the session; only the SHA-256 hash (challenge) goes to Azure.
        // On token exchange, Azure re-hashes the verifier and compares — proving the same
        // server that started the login is completing it.
        byte[] verifierBytes = new byte[32];
        new SecureRandom().nextBytes(verifierBytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierBytes);
        byte[] challengeBytes = MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
        req.getSession().setAttribute(SESSION_CODE_VERIFIER, codeVerifier);

        // Nonce — embedded in the ID token by Azure AD and validated on return.
        // Prevents token replay attacks where an attacker tries to reuse a previously
        // captured ID token to establish a new session.
        String nonce = UUID.randomUUID().toString();
        req.getSession().setAttribute(SESSION_NONCE, nonce);

        TokenHelper helper = createMsalTokenHelper();
        String authUrl = helper.buildAuthorizationUrl(buildRedirectUri(req), state, codeChallenge, nonce);

        LOGGER.log(Level.FINE, "Redirecting to Azure AD for Entra login");
        return HttpResponses.redirectTo(authUrl);
    }

    /**
     * Step 2 — Azure AD posts back with an authorization code.
     * Called by OmniAuthRootAction at GET /omniauth/finishLogin?code=…&state=…
     */
    HttpResponse finishEntraLogin(StaplerRequest req)
            throws Exception {
        // CSRF: validate state nonce
        String returnedState = req.getParameter("state");
        String sessionState  = (String) req.getSession().getAttribute(SESSION_OAUTH_STATE);
        if (returnedState == null || !returnedState.equals(sessionState)) {
            LOGGER.log(Level.WARNING, "OAuth2 state mismatch — session likely expired, redirecting to login");
            return HttpResponses.redirectTo(Jenkins.get().getRootUrl() + "securityRealm/login?error=session");
        }
        req.getSession().removeAttribute(SESSION_OAUTH_STATE);

        // Azure AD error (e.g. user cancelled)
        String error = req.getParameter("error");
        if (error != null) {
            LOGGER.log(Level.WARNING, "Azure AD error: {0} — {1}",
                    new Object[]{error, req.getParameter("error_description")});
            return HttpResponses.redirectTo(Jenkins.get().getRootUrl() + "login?error=entra");
        }

        String authCode = req.getParameter("code");
        if (authCode == null || authCode.isEmpty()) {
            return HttpResponses.error(400, "No authorization code received from Azure AD.");
        }

        // PKCE — retrieve the verifier stored during commenceLogin and send it to Azure.
        // Azure hashes it and checks it matches the challenge sent earlier. An attacker
        // who intercepted the authorization code cannot exchange it without this verifier.
        String codeVerifier = (String) req.getSession().getAttribute(SESSION_CODE_VERIFIER);
        req.getSession().removeAttribute(SESSION_CODE_VERIFIER);
        if (codeVerifier == null) {
            LOGGER.log(Level.WARNING, "PKCE code verifier missing from session — possible session expiry");
            return HttpResponses.redirectTo(Jenkins.get().getRootUrl() + "securityRealm/login?error=session");
        }

        // Exchange code → tokens
        TokenHelper helper = createMsalTokenHelper();
        IAuthenticationResult result = helper.exchangeCodeForTokens(authCode, buildRedirectUri(req), codeVerifier);

        JWTClaimsSet claims = helper.parseIdToken(result.idToken());

        // Nonce validation — confirm the ID token was issued for this exact login attempt.
        // Azure AD embeds the nonce we sent in the token; we verify it matches what we stored.
        String sessionNonce = (String) req.getSession().getAttribute(SESSION_NONCE);
        req.getSession().removeAttribute(SESSION_NONCE);
        String tokenNonce = MsalTokenHelper.getStringClaim(claims, "nonce");
        if (sessionNonce == null || !sessionNonce.equals(tokenNonce)) {
            LOGGER.log(Level.SEVERE, "ID token nonce mismatch — possible token replay attack, rejecting login");
            return HttpResponses.error(400, "Authentication failed: nonce validation error.");
        }

        String oid   = MsalTokenHelper.getStringClaim(claims, "oid");
        String upn   = MsalTokenHelper.getStringClaim(claims, "preferred_username");
        String name  = MsalTokenHelper.getStringClaim(claims, "name");
        String email = MsalTokenHelper.getStringClaim(claims, "email");

        if (oid == null) {
            LOGGER.log(Level.SEVERE, "ID token missing 'oid' claim — cannot identify user");
            return HttpResponses.error(500, "Microsoft did not return a valid user identifier.");
        }

        // Optional group sync
        List<EntraGroupDetails> groups = new ArrayList<>();
        if (entraConfig.isEnableGroupSync() && result.accessToken() != null) {
            try {
                groups = new GraphApiHelper().getGroupMemberships(result.accessToken());
            } catch (IOException | InterruptedException e) {
                LOGGER.log(Level.WARNING, "Graph API group sync failed — continuing without groups", e);
                NotificationService.sendGraphApiFailed(OmniAuthGlobalConfig.get(),
                        upn != null ? upn : oid, e.getMessage());
            }
        }

        // Provision / update Jenkins user
        User jenkinsUser = getOrCreateEntraUser(oid, upn, name, groups);

        // Establish Spring Security session
        EntraUserDetails userDetails = new EntraUserDetails(
                jenkinsUser.getId(), name, email, oid, groups);
        EntraAuthenticationToken auth = new EntraAuthenticationToken(userDetails);

        // Use SecurityContextImpl explicitly — Spring Security 6's holder may return
        // a deferred/lazy wrapper that doesn't serialize cleanly into the HTTP session.
        SecurityContext securityContext = new SecurityContextImpl(auth);
        SecurityContextHolder.setContext(securityContext);

        // Persist the security context into the HTTP session.
        req.getSession().setAttribute(
                org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                securityContext);

        // Jenkins's HttpSessionContextIntegrationFilter2 checks "_JENKINS_SESSION_SEED" on
        // every request and wipes the security context if it is absent or stale.
        // SecurityListener.fireAuthenticated2() tries to store it via Stapler.getCurrentRequest2()
        // (the Jakarta-Servlet API), but doFinishLogin uses the old StaplerRequest API so
        // getCurrentRequest2() returns null and the seed is never written.
        // We store it directly here to guarantee the check passes.
        jenkins.security.seed.UserSeedProperty seedProp =
                jenkinsUser.getProperty(jenkins.security.seed.UserSeedProperty.class);
        if (seedProp != null) {
            req.getSession().setAttribute(
                    jenkins.security.seed.UserSeedProperty.USER_SESSION_SEED,
                    seedProp.getSeed());
        }

        // Notify Jenkins security listeners (audit log, active sessions tracker, etc.)
        SecurityListener.fireAuthenticated2(userDetails);

        LOGGER.log(Level.INFO, "Entra login successful: {0} (OID: {1})", new Object[]{upn, oid});

        String from = (String) req.getSession().getAttribute(SESSION_FROM_URL);
        req.getSession().removeAttribute(SESSION_FROM_URL);
        String dest = (from != null && !from.isEmpty())
                ? from
                : (Jenkins.get().getRootUrl() != null ? Jenkins.get().getRootUrl() : "/");
        return HttpResponses.redirectTo(dest);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private User getOrCreateEntraUser(String oid, String upn, String displayName,
                                      List<EntraGroupDetails> groups) throws IOException {
        // Fast path: look up by UPN directly (UPN is the Jenkins user ID)
        if (upn != null && !upn.isEmpty()) {
            User existing = User.getById(upn, false);
            if (existing != null) {
                OmniAuthUserProperty prop = existing.getProperty(OmniAuthUserProperty.class);
                if (prop != null && oid.equals(prop.getEntraObjectId())) {
                    updateUserProperty(existing, oid, upn, groups);
                    return existing;
                }
            }
        }
        // Slow path: UPN may have changed — scan all users by OID
        for (User u : User.getAll()) {
            OmniAuthUserProperty prop = u.getProperty(OmniAuthUserProperty.class);
            if (prop != null && oid.equals(prop.getEntraObjectId())) {
                updateUserProperty(u, oid, upn, groups);
                return u;
            }
        }
        // New user — provision with UPN as Jenkins user ID
        String userId = (upn != null && !upn.isEmpty()) ? upn : oid;
        User newUser = User.getOrCreateByIdOrFullName(userId);
        newUser.setFullName(displayName != null ? displayName : upn);
        updateUserProperty(newUser, oid, upn, groups);
        LOGGER.log(Level.INFO, "Provisioned Jenkins user for Entra identity: {0}", upn);
        return newUser;
    }

    private void updateUserProperty(User user, String oid, String upn,
                                    List<EntraGroupDetails> groups) throws IOException {
        String now = Instant.now().toString();
        OmniAuthUserProperty prop = new OmniAuthUserProperty(oid, upn);
        prop.setGroupsLastSynced(now);
        prop.setLastLoginAt(now);
        List<String> names = new ArrayList<>();
        for (EntraGroupDetails g : groups) names.add(g.getDisplayName());
        prop.setCachedGroups(names);
        user.addProperty(prop);
        user.save();
    }

    /**
     * Returns the shared MsalTokenHelper, creating it on first call (lazy init).
     *
     * ConfidentialClientApplication is designed to be long-lived and thread-safe — MSAL4J
     * caches authority metadata, token cache, and discovery results on it. Creating a new
     * instance per login throws all that away and re-runs the authority discovery call on
     * every login. We create it once and reuse it for the lifetime of this realm instance.
     *
     * entraConfig is final, so the helper never goes stale. If an admin reconfigures the
     * realm, Jenkins creates a new OmniAuthSecurityRealm instance, which gets a fresh helper.
     *
     * Overridden in tests to inject a fake helper without touching MSAL4J.
     */
    TokenHelper createMsalTokenHelper() throws Exception {
        if (cachedHelper == null) {
            synchronized (this) {
                if (cachedHelper == null) {
                    cachedHelper = new MsalTokenHelper(entraConfig);
                }
            }
        }
        return cachedHelper;
    }

    /**
     * Returns true only for relative URLs that stay within this server.
     * Rejects absolute URLs (http/https), protocol-relative URLs (//evil.com),
     * and backslash paths (\evil.com) — all of which browsers treat as external redirects.
     * Only paths starting with a single "/" are accepted as safe post-login destinations.
     */
    private static boolean isSafeRedirectUrl(String url) {
        return url.startsWith("/")
            && !url.startsWith("//")
            && !url.startsWith("\\");
    }

    private String buildRedirectUri(StaplerRequest req) {
        String root = Jenkins.get().getRootUrl();
        if (root == null) root = req.getRootPath() + "/";
        if (root.endsWith("/")) root = root.substring(0, root.length() - 1);
        return root + "/omniauth/finishLogin";
    }

    // -------------------------------------------------------------------------
    // Descriptor
    // -------------------------------------------------------------------------

    @Extension
    @Symbol("omniAuth")
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getDisplayName() {
            return "Jenkins' own user database + Microsoft Entra (Omni Auth)";
        }

        @Override
        public SecurityRealm newInstance(StaplerRequest req, JSONObject formData)
                throws FormException {
            // Snapshot old config for diff notification
            Jenkins j = Jenkins.get();
            EntraOAuthConfig oldEntra = (j.getSecurityRealm() instanceof OmniAuthSecurityRealm)
                    ? ((OmniAuthSecurityRealm) j.getSecurityRealm()).getEntraConfig()
                    : null;
            boolean oldAllowsSignup = (j.getSecurityRealm() instanceof OmniAuthSecurityRealm)
                    && ((OmniAuthSecurityRealm) j.getSecurityRealm()).getAllowsSignup();

            boolean allowsSignup = formData.optBoolean("allowsSignup", false);

            EntraOAuthConfig entraConfig = null;
            JSONObject entraData = formData.optJSONObject("entraConfig");
            if (entraData != null && !entraData.isEmpty()) {
                String tenantId  = entraData.optString("tenantId",  "").trim();
                String clientId  = entraData.optString("clientId",  "").trim();
                String secretStr = entraData.optString("clientSecret", "").trim();
                if (!tenantId.isEmpty() && !clientId.isEmpty() && !secretStr.isEmpty()) {
                    entraConfig = new EntraOAuthConfig(
                            tenantId, clientId, hudson.util.Secret.fromString(secretStr));
                    entraConfig.setEnableGroupSync(entraData.optBoolean("enableGroupSync", false));
                }
            }

            // Send config change notification
            OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
            if (cfg != null) {
                List<String> diff = buildConfigDiff(oldAllowsSignup, allowsSignup, oldEntra, entraConfig);
                if (!diff.isEmpty()) {
                    String changedBy = currentUserId();
                    NotificationService.sendConfigChanged(cfg, changedBy, Instant.now().toString(), diff);
                }
            }

            return new OmniAuthSecurityRealm(allowsSignup, entraConfig);
        }

        private static List<String> buildConfigDiff(boolean oldSignup, boolean newSignup,
                                                     EntraOAuthConfig oldE, EntraOAuthConfig newE) {
            List<String> lines = new ArrayList<>();
            if (oldSignup != newSignup) {
                lines.add("allowsSignup: " + oldSignup + " → " + newSignup);
            }
            String oldTenant = oldE != null ? oldE.getTenantId() : "(none)";
            String newTenant = newE != null ? newE.getTenantId() : "(none)";
            if (!oldTenant.equals(newTenant)) lines.add("tenantId: " + oldTenant + " → " + newTenant);

            String oldClient = oldE != null ? oldE.getClientId() : "(none)";
            String newClient = newE != null ? newE.getClientId() : "(none)";
            if (!oldClient.equals(newClient)) lines.add("clientId: " + oldClient + " → " + newClient);

            boolean oldGroupSync = oldE != null && oldE.isEnableGroupSync();
            boolean newGroupSync = newE != null && newE.isEnableGroupSync();
            if (oldGroupSync != newGroupSync) {
                lines.add("enableGroupSync: " + oldGroupSync + " → " + newGroupSync);
            }

            // Detect secret change without exposing values
            String oldSecret = (oldE != null && oldE.getClientSecret() != null)
                    ? oldE.getClientSecret().getPlainText() : "";
            String newSecret = (newE != null && newE.getClientSecret() != null)
                    ? newE.getClientSecret().getPlainText() : "";
            if (!oldSecret.equals(newSecret)) {
                lines.add("clientSecret: [changed]");
            }
            return lines;
        }

        private static String currentUserId() {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return (auth != null && auth.getName() != null) ? auth.getName() : "unknown";
        }
    }
}
