package io.jenkins.plugins.dualauth;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTClaimsSet;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.dualauth.util.GraphApiHelper;
import io.jenkins.plugins.dualauth.util.MsalTokenHelper;
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
import java.time.Instant;
import java.util.ArrayList;
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
public class DualAuthSecurityRealm extends HudsonPrivateSecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(DualAuthSecurityRealm.class.getName());

    static final String SESSION_OAUTH_STATE = "dualauth_oauth_state";
    static final String SESSION_FROM_URL    = "dualauth_from_url";

    /** Azure AD configuration — may be null when Entra login is not yet configured. */
    private final EntraOAuthConfig entraConfig;

    @DataBoundConstructor
    public DualAuthSecurityRealm(boolean allowsSignup, EntraOAuthConfig entraConfig) {
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
     *   resources/io/jenkins/plugins/dualauth/DualAuthSecurityRealm/login.jelly
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

    // -------------------------------------------------------------------------
    // Entra OAuth2 endpoints
    // -------------------------------------------------------------------------

    /**
     * Step 1 — redirect browser to Azure AD login page.
     * URL: GET /securityRealm/commenceLogin[?from=…]
     */
    public HttpResponse doCommenceLogin(StaplerRequest req, StaplerResponse rsp)
            throws Exception {
        if (entraConfig == null) {
            return HttpResponses.error(503,
                    "Microsoft Entra is not configured. Ask your Jenkins administrator to set it up.");
        }

        String state = UUID.randomUUID().toString();
        req.getSession().setAttribute(SESSION_OAUTH_STATE, state);

        String from = req.getParameter("from");
        if (from != null && !from.isEmpty()) {
            req.getSession().setAttribute(SESSION_FROM_URL, from);
        }

        MsalTokenHelper helper = new MsalTokenHelper(entraConfig);
        String authUrl = helper.buildAuthorizationUrl(buildRedirectUri(req), state);

        LOGGER.log(Level.FINE, "Redirecting to Azure AD for Entra login");
        return HttpResponses.redirectTo(authUrl);
    }

    /**
     * Step 2 — Azure AD posts back with an authorization code.
     * URL: GET /securityRealm/finishLogin?code=…&state=…
     */
    public HttpResponse doFinishLogin(StaplerRequest req, StaplerResponse rsp)
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

        // Exchange code → tokens
        MsalTokenHelper helper = new MsalTokenHelper(entraConfig);
        IAuthenticationResult result = helper.exchangeCodeForTokens(authCode, buildRedirectUri(req));

        JWTClaimsSet claims = helper.parseIdToken(result.idToken());
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
        for (User u : User.getAll()) {
            DualAuthUserProperty prop = u.getProperty(DualAuthUserProperty.class);
            if (prop != null && oid.equals(prop.getEntraObjectId())) {
                updateUserProperty(u, oid, upn, groups);
                return u;
            }
        }
        // Use UPN (email) as Jenkins user ID so admins can pre-assign permissions by email
        String userId = (upn != null && !upn.isEmpty()) ? upn : oid;
        User newUser = User.getOrCreateByIdOrFullName(userId);
        newUser.setFullName(displayName != null ? displayName : upn);
        updateUserProperty(newUser, oid, upn, groups);
        LOGGER.log(Level.INFO, "Provisioned Jenkins user for Entra identity: {0}", upn);
        return newUser;
    }

    private void updateUserProperty(User user, String oid, String upn,
                                    List<EntraGroupDetails> groups) throws IOException {
        DualAuthUserProperty prop = new DualAuthUserProperty(oid, upn);
        prop.setGroupsLastSynced(Instant.now().toString());
        List<String> names = new ArrayList<>();
        for (EntraGroupDetails g : groups) names.add(g.getDisplayName());
        prop.setCachedGroups(names);
        user.addProperty(prop);
        user.save();
    }

    private String buildRedirectUri(StaplerRequest req) {
        String root = Jenkins.get().getRootUrl();
        if (root == null) root = req.getRootPath() + "/";
        if (root.endsWith("/")) root = root.substring(0, root.length() - 1);
        return root + "/securityRealm/finishLogin";
    }

    // -------------------------------------------------------------------------
    // Descriptor
    // -------------------------------------------------------------------------

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getDisplayName() {
            return "Jenkins' own user database + Microsoft Entra";
        }

        @Override
        public SecurityRealm newInstance(StaplerRequest req, JSONObject formData)
                throws FormException {
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
            return new DualAuthSecurityRealm(allowsSignup, entraConfig);
        }
    }
}
