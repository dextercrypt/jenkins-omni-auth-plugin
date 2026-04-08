package io.jenkins.plugins.omniauth;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.ITenantProfile;
import com.nimbusds.jwt.JWTClaimsSet;
import hudson.security.AuthorizationStrategy;
import hudson.security.GroupDetails;
import hudson.util.Secret;
import io.jenkins.plugins.omniauth.util.TokenHelper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.PrintWriter;
import java.io.Writer;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;

/**
 * Integration tests for OmniAuthSecurityRealm.
 *
 * Uses FakeMsalTokenHelper (a test subclass) to avoid any real Azure AD calls.
 * No HTTP requests are made — Tier 2/3 tests call startEntraLogin / finishEntraLogin
 * directly with a fake StaplerRequest proxy and capture the returned HttpResponse
 * through a fake StaplerResponse2 proxy.
 *
 * Test tiers:
 *   Tier 1 — direct method calls, no HTTP (group loading, user loading)
 *   Tier 2 — OAuth2 error cases that return before reaching Azure AD
 *   Tier 3 — full OAuth2 flow with fake token exchange
 */
public class OmniAuthSecurityRealmTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void allowAnonymousAccess() {
        j.jenkins.setAuthorizationStrategy(new AuthorizationStrategy.Unsecured());
    }

    // ─── FakeMsalTokenHelper ──────────────────────────────────────────────────

    /**
     * Test-only TokenHelper implementation. No MSAL4J initialisation whatsoever.
     * Records captured state/nonce so tests can read what was stored in the session.
     */
    static class FakeMsalTokenHelper implements TokenHelper {

        String                fakeAuthUrl = "https://fake-azure.example.com/authorize";
        IAuthenticationResult fakeResult  = null;
        JWTClaimsSet          fakeClaims  = null;

        // Captured by buildAuthorizationUrl — readable by tests after startEntraLogin
        String capturedState;
        String capturedNonce;

        @Override
        public String buildAuthorizationUrl(String redirectUri, String state,
                                            String codeChallenge, String nonce) {
            this.capturedState = state;
            this.capturedNonce = nonce;
            return fakeAuthUrl;
        }

        @Override
        public IAuthenticationResult exchangeCodeForTokens(String authCode,
                                                           String redirectUri,
                                                           String codeVerifier)
                throws ExecutionException, InterruptedException {
            return fakeResult;
        }

        @Override
        public JWTClaimsSet parseIdToken(String idToken) {
            return fakeClaims;
        }
    }

    // ─── FakeAuthResult ───────────────────────────────────────────────────────

    static class FakeAuthResult implements IAuthenticationResult {
        private final String idToken;
        private final String accessToken;

        FakeAuthResult(String idToken, String accessToken) {
            this.idToken     = idToken;
            this.accessToken = accessToken;
        }

        @Override public String accessToken()           { return accessToken; }
        @Override public String idToken()               { return idToken; }
        @Override public IAccount account()             { return null; }
        @Override public ITenantProfile tenantProfile() { return null; }
        @Override public String environment()           { return null; }
        @Override public String scopes()                { return null; }
        @Override public Date expiresOnDate()           { return null; }
    }

    // ─── FakeSession ──────────────────────────────────────────────────────────

    /**
     * In-memory HttpSession backed by a HashMap.
     * Shared across multiple fakeRequest() calls to simulate a real browser session
     * that persists state between commenceLogin and finishLogin.
     */
    static class FakeSession implements javax.servlet.http.HttpSession {
        private final Map<String, Object> attrs = new HashMap<>();

        @Override public Object getAttribute(String name)                  { return attrs.get(name); }
        @Override public void   setAttribute(String name, Object value)    { attrs.put(name, value); }
        @Override public void   removeAttribute(String name)               { attrs.remove(name); }
        @Override public Enumeration<String> getAttributeNames()           { return Collections.enumeration(attrs.keySet()); }
        @Override public String getId()                                    { return "fake-session-id"; }
        @Override public long   getCreationTime()                          { return 0; }
        @Override public long   getLastAccessedTime()                      { return 0; }
        @Override public javax.servlet.ServletContext getServletContext()   { return null; }
        @Override public void   setMaxInactiveInterval(int interval)       {}
        @Override public int    getMaxInactiveInterval()                   { return 0; }
        @Override public void   invalidate()                               { attrs.clear(); }
        @Override public boolean isNew()                                   { return false; }
        // Deprecated Servlet 2.1 methods — required by the interface
        @Override public void   putValue(String name, Object value)        { attrs.put(name, value); }
        @Override public Object getValue(String name)                      { return attrs.get(name); }
        @Override public void   removeValue(String name)                   { attrs.remove(name); }
        @Override public String[] getValueNames()                          { return attrs.keySet().toArray(new String[0]); }
        @Override public javax.servlet.http.HttpSessionContext getSessionContext() { return null; }
    }

    // ─── FakeHelperRealm ──────────────────────────────────────────────────────

    /**
     * Named static subclass so XStream serialisation never follows an inner-class
     * this$0 reference back to the test instance (which holds JenkinsRule and is
     * not serialisable).
     */
    static class FakeHelperRealm extends OmniAuthSecurityRealm {
        private final transient TokenHelper helper;

        FakeHelperRealm(EntraOAuthConfig config, FakeMsalTokenHelper helper) {
            super(false, config);
            this.helper = helper;
        }

        @Override
        TokenHelper createMsalTokenHelper() { return helper; }
    }

    // ─── Captured response ────────────────────────────────────────────────────

    static final class Resp {
        final int    status;
        final String location;

        Resp(int status, String location) {
            this.status   = status;
            this.location = location != null ? location : "";
        }
    }

    // ─── Test helpers ─────────────────────────────────────────────────────────

    private EntraOAuthConfig testConfig() { return testConfig(false); }

    private EntraOAuthConfig testConfig(boolean groupSync) {
        EntraOAuthConfig config = new EntraOAuthConfig(
                "test-tenant", "test-client-id", Secret.fromString("test-secret"));
        config.setEnableGroupSync(groupSync);
        return config;
    }

    private OmniAuthSecurityRealm realmWithFakeHelper(EntraOAuthConfig config,
                                                      FakeMsalTokenHelper helper) {
        return new FakeHelperRealm(config, helper);
    }

    private JWTClaimsSet fakeClaims(String nonce) throws Exception {
        return new JWTClaimsSet.Builder()
                .claim("oid",                "test-oid-abc123")
                .claim("preferred_username", "testuser@example.com")
                .claim("name",               "Test User")
                .claim("email",              "testuser@example.com")
                .claim("nonce",              nonce)
                .build();
    }

    /**
     * Creates a StaplerRequest proxy that serves only the methods called by
     * startEntraLogin / finishEntraLogin: getSession(), getParameter(), getRootPath().
     *
     * The same FakeSession instance must be shared across the commence + finish
     * calls so that session attributes written by startEntraLogin are visible to
     * finishEntraLogin — exactly as a real browser session works.
     */
    private StaplerRequest fakeRequest(Map<String, String> params, FakeSession session) {
        return (StaplerRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{ StaplerRequest.class },
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getSession":  return session;
                        case "getParameter": return params.get((String) args[0]);
                        case "getRootPath": return "http://localhost/jenkins";
                        default:
                            if (method.getReturnType() == boolean.class) return false;
                            if (method.getReturnType() == int.class)     return 0;
                            return null;
                    }
                });
    }

    /**
     * Drives an HttpResponse through a StaplerResponse2 proxy that captures
     * the status code and Location header without any real HTTP socket.
     *
     * HttpRedirect calls rsp.sendRedirect(int statusCode, String url) (Stapler 2-arg).
     * HttpResponseException calls rsp.setStatus(int) + rsp.getWriter() (for error body).
     *
     * Jenkins' InstallUncaughtExceptionHandler intercepts error responses and calls
     * req.setAttribute(...) before delegating to the underlying response — so fakeReq2
     * must be a non-null proxy that stubs all request methods (not just null).
     */
    private Resp captureResponse(HttpResponse httpResponse) throws Exception {
        int[]    status   = { 0 };
        String[] location = { "" };

        // Stub request — only needed so error-path interceptors can call setAttribute
        StaplerRequest2 fakeReq2 = (StaplerRequest2) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{ StaplerRequest2.class },
                (proxy, method, args) -> {
                    if (method.getReturnType() == boolean.class) return false;
                    if (method.getReturnType() == int.class)     return 0;
                    return null;
                });

        StaplerResponse2 fakeRsp2 = (StaplerResponse2) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{ StaplerResponse2.class },
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "setStatus":
                            status[0] = (int) args[0];
                            return null;
                        case "sendRedirect":
                            if (args.length == 2 && args[0] instanceof Integer) {
                                // Stapler-specific: sendRedirect(int statusCode, String url)
                                status[0]   = (int)    args[0];
                                location[0] = (String) args[1];
                            } else {
                                // Servlet standard: sendRedirect(String url)
                                status[0]   = 302;
                                location[0] = (String) args[0];
                            }
                            return null;
                        case "setContentType":
                        case "setHeader":
                        case "addHeader":
                            return null;
                        case "getWriter":
                            return new PrintWriter(Writer.nullWriter());
                        case "isCommitted":
                            return false;
                        default:
                            if (method.getReturnType() == boolean.class) return false;
                            if (method.getReturnType() == int.class)     return 0;
                            return null;
                    }
                });

        try {
            httpResponse.generateResponse(fakeReq2, fakeRsp2, null);
        } catch (RuntimeException e) {
            // Jenkins' error handler (InstallUncaughtExceptionHandler) calls
            // rsp.setStatus(code) and then tries to forward to a Jelly error page
            // via Stapler.invoke(req, rsp, jenkins, "/oops"), which fails in the
            // test environment because our fake request has no real servlet context.
            // The status code was already captured before the dispatch attempt —
            // only rethrow if we have no useful data at all.
            if (status[0] == 0 && location[0].isEmpty()) throw e;
        }
        return new Resp(status[0], location[0]);
    }

    // ─── Tier 1: Security realm method tests (no HTTP) ────────────────────────

    @Test
    public void loadGroupByGroupname2_groupSyncEnabled_returnsGroupWithCorrectName() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig(true));
        j.jenkins.setSecurityRealm(realm);

        GroupDetails group = realm.loadGroupByGroupname2("dev-team", false);

        assertNotNull(group);
        assertEquals("dev-team", group.getName());
    }

    @Test(expected = UsernameNotFoundException.class)
    public void loadGroupByGroupname2_groupSyncDisabled_throwsUsernameNotFoundException() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig(false));
        j.jenkins.setSecurityRealm(realm);

        realm.loadGroupByGroupname2("dev-team", false);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void loadGroupByGroupname2_noEntraConfig_throwsUsernameNotFoundException() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, null);
        j.jenkins.setSecurityRealm(realm);

        realm.loadGroupByGroupname2("any-group", false);
    }

    @Test
    public void loadUserByUsername2_emailFormat_whenEntraConfigured_returnsStubUserDetails() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig());
        j.jenkins.setSecurityRealm(realm);

        var userDetails = realm.loadUserByUsername2("preprovisioned@example.com");

        assertNotNull(userDetails);
        assertEquals("preprovisioned@example.com", userDetails.getUsername());
    }

    @Test(expected = UsernameNotFoundException.class)
    public void loadUserByUsername2_nonEmailFormat_whenNotInDB_throwsUsernameNotFoundException() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig());
        j.jenkins.setSecurityRealm(realm);

        realm.loadUserByUsername2("notanemail");
    }

    // ─── Tier 2: OAuth2 error cases (direct method calls, no HTTP) ───────────

    /**
     * When Entra is not configured, startEntraLogin should immediately return a
     * 503 Service Unavailable rather than crashing.
     */
    @Test
    public void commenceLogin_withNoEntraConfig_returns503() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, null);

        HttpResponse response = realm.startEntraLogin(fakeRequest(Map.of(), new FakeSession()));
        Resp resp = captureResponse(response);

        assertEquals(503, resp.status);
    }

    /**
     * When Entra is configured, startEntraLogin should redirect to the Azure AD
     * login page (returned by MsalTokenHelper.buildAuthorizationUrl) and store
     * OAuth state and OIDC nonce in the session.
     */
    @Test
    public void commenceLogin_withEntraConfig_redirectsToFakeAzureUrl() throws Exception {
        FakeMsalTokenHelper fakeHelper = new FakeMsalTokenHelper();
        OmniAuthSecurityRealm realm = realmWithFakeHelper(testConfig(), fakeHelper);
        j.jenkins.setSecurityRealm(realm);

        HttpResponse response = realm.startEntraLogin(fakeRequest(Map.of(), new FakeSession()));
        Resp resp = captureResponse(response);

        assertEquals(302, resp.status);
        assertEquals("Should redirect to URL returned by buildAuthorizationUrl",
                fakeHelper.fakeAuthUrl, resp.location);
        assertNotNull("State must be stored in session", fakeHelper.capturedState);
        assertNotNull("Nonce must be stored in session", fakeHelper.capturedNonce);
    }

    /**
     * If the OAuth state returned by Azure does not match the session (e.g. session
     * expired, CSRF attempt), finishEntraLogin should redirect to the login page with
     * error=session rather than proceeding with token exchange.
     */
    @Test
    public void finishLogin_withStateMismatch_redirectsToLoginWithSessionError() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig());
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();
        // No prior startEntraLogin → session has no oauth state → any returned state is a mismatch

        Map<String, String> params = new HashMap<>();
        params.put("state", "wrong-state");
        params.put("code",  "any");

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals(302, resp.status);
        assertTrue("Should redirect to login with session error",
                resp.location.contains("error=session"));
    }

    /**
     * If the authorization code is missing from Azure's callback (malformed request),
     * finishEntraLogin should return HTTP 400 immediately without attempting token exchange.
     * State must match to get past the CSRF check first.
     */
    @Test
    public void finishLogin_withNoAuthCode_returns400() throws Exception {
        FakeMsalTokenHelper fakeHelper = new FakeMsalTokenHelper();
        OmniAuthSecurityRealm realm = realmWithFakeHelper(testConfig(), fakeHelper);
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();

        // Establish valid state in session via commenceLogin
        realm.startEntraLogin(fakeRequest(Map.of(), session));

        // finishLogin with matching state but NO code parameter
        Map<String, String> params = new HashMap<>();
        params.put("state", fakeHelper.capturedState);
        // intentionally no "code" param

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals("Missing auth code should return 400", 400, resp.status);
    }

    /**
     * If the PKCE code verifier is missing from the session (session expired between
     * commenceLogin and finishLogin), finishEntraLogin should redirect to the login
     * page with error=session rather than attempting token exchange without PKCE.
     */
    @Test
    public void finishLogin_withMissingCodeVerifier_redirectsToLoginWithSessionError() throws Exception {
        OmniAuthSecurityRealm realm = new OmniAuthSecurityRealm(false, testConfig());
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();

        // Manually inject only the state — no code verifier — simulating a session
        // that lost its PKCE state between commenceLogin and finishLogin
        session.setAttribute(OmniAuthSecurityRealm.SESSION_OAUTH_STATE, "my-state");
        // SESSION_CODE_VERIFIER intentionally not set

        Map<String, String> params = new HashMap<>();
        params.put("state", "my-state");
        params.put("code",  "some-auth-code");

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals(302, resp.status);
        assertTrue("Missing PKCE verifier should redirect to login with session error",
                resp.location.contains("error=session"));
    }

    /**
     * When Azure returns an error parameter (e.g. user cancelled the login),
     * finishEntraLogin should redirect to the login page with error=entra.
     * The session state from commenceLogin must match for the error to be detected.
     */
    @Test
    public void finishLogin_withAzureError_redirectsToLoginWithEntraError() throws Exception {
        FakeMsalTokenHelper fakeHelper = new FakeMsalTokenHelper();
        OmniAuthSecurityRealm realm = realmWithFakeHelper(testConfig(), fakeHelper);
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();

        // Step 1: commenceLogin — stores valid state in session
        realm.startEntraLogin(fakeRequest(Map.of(), session));
        assertNotNull("State must be captured from session", fakeHelper.capturedState);

        // Step 2: finishLogin — Azure returns an error (e.g. user cancelled)
        Map<String, String> params = new HashMap<>();
        params.put("state",             fakeHelper.capturedState);
        params.put("error",             "access_denied");
        params.put("error_description", "User cancelled");

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals(302, resp.status);
        assertTrue("Should redirect to login with entra error",
                resp.location.contains("error=entra"));
    }

    // ─── Tier 3: Full OAuth2 flow (direct method calls) ──────────────────────

    /**
     * Happy path: commenceLogin followed by finishLogin with a valid code and
     * correct nonce should provision a Jenkins user and redirect to the dashboard.
     */
    @Test
    public void finishLogin_validOAuthFlow_createsJenkinsUserAndRedirects() throws Exception {
        FakeMsalTokenHelper fakeHelper = new FakeMsalTokenHelper();
        fakeHelper.fakeResult = new FakeAuthResult("fake.id.token", null); // null accessToken = no group sync

        OmniAuthSecurityRealm realm = realmWithFakeHelper(testConfig(), fakeHelper);
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();

        // Step 1: commenceLogin — stores state and nonce in session, captures them in fakeHelper
        realm.startEntraLogin(fakeRequest(Map.of(), session));
        assertNotNull("Nonce must be captured", fakeHelper.capturedNonce);

        // Step 2: arm parseIdToken to return claims with the EXACT nonce stored in the session
        fakeHelper.fakeClaims = fakeClaims(fakeHelper.capturedNonce);

        // Step 3: finishLogin with valid state + fake auth code
        Map<String, String> params = new HashMap<>();
        params.put("state", fakeHelper.capturedState);
        params.put("code",  "fake-auth-code");

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals("Should redirect after successful login", 302, resp.status);
        assertFalse("Should NOT redirect to an error page", resp.location.contains("error="));

        // Step 4: verify Jenkins user was provisioned with the correct identity
        hudson.model.User user = hudson.model.User.getById("testuser@example.com", false);
        assertNotNull("Jenkins user should have been provisioned", user);
        assertEquals("Test User", user.getFullName());

        OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
        assertNotNull("OmniAuthUserProperty should be attached", prop);
        assertEquals("test-oid-abc123",      prop.getEntraObjectId());
        assertEquals("testuser@example.com", prop.getEntraUpn());
    }

    /**
     * If the ID token carries a nonce that does not match the one stored in the
     * session (possible token replay attack), finishEntraLogin must reject the
     * request with HTTP 400 and must NOT provision a user.
     */
    @Test
    public void finishLogin_withNonceMismatchInToken_returns400() throws Exception {
        FakeMsalTokenHelper fakeHelper = new FakeMsalTokenHelper();
        fakeHelper.fakeResult = new FakeAuthResult("fake.id.token", null);
        // Token always returns the WRONG nonce — will not match what is in the session
        fakeHelper.fakeClaims = fakeClaims("wrong-nonce-will-not-match-session");

        OmniAuthSecurityRealm realm = realmWithFakeHelper(testConfig(), fakeHelper);
        j.jenkins.setSecurityRealm(realm);
        FakeSession session = new FakeSession();

        // commenceLogin — stores the real (correct) nonce in the session
        realm.startEntraLogin(fakeRequest(Map.of(), session));

        // finishLogin — token has wrong nonce → must be rejected
        Map<String, String> params = new HashMap<>();
        params.put("state", fakeHelper.capturedState);
        params.put("code",  "fake-auth-code");

        HttpResponse response = realm.finishEntraLogin(fakeRequest(params, session));
        Resp resp = captureResponse(response);

        assertEquals("Nonce mismatch should return 400", 400, resp.status);
    }
}
