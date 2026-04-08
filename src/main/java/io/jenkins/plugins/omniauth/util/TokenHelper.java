package io.jenkins.plugins.omniauth.util;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.concurrent.ExecutionException;

/**
 * Abstraction over the OAuth2 token operations needed by OmniAuthSecurityRealm.
 *
 * The production implementation is MsalTokenHelper (backed by MSAL4J + Azure AD).
 * Tests supply their own implementation without touching MSAL4J at all.
 */
public interface TokenHelper {

    /**
     * Builds the Microsoft Azure AD authorization URL to redirect the user's browser to.
     *
     * @param redirectUri   The registered redirect URI (finishLogin endpoint)
     * @param state         A random nonce stored in the HTTP session for CSRF protection
     * @param codeChallenge BASE64URL(SHA-256(codeVerifier)) for PKCE
     * @param nonce         A random value embedded in the ID token for replay attack prevention
     * @return              The full authorization URL string
     */
    String buildAuthorizationUrl(String redirectUri, String state,
                                 String codeChallenge, String nonce) throws Exception;

    /**
     * Exchanges an OAuth2 authorization code for tokens.
     *
     * @param authCode     The code received from Azure AD at the redirect URI
     * @param redirectUri  The same redirect URI used during the authorization request
     * @param codeVerifier The original PKCE verifier generated during commenceLogin
     * @return             The authentication result containing access token and ID token
     */
    IAuthenticationResult exchangeCodeForTokens(String authCode, String redirectUri,
                                                String codeVerifier)
            throws ExecutionException, InterruptedException;

    /**
     * Parses the JWT ID token and returns all claims.
     *
     * @param idToken The raw JWT string from the authentication result
     * @return        Parsed JWT claims set
     */
    JWTClaimsSet parseIdToken(String idToken) throws Exception;
}
