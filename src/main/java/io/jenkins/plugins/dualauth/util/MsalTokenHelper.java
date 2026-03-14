package io.jenkins.plugins.dualauth.util;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import io.jenkins.plugins.dualauth.EntraOAuthConfig;

import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Wraps MSAL4J to build OAuth2 authorization URLs and exchange authorization codes for tokens.
 *
 * Responsibilities:
 * - Build the Azure AD /authorize URL for redirecting the user
 * - Exchange the authorization code for access + ID tokens
 * - Parse claims from the ID token JWT
 */
public class MsalTokenHelper {

    private static final Logger LOGGER = Logger.getLogger(MsalTokenHelper.class.getName());

    private final ConfidentialClientApplication msalApp;
    private final EntraOAuthConfig config;

    public MsalTokenHelper(EntraOAuthConfig config) throws Exception {
        this.config = config;
        IClientSecret clientCredential = ClientCredentialFactory.createFromSecret(
                config.getClientSecret().getPlainText()
        );
        this.msalApp = ConfidentialClientApplication.builder(
                config.getClientId(),
                clientCredential
        ).authority(config.getAuthority()).build();
    }

    /**
     * Builds the Microsoft Azure AD authorization URL to redirect the user's browser to.
     *
     * @param redirectUri   The registered redirect URI (finishLogin endpoint)
     * @param state         A random nonce stored in the HTTP session for CSRF protection
     * @param codeChallenge BASE64URL(SHA-256(codeVerifier)) for PKCE
     * @return              The full authorization URL string
     */
    public String buildAuthorizationUrl(String redirectUri, String state, String codeChallenge) throws Exception {
        Set<String> scopes = Collections.singleton(config.getScope());

        AuthorizationRequestUrlParameters params = AuthorizationRequestUrlParameters
                .builder(redirectUri, scopes)
                .responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod("S256")
                .state(state)
                .build();

        return msalApp.getAuthorizationRequestUrl(params).toString();
    }

    /**
     * Exchanges an OAuth2 authorization code for tokens.
     *
     * @param authCode     The code received from Azure AD at the redirect URI
     * @param redirectUri  The same redirect URI used during the authorization request
     * @param codeVerifier The original PKCE verifier generated during commenceLogin;
     *                     Azure hashes this and checks it matches the earlier challenge
     * @return             The authentication result containing access token and ID token
     */
    public IAuthenticationResult exchangeCodeForTokens(String authCode, String redirectUri, String codeVerifier)
            throws ExecutionException, InterruptedException {
        Set<String> scopes = Collections.singleton(config.getScope());

        AuthorizationCodeParameters params = AuthorizationCodeParameters
                .builder(authCode, URI.create(redirectUri))
                .scopes(scopes)
                .codeVerifier(codeVerifier)
                .build();

        return msalApp.acquireToken(params).get();
    }

    /**
     * Parses the JWT ID token and returns all claims.
     *
     * @param idToken The raw JWT string from the authentication result
     * @return        Parsed JWT claims set
     */
    public JWTClaimsSet parseIdToken(String idToken) throws Exception {
        JWT jwt = JWTParser.parse(idToken);
        return jwt.getJWTClaimsSet();
    }

    /**
     * Extracts a string claim safely, returning null if absent.
     */
    public static String getStringClaim(JWTClaimsSet claims, String claimName) {
        try {
            return claims.getStringClaim(claimName);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not parse claim: " + claimName, e);
            return null;
        }
    }
}
