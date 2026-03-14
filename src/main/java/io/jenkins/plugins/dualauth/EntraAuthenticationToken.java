package io.jenkins.plugins.dualauth;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Spring Security Authentication token for a Microsoft Entra authenticated user.
 * Created after successful OAuth2 code exchange and placed into the SecurityContext.
 */
public class EntraAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final EntraUserDetails principal;

    public EntraAuthenticationToken(EntraUserDetails principal) {
        super(principal.getAuthorities());
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        // Credentials are not stored after authentication is established
        return null;
    }

    @Override
    public EntraUserDetails getPrincipal() {
        return principal;
    }

    @Override
    public String getName() {
        return principal.getUsername();
    }

    /**
     * Returns a comma-separated list of group names for logging/debugging.
     */
    public String getGroupSummary() {
        return principal.getGroups().stream()
                .map(EntraGroupDetails::getDisplayName)
                .collect(Collectors.joining(", "));
    }
}
