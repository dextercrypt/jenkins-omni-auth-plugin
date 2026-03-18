package io.jenkins.plugins.omniauth;

import hudson.security.SecurityRealm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Spring Security UserDetails implementation for a Microsoft Entra authenticated user.
 * Entra users have no local password — authentication is delegated entirely to Azure AD.
 */
public class EntraUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final String username;       // preferred_username (UPN) or OID as fallback
    private final String displayName;    // Full name from 'name' claim
    private final String email;
    private final String entraObjectId;  // Stable OID from Azure AD
    private final List<EntraGroupDetails> groups;

    public EntraUserDetails(String username, String displayName, String email,
                            String entraObjectId, List<EntraGroupDetails> groups) {
        this.username = username;
        this.displayName = displayName;
        this.email = email;
        this.entraObjectId = entraObjectId;
        this.groups = groups != null ? Collections.unmodifiableList(groups) : Collections.emptyList();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>(groups);
        // Jenkins requires the "authenticated" authority for logged-in access checks
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        return authorities;
    }

    /** Entra users have no local password. Returns null intentionally. */
    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Azure AD manages account lifecycle
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getEmail() {
        return email;
    }

    public String getEntraObjectId() {
        return entraObjectId;
    }

    public List<EntraGroupDetails> getGroups() {
        return groups;
    }
}
