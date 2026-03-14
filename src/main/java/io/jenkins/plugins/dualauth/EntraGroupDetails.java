package io.jenkins.plugins.dualauth;

import org.springframework.security.core.GrantedAuthority;

/**
 * Represents an Azure AD group as a Spring Security GrantedAuthority.
 * The authority string is the group display name, which must match
 * exactly what is configured in Jenkins' Matrix-based authorization strategy.
 */
public class EntraGroupDetails implements GrantedAuthority {

    private static final long serialVersionUID = 1L;

    private final String objectId;
    private final String displayName;

    public EntraGroupDetails(String objectId, String displayName) {
        this.objectId = objectId;
        this.displayName = displayName;
    }

    /**
     * Returns the group display name. This string is what Jenkins' authorization
     * strategies compare against when checking group membership.
     */
    @Override
    public String getAuthority() {
        return displayName;
    }

    public String getObjectId() {
        return objectId;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return "EntraGroup[" + displayName + "(" + objectId + ")]";
    }
}
