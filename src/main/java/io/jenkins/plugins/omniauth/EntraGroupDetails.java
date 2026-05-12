package io.jenkins.plugins.omniauth;

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
     * Returns the group OID. All matrix entries and assignment configs key groups by OID,
     * so this must match what is stored in the authorization strategy.
     */
    @Override
    public String getAuthority() {
        return objectId;
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
