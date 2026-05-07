package io.jenkins.plugins.omniauth;

import java.util.ArrayList;
import java.util.List;

public class OmniAuthAssignment {

    private String userId;
    private String authType;             // USER or GROUP
    private String roleId;               // role name or CUSTOM
    private String scope;                // full item path, "" = global
    private String scopeType;            // GLOBAL, FOLDER, JOB
    private List<String> customPermissions = new ArrayList<>();
    private String grantedAt;
    private String grantedBy;
    private String expiresAt;  // ISO-8601 UTC, null = no expiry

    public OmniAuthAssignment() {}

    public OmniAuthAssignment(String userId, String authType, String roleId,
                               String scope, String scopeType,
                               List<String> customPermissions,
                               String grantedAt, String grantedBy) {
        this.userId = userId;
        this.authType = authType;
        this.roleId = roleId;
        this.scope = scope != null ? scope : "";
        this.scopeType = scopeType;
        this.customPermissions = customPermissions != null ? new ArrayList<>(customPermissions) : new ArrayList<>();
        this.grantedAt = grantedAt;
        this.grantedBy = grantedBy;
    }

    public String getUserId() { return userId != null ? userId : ""; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getAuthType() { return authType != null ? authType : "USER"; }
    public void setAuthType(String authType) { this.authType = authType; }

    public String getRoleId() { return roleId != null ? roleId : ""; }
    public void setRoleId(String roleId) { this.roleId = roleId; }

    public String getScope() { return scope != null ? scope : ""; }
    public void setScope(String scope) { this.scope = scope; }

    public String getScopeType() { return scopeType != null ? scopeType : "GLOBAL"; }
    public void setScopeType(String scopeType) { this.scopeType = scopeType; }

    public List<String> getCustomPermissions() {
        return customPermissions != null ? customPermissions : new ArrayList<>();
    }
    public void setCustomPermissions(List<String> customPermissions) {
        this.customPermissions = customPermissions;
    }

    public String getGrantedAt() { return grantedAt != null ? grantedAt : ""; }
    public void setGrantedAt(String grantedAt) { this.grantedAt = grantedAt; }

    public String getGrantedBy() { return grantedBy != null ? grantedBy : ""; }
    public void setGrantedBy(String grantedBy) { this.grantedBy = grantedBy; }

    public String getExpiresAt() { return expiresAt; }
    public void setExpiresAt(String expiresAt) { this.expiresAt = (expiresAt != null && !expiresAt.isBlank()) ? expiresAt : null; }

    public boolean isExpired() {
        if (expiresAt == null || expiresAt.isBlank()) return false;
        try {
            return java.time.Instant.parse(expiresAt).isBefore(java.time.Instant.now());
        } catch (Exception e) {
            return false;
        }
    }
}
