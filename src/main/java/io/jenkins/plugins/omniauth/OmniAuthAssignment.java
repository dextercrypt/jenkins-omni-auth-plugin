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
    private String expiresAt;   // ISO-8601 UTC, null = no expiry
    private String reviewedAt;  // ISO-8601 UTC, null = never reviewed
    private String       accessType;  // STANDING (default) | JIT
    private String       approverGroup; // legacy — kept for XStream compat only; migrated to approvers on load
    private List<String> approvers = new ArrayList<>();
    private int          maxDurationHours     = 4;
    private int          approvalTimeoutHours = 4;

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

    public String getReviewedAt() { return reviewedAt; }
    public void setReviewedAt(String reviewedAt) { this.reviewedAt = (reviewedAt != null && !reviewedAt.isBlank()) ? reviewedAt : null; }

    public String getAccessType() { return accessType != null ? accessType : "STANDING"; }
    public void setAccessType(String v) { this.accessType = v; }
    public boolean isJit() { return "JIT".equalsIgnoreCase(accessType); }

    private Object readResolve() {
        if (approvers == null) approvers = new ArrayList<>();
        if (approvers.isEmpty() && approverGroup != null && !approverGroup.isBlank()) {
            approvers.add(approverGroup.trim());
        }
        return this;
    }

    public List<String> getApprovers() { return approvers != null ? approvers : new ArrayList<>(); }
    public void setApprovers(List<String> v) {
        this.approvers = v != null ? new java.util.ArrayList<>(v) : new ArrayList<>();
    }

    /** Legacy — returns the first approver, or empty string. Use getApprovers() for full list. */
    public String getApproverGroup() {
        List<String> a = getApprovers();
        return a.isEmpty() ? "" : String.join(", ", a);
    }
    public void setApproverGroup(String v) { this.approverGroup = v; }

    public int getMaxDurationHours() { return maxDurationHours > 0 ? maxDurationHours : 4; }
    public void setMaxDurationHours(int v) { this.maxDurationHours = v; }

    public int getApprovalTimeoutHours() { return approvalTimeoutHours > 0 ? approvalTimeoutHours : 4; }
    public void setApprovalTimeoutHours(int v) { this.approvalTimeoutHours = v; }

    public boolean isExpired() {
        if (expiresAt == null || expiresAt.isBlank()) return false;
        try {
            return java.time.Instant.parse(expiresAt).isBefore(java.time.Instant.now());
        } catch (Exception e) {
            return false;
        }
    }

    /** True when this assignment has not been reviewed within thresholdDays. Assignments with any expiry date are excluded. */
    public boolean isReviewDue(int thresholdDays) {
        if (expiresAt != null && !expiresAt.isBlank()) return false;
        java.time.Instant cutoff = java.time.Instant.now().minus(thresholdDays, java.time.temporal.ChronoUnit.DAYS);
        java.time.Instant baseline;
        if (reviewedAt != null && !reviewedAt.isBlank()) {
            try { baseline = java.time.Instant.parse(reviewedAt); } catch (Exception e) { return false; }
        } else if (grantedAt != null && !grantedAt.isBlank()) {
            try { baseline = java.time.Instant.parse(grantedAt); } catch (Exception e) { return false; }
        } else {
            return true; // no grant date — unknown age, treat as immediately overdue
        }
        return baseline.isBefore(cutoff);
    }
}
