package io.jenkins.plugins.omniauth;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class OmniAuthJitRequest {

    // ── Approval entry — one per named approver, XStream-serializable ────────

    public static class ApprovalEntry {
        private String approverIdentity; // email or Jenkins username
        private String token;            // unique UUID — used in the email action link
        private String decision;         // null = pending, "APPROVED", "DENIED"
        private String remarks;
        private String decidedAt;        // ISO-8601 UTC

        public ApprovalEntry() {}

        public static ApprovalEntry create(String approverIdentity) {
            ApprovalEntry e = new ApprovalEntry();
            e.approverIdentity = approverIdentity != null ? approverIdentity.trim() : "";
            e.token = UUID.randomUUID().toString();
            return e;
        }

        public String getApproverIdentity() { return approverIdentity != null ? approverIdentity : ""; }
        public void   setApproverIdentity(String v) { this.approverIdentity = v; }
        public String getToken()            { return token != null ? token : ""; }
        public void   setToken(String v)    { this.token = v; }
        public String getDecision()         { return decision; }
        public void   setDecision(String v) { this.decision = v; }
        public String getRemarks()          { return remarks != null ? remarks : ""; }
        public void   setRemarks(String v)  { this.remarks = v; }
        public String getDecidedAt()        { return decidedAt != null ? decidedAt : ""; }
        public void   setDecidedAt(String v){ this.decidedAt = v; }

        public boolean isPending()  { return decision == null; }
        public boolean isApproved() { return "APPROVED".equals(decision); }
        public boolean isDenied()   { return "DENIED".equals(decision); }
    }

    public static final String STATUS_PENDING   = "PENDING";
    public static final String STATUS_ACTIVE    = "ACTIVE";
    public static final String STATUS_DENIED    = "DENIED";
    public static final String STATUS_EXPIRED   = "EXPIRED";
    public static final String STATUS_TIMED_OUT = "TIMED_OUT";
    public static final String STATUS_CANCELLED = "CANCELLED";
    public static final String STATUS_REVOKED   = "REVOKED";

    private String requestId;
    private String requesterId;

    private String scope;
    private String reason;
    private int    requestedDurationHours;
    private String status;
    private String requestedAt;
    private String approvedAt;
    private String approverId;
    private String approverComment;
    private String expiresAt;
    private String approvalDeadline;
    private List<ApprovalEntry> approvalEntries = new ArrayList<>();

    public OmniAuthJitRequest() {}

    public static OmniAuthJitRequest create(String requesterId, String scope,
                                             String reason, int durationHours,
                                             int approvalTimeoutHours) {
        OmniAuthJitRequest r = new OmniAuthJitRequest();
        r.requestId               = UUID.randomUUID().toString();
        r.requesterId             = requesterId;
        r.scope                   = scope;
        r.reason                  = reason;
        r.requestedDurationHours  = durationHours;
        r.status                  = STATUS_PENDING;
        r.requestedAt             = java.time.Instant.now().toString();
        r.approvalDeadline        = java.time.Instant.now()
                .plus(approvalTimeoutHours, java.time.temporal.ChronoUnit.HOURS).toString();
        return r;
    }

    // ── Getters / setters ───────────────────────────────────────────────────

    public String getRequestId()             { return requestId  != null ? requestId  : ""; }
    public void   setRequestId(String v)     { this.requestId  = v; }

    public String getRequesterId()           { return requesterId != null ? requesterId : ""; }
    public void   setRequesterId(String v)   { this.requesterId = v; }

    public String getScope()                 { return scope != null ? scope : ""; }
    public void   setScope(String v)         { this.scope = v; }

    public String getReason()                { return reason != null ? reason : ""; }
    public void   setReason(String v)        { this.reason = v; }

    public int    getRequestedDurationHours()          { return requestedDurationHours; }
    public void   setRequestedDurationHours(int v)     { this.requestedDurationHours = v; }

    public String getStatus()                { return status != null ? status : ""; }
    public void   setStatus(String v)        { this.status = v; }

    public String getRequestedAt()           { return requestedAt != null ? requestedAt : ""; }
    public void   setRequestedAt(String v)   { this.requestedAt = v; }

    public String getApprovedAt()            { return approvedAt; }
    public void   setApprovedAt(String v)    { this.approvedAt = v; }

    public String getApproverId()            { return approverId != null ? approverId : ""; }
    public void   setApproverId(String v)    { this.approverId = v; }

    public String getApproverComment()       { return approverComment != null ? approverComment : ""; }
    public void   setApproverComment(String v) { this.approverComment = v; }

    public String getExpiresAt()             { return expiresAt; }
    public void   setExpiresAt(String v)     { this.expiresAt = v; }

    public String getApprovalDeadline()      { return approvalDeadline; }
    public void   setApprovalDeadline(String v) { this.approvalDeadline = v; }

    // ── Approval entries ─────────────────────────────────────────────────────

    public List<ApprovalEntry> getApprovalEntries() {
        return approvalEntries != null ? approvalEntries : new ArrayList<>();
    }
    public void setApprovalEntries(List<ApprovalEntry> v) {
        this.approvalEntries = v != null ? v : new ArrayList<>();
    }

    public void initApprovalEntries(List<String> approvers) {
        this.approvalEntries = new ArrayList<>();
        for (String a : approvers) {
            approvalEntries.add(ApprovalEntry.create(a));
        }
    }

    public ApprovalEntry findEntryByToken(String token) {
        if (token == null) return null;
        for (ApprovalEntry e : getApprovalEntries()) {
            if (token.equals(e.getToken())) return e;
        }
        return null;
    }

    public ApprovalEntry findPendingEntryByIdentity(String identity) {
        if (identity == null) return null;
        for (ApprovalEntry e : getApprovalEntries()) {
            if (identity.equals(e.getApproverIdentity()) && e.isPending()) return e;
        }
        return null;
    }

    public boolean isFullyApproved() {
        List<ApprovalEntry> entries = getApprovalEntries();
        if (entries.isEmpty()) return false;
        return entries.stream().allMatch(ApprovalEntry::isApproved);
    }

    public int getApprovedCount() {
        return (int) getApprovalEntries().stream().filter(ApprovalEntry::isApproved).count();
    }

    public int getTotalApprovers() { return getApprovalEntries().size(); }

    /** True if userId has a pending (not yet decided) entry in the approvers list. */
    public boolean isCurrentUserApprover(String userId) {
        if (userId == null) return false;
        return getApprovalEntries().stream()
                .anyMatch(e -> e.isPending() && e.getApproverIdentity().equals(userId));
    }

    // ── State checks ────────────────────────────────────────────────────────

    public boolean isPending() { return STATUS_PENDING.equals(status); }
    public boolean isActive()  { return STATUS_ACTIVE.equals(status); }

    public boolean isTimedOut() {
        if (!STATUS_PENDING.equals(status) || approvalDeadline == null) return false;
        try { return java.time.Instant.parse(approvalDeadline).isBefore(java.time.Instant.now()); }
        catch (Exception e) { return false; }
    }

    public boolean isExpiredActive() {
        if (!STATUS_ACTIVE.equals(status) || expiresAt == null) return false;
        try { return java.time.Instant.parse(expiresAt).isBefore(java.time.Instant.now()); }
        catch (Exception e) { return false; }
    }

    public long secondsRemaining() {
        if (!STATUS_ACTIVE.equals(status) || expiresAt == null) return 0;
        try {
            long s = java.time.Instant.now().until(
                    java.time.Instant.parse(expiresAt), java.time.temporal.ChronoUnit.SECONDS);
            return Math.max(0, s);
        } catch (Exception e) { return 0; }
    }

    public String timeAgo() {
        String ts = requestedAt;
        if (ts == null || ts.isBlank()) return "";
        try {
            long mins = java.time.temporal.ChronoUnit.MINUTES.between(
                    java.time.Instant.parse(ts), java.time.Instant.now());
            if (mins < 1)  return "just now";
            if (mins < 60) return mins + "m ago";
            long hrs = mins / 60;
            if (hrs < 24)  return hrs + "h ago";
            return (hrs / 24) + "d ago";
        } catch (Exception e) { return ""; }
    }

    public String statusLabel() {
        if (status == null) return "";
        switch (status) {
            case STATUS_PENDING:   return "Pending";
            case STATUS_ACTIVE:    return "Active";
            case STATUS_DENIED:    return "Denied";
            case STATUS_EXPIRED:   return "Expired";
            case STATUS_TIMED_OUT: return "Timed Out";
            case STATUS_CANCELLED: return "Cancelled";
            case STATUS_REVOKED:   return "Revoked";
            default:               return status;
        }
    }
}
