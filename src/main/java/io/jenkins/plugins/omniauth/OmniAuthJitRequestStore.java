package io.jenkins.plugins.omniauth;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import org.jenkinsci.Symbol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

@Extension
@Symbol("omniAuthJitRequests")
public class OmniAuthJitRequestStore extends GlobalConfiguration {

    private List<OmniAuthJitRequest> requests = new CopyOnWriteArrayList<>();

    public OmniAuthJitRequestStore() { load(); }

    private Object readResolve() {
        if (!(requests instanceof CopyOnWriteArrayList)) {
            requests = new CopyOnWriteArrayList<>(
                    requests != null ? requests : Collections.emptyList());
        }
        return this;
    }

    public static OmniAuthJitRequestStore get() {
        return GlobalConfiguration.all().get(OmniAuthJitRequestStore.class);
    }

    public synchronized void addRequest(OmniAuthJitRequest r) {
        requests.add(r);
        save();
    }

    public OmniAuthJitRequest findById(String requestId) {
        if (requestId == null) return null;
        return requests.stream()
                .filter(r -> r.getRequestId().equals(requestId))
                .findFirst().orElse(null);
    }

    public OmniAuthJitRequest findActiveForUser(String userId, String scope) {
        return requests.stream()
                .filter(r -> r.getRequesterId().equals(userId)
                        && r.getScope().equals(scope)
                        && OmniAuthJitRequest.STATUS_ACTIVE.equals(r.getStatus()))
                .findFirst().orElse(null);
    }

    public OmniAuthJitRequest findPendingForUser(String userId, String scope) {
        return requests.stream()
                .filter(r -> r.getRequesterId().equals(userId)
                        && r.getScope().equals(scope)
                        && OmniAuthJitRequest.STATUS_PENDING.equals(r.getStatus()))
                .findFirst().orElse(null);
    }

    public List<OmniAuthJitRequest> getPendingRequests() {
        return requests.stream()
                .filter(r -> OmniAuthJitRequest.STATUS_PENDING.equals(r.getStatus()))
                .collect(Collectors.toList());
    }

    public int getPendingCount() {
        return (int) requests.stream()
                .filter(r -> OmniAuthJitRequest.STATUS_PENDING.equals(r.getStatus()))
                .count();
    }

    public List<OmniAuthJitRequest> getRecentRequests(int limit) {
        List<OmniAuthJitRequest> sorted = new ArrayList<>(requests);
        sorted.sort((a, b) -> {
            String ta = a.getRequestedAt() != null ? a.getRequestedAt() : "";
            String tb = b.getRequestedAt() != null ? b.getRequestedAt() : "";
            return tb.compareTo(ta);
        });
        return sorted.stream().limit(limit).collect(Collectors.toList());
    }

    public synchronized boolean cancel(String requestId, String requesterId) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isPending()) return false;
        if (!r.getRequesterId().equals(requesterId)) return false;
        r.setStatus(OmniAuthJitRequest.STATUS_CANCELLED);
        save();
        return true;
    }

    public synchronized boolean revoke(String requestId, String revokedBy) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isActive()) return false;
        r.setStatus(OmniAuthJitRequest.STATUS_REVOKED);
        r.setApproverId(revokedBy);
        save();
        OmniAuthAuthorizationStrategy.invalidateCache();
        return true;
    }

    /** Removes terminal requests older than retentionDays. Returns count purged. */
    public synchronized int purgeOldRecords(int retentionDays) {
        if (retentionDays <= 0) return 0;
        java.time.Instant cutoff = java.time.Instant.now()
                .minus(retentionDays, java.time.temporal.ChronoUnit.DAYS);
        List<OmniAuthJitRequest> toRemove = requests.stream()
                .filter(r -> isTerminalStatus(r.getStatus()) && isOlderThan(r.getRequestedAt(), cutoff))
                .collect(Collectors.toList());
        if (toRemove.isEmpty()) return 0;
        requests.removeAll(toRemove);
        save();
        return toRemove.size();
    }

    private static boolean isTerminalStatus(String status) {
        return OmniAuthJitRequest.STATUS_EXPIRED.equals(status)
                || OmniAuthJitRequest.STATUS_REVOKED.equals(status)
                || OmniAuthJitRequest.STATUS_DENIED.equals(status)
                || OmniAuthJitRequest.STATUS_TIMED_OUT.equals(status)
                || OmniAuthJitRequest.STATUS_CANCELLED.equals(status);
    }

    private static boolean isOlderThan(String requestedAt, java.time.Instant cutoff) {
        if (requestedAt == null || requestedAt.isBlank()) return false;
        try { return java.time.Instant.parse(requestedAt).isBefore(cutoff); }
        catch (Exception e) { return false; }
    }

    /** Transitions timed-out PENDING and expired ACTIVE requests. Returns the transitioned requests. */
    public synchronized List<OmniAuthJitRequest> processExpiredAndTimedOut() {
        List<OmniAuthJitRequest> transitioned = new ArrayList<>();
        for (OmniAuthJitRequest r : requests) {
            if (r.isTimedOut()) {
                r.setStatus(OmniAuthJitRequest.STATUS_TIMED_OUT);
                transitioned.add(r);
            } else if (r.isExpiredActive()) {
                r.setStatus(OmniAuthJitRequest.STATUS_EXPIRED);
                transitioned.add(r);
            }
        }
        if (!transitioned.isEmpty()) {
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
        }
        return transitioned;
    }

    // ── Per-approver action methods ──────────────────────────────────────────

    /** Returns the most recent request for this user+scope regardless of status, or null. */
    public OmniAuthJitRequest findLastRequestForUser(String userId, String scope) {
        return requests.stream()
                .filter(r -> r.getRequesterId().equals(userId) && r.getScope().equals(scope))
                .max(java.util.Comparator.comparing(r -> r.getRequestedAt() != null ? r.getRequestedAt() : ""))
                .orElse(null);
    }

    public OmniAuthJitRequest findByToken(String token) {
        if (token == null) return null;
        return requests.stream()
                .filter(r -> r.findEntryByToken(token) != null)
                .findFirst().orElse(null);
    }

    public enum ActionResult { TOKEN_NOT_FOUND, ALREADY_PROCESSED, PARTIAL_APPROVED, ALL_APPROVED, DENIED }

    public synchronized ActionResult processApproverAction(String token, String decision, String remarks) {
        OmniAuthJitRequest r = findByToken(token);
        if (r == null) return ActionResult.TOKEN_NOT_FOUND;
        if (!r.isPending()) return ActionResult.ALREADY_PROCESSED;

        OmniAuthJitRequest.ApprovalEntry entry = r.findEntryByToken(token);
        if (entry == null || !entry.isPending()) return ActionResult.ALREADY_PROCESSED;

        entry.setDecision(decision);
        entry.setRemarks(remarks != null ? remarks : "");
        entry.setDecidedAt(java.time.Instant.now().toString());

        if ("DENIED".equals(decision)) {
            r.setStatus(OmniAuthJitRequest.STATUS_DENIED);
            r.setApproverId(entry.getApproverIdentity());
            if (remarks != null && !remarks.isBlank()) r.setApproverComment(remarks);
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
            return ActionResult.DENIED;
        }

        if (r.isFullyApproved()) {
            r.setStatus(OmniAuthJitRequest.STATUS_ACTIVE);
            r.setApprovedAt(java.time.Instant.now().toString());
            r.setExpiresAt(java.time.Instant.now()
                    .plus(r.getRequestedDurationHours(), java.time.temporal.ChronoUnit.HOURS).toString());
            r.setApproverId(entry.getApproverIdentity());
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
            return ActionResult.ALL_APPROVED;
        }

        save();
        return ActionResult.PARTIAL_APPROVED;
    }

    /** Admin approves via Jenkins page — only works if approverId is a listed approver. Returns true if went ACTIVE. */
    public synchronized boolean approveAsApprover(String requestId, String approverId) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isPending()) return false;
        OmniAuthJitRequest.ApprovalEntry entry = r.findPendingEntryByIdentity(approverId);
        if (entry == null) return false;

        entry.setDecision("APPROVED");
        entry.setDecidedAt(java.time.Instant.now().toString());

        if (r.isFullyApproved()) {
            r.setStatus(OmniAuthJitRequest.STATUS_ACTIVE);
            r.setApprovedAt(java.time.Instant.now().toString());
            r.setExpiresAt(java.time.Instant.now()
                    .plus(r.getRequestedDurationHours(), java.time.temporal.ChronoUnit.HOURS).toString());
            r.setApproverId(approverId);
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
            return true;
        }
        save();
        return false;
    }

    /** Admin denies via Jenkins page — only works if approverId is a listed approver. */
    public synchronized boolean denyAsApprover(String requestId, String approverId, String comment) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isPending()) return false;
        OmniAuthJitRequest.ApprovalEntry entry = r.findPendingEntryByIdentity(approverId);
        if (entry == null) return false;

        entry.setDecision("DENIED");
        entry.setRemarks(comment != null ? comment : "");
        entry.setDecidedAt(java.time.Instant.now().toString());
        r.setStatus(OmniAuthJitRequest.STATUS_DENIED);
        r.setApproverId(approverId);
        if (comment != null && !comment.isBlank()) r.setApproverComment(comment);
        save();
        OmniAuthAuthorizationStrategy.invalidateCache();
        return true;
    }
}
