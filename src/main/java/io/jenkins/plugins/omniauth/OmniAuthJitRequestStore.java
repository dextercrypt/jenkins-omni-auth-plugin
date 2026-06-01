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

    public synchronized boolean approve(String requestId, String approverId) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isPending()) return false;
        r.setStatus(OmniAuthJitRequest.STATUS_ACTIVE);
        r.setApproverId(approverId);
        r.setApprovedAt(java.time.Instant.now().toString());
        r.setExpiresAt(java.time.Instant.now()
                .plus(r.getRequestedDurationHours(), java.time.temporal.ChronoUnit.HOURS)
                .toString());
        save();
        OmniAuthAuthorizationStrategy.invalidateCache();
        return true;
    }

    public synchronized boolean deny(String requestId, String approverId, String comment) {
        OmniAuthJitRequest r = findById(requestId);
        if (r == null || !r.isPending()) return false;
        r.setStatus(OmniAuthJitRequest.STATUS_DENIED);
        r.setApproverId(approverId);
        if (comment != null && !comment.isBlank()) r.setApproverComment(comment);
        save();
        return true;
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

    /** Transitions timed-out PENDING and expired ACTIVE requests. Returns count changed. */
    public synchronized int processExpiredAndTimedOut() {
        int count = 0;
        for (OmniAuthJitRequest r : requests) {
            if (r.isTimedOut()) {
                r.setStatus(OmniAuthJitRequest.STATUS_TIMED_OUT);
                count++;
            } else if (r.isExpiredActive()) {
                r.setStatus(OmniAuthJitRequest.STATUS_EXPIRED);
                count++;
            }
        }
        if (count > 0) {
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
        }
        return count;
    }
}
