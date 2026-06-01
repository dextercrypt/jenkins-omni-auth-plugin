package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.RootAction;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.core.Authentication;

import java.util.List;

/**
 * User-facing JIT endpoints — accessible to any authenticated user, not just admins.
 * Mounted at /omniauth-jit/ (RootAction, bypasses ManagementLink ADMINISTER gate).
 */
@Extension
public class OmniAuthJitAction implements RootAction {

    @Override public String getIconFileName()  { return null; } // hidden from sidebar
    @Override public String getDisplayName()   { return null; }
    @Override public String getUrlName()       { return "omniauth-jit"; }

    /**
     * GET /omniauth-jit/status?job=payments/prod/prod-pipeline
     * Returns JSON describing the JIT state for the current user + job.
     * Called by the in-page banner script via AJAX.
     */
    public void doStatus(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins j = Jenkins.getInstanceOrNull();
        if (j == null) { writeJson(rsp, "{\"hasJit\":false}"); return; }

        Authentication auth = Jenkins.getAuthentication2();
        if (auth == null || "anonymous".equals(auth.getName())) {
            writeJson(rsp, "{\"hasJit\":false}"); return;
        }

        String job = req.getParameter("job");
        if (job == null || job.isBlank()) { writeJson(rsp, "{\"hasJit\":false}"); return; }

        String userId = auth.getName();
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null) { writeJson(rsp, "{\"hasJit\":false}"); return; }

        OmniAuthAssignment jitAssignment = config.getAssignmentsForUser(userId, "USER")
                .stream()
                .filter(a -> !a.isExpired() && a.isJit() && a.getScope().equals(job))
                .findFirst().orElse(null);

        if (jitAssignment == null) { writeJson(rsp, "{\"hasJit\":false}"); return; }

        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        OmniAuthJitRequest active  = store != null ? store.findActiveForUser(userId, job)  : null;
        OmniAuthJitRequest pending = store != null ? store.findPendingForUser(userId, job) : null;

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"hasJit\":true");
        sb.append(",\"maxDurationHours\":").append(jitAssignment.getMaxDurationHours());
        sb.append(",\"approvalTimeoutHours\":").append(jitAssignment.getApprovalTimeoutHours());
        sb.append(",\"approverGroup\":\"").append(jsonEsc(jitAssignment.getApproverGroup())).append("\"");

        if (active != null) {
            sb.append(",\"status\":\"ACTIVE\"");
            sb.append(",\"requestId\":\"").append(jsonEsc(active.getRequestId())).append("\"");
            sb.append(",\"secondsRemaining\":").append(active.secondsRemaining());
            sb.append(",\"approverId\":\"").append(jsonEsc(active.getApproverId())).append("\"");
        } else if (pending != null) {
            sb.append(",\"status\":\"PENDING\"");
            sb.append(",\"requestId\":\"").append(jsonEsc(pending.getRequestId())).append("\"");
            sb.append(",\"reason\":\"").append(jsonEsc(pending.getReason())).append("\"");
            sb.append(",\"timeAgo\":\"").append(jsonEsc(pending.timeAgo())).append("\"");
        } else {
            sb.append(",\"status\":\"NONE\"");
        }
        sb.append("}");
        writeJson(rsp, sb.toString());
    }

    /**
     * POST /omniauth-jit/request
     * Creates a new JIT request for the current user.
     */
    @POST
    public void doRequest(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins j = Jenkins.getInstanceOrNull();
        if (j == null) { writeJson(rsp, "{\"ok\":false,\"error\":\"Jenkins unavailable\"}"); return; }

        Authentication auth = Jenkins.getAuthentication2();
        if (auth == null || "anonymous".equals(auth.getName())) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"Not authenticated\"}"); return;
        }

        String job          = req.getParameter("job");
        String reason       = req.getParameter("reason");
        String durStr       = req.getParameter("durationHours");
        String userId       = auth.getName();

        if (job == null || job.isBlank()) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"job is required\"}"); return;
        }
        if (reason == null || reason.isBlank()) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"reason is required\"}"); return;
        }

        int durationHours = 1;
        try { durationHours = Integer.parseInt(durStr); } catch (Exception ignored) {}

        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null) { writeJson(rsp, "{\"ok\":false,\"error\":\"Config unavailable\"}"); return; }

        OmniAuthAssignment jitAssignment = config.getAssignmentsForUser(userId, "USER")
                .stream()
                .filter(a -> !a.isExpired() && a.isJit() && a.getScope().equals(job))
                .findFirst().orElse(null);

        if (jitAssignment == null) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"No JIT eligibility for this job\"}"); return;
        }

        // Cap duration at configured max
        durationHours = Math.max(1, Math.min(durationHours, jitAssignment.getMaxDurationHours()));

        // Block duplicate pending or active request for same scope
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        if (store == null) { writeJson(rsp, "{\"ok\":false,\"error\":\"JIT store unavailable\"}"); return; }
        if (store.findActiveForUser(userId, job) != null) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"JIT access already active for this job\"}"); return;
        }
        if (store.findPendingForUser(userId, job) != null) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"A request is already pending for this job\"}"); return;
        }

        OmniAuthJitRequest jitReq = OmniAuthJitRequest.create(
                userId, job, reason, durationHours, jitAssignment.getApprovalTimeoutHours());
        store.addRequest(jitReq);

        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logJitRequested(userId, job, reason, durationHours);

        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        NotificationService.sendJitRequested(cfg, jitReq, jitAssignment.getApproverGroup());

        writeJson(rsp, "{\"ok\":true,\"requestId\":\"" + jsonEsc(jitReq.getRequestId()) + "\"}");
    }

    /**
     * POST /omniauth-jit/cancel
     * Cancels the current user's own pending JIT request.
     */
    @POST
    public void doCancel(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Authentication auth = Jenkins.getAuthentication2();
        if (auth == null || "anonymous".equals(auth.getName())) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"Not authenticated\"}"); return;
        }

        String requestId = req.getParameter("requestId");
        String userId    = auth.getName();

        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        if (store == null || requestId == null) {
            writeJson(rsp, "{\"ok\":false,\"error\":\"Invalid request\"}"); return;
        }

        OmniAuthJitRequest jitReq = store.findById(requestId);
        if (jitReq != null) {
            store.cancel(requestId, userId);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logJitCancelled(userId, jitReq.getScope());
        }
        writeJson(rsp, "{\"ok\":true}");
    }

    private static void writeJson(StaplerResponse rsp, String json) throws Exception {
        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write(json);
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "").replace("\t", " ");
    }
}
