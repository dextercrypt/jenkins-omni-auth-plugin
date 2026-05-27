package io.jenkins.plugins.omniauth;

import java.util.List;

/**
 * Dispatches OmniAuth notification events to all subscribed channels (SMTP, Slack, Teams).
 * Each channel independently decides which events it receives.
 * SMTP receives full HTML; Slack/Teams receive plain text.
 */
public class NotificationService {

    private NotificationService() {}

    private static String rootUrl() {
        try {
            String r = jenkins.model.Jenkins.get().getRootUrl();
            if (r == null || r.isEmpty()) return "";
            return r.endsWith("/") ? r.substring(0, r.length() - 1) : r;
        } catch (Exception e) { return ""; }
    }

    private static String ctaLine(String label, String path) {
        String root = rootUrl();
        if (root.isEmpty()) return "";
        return "\nCTA: " + label + " | " + root + "/manage/omniauth-management/" + path;
    }

    private static void dispatch(OmniAuthGlobalConfig cfg, String event,
                                  String subject, String plainBody, String htmlBody) {
        if (cfg == null || !cfg.isNotificationsEnabled()) return;
        if (cfg.isSmtpEvent(event))  SmtpHelper.send(cfg, subject, htmlBody, plainBody);
        if (cfg.isSlackEvent(event)) SlackHelper.send(cfg, subject, plainBody);
        if (cfg.isTeamsEvent(event)) TeamsHelper.send(cfg, subject, plainBody);
    }

    // -------------------------------------------------------------------------
    // Event: Stale cleanup ran
    // -------------------------------------------------------------------------

    public static void sendCleanupReport(OmniAuthGlobalConfig cfg,
                                          OmniAuthGlobalConfig.CleanupRunRecord record) {
        if (cfg == null) return;
        String mode    = record.isDryRun() ? "Dry-run" : "Live";
        String subject = "[Jenkins OmniAuth] Stale user cleanup ran (" + mode + ")";

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Stale User Cleanup Report\n")
             .append("===================================\n\n")
             .append("Mode:              ").append(mode).append("\n")
             .append("Run at:            ").append(record.getTimestamp()).append("\n")
             .append("Users scanned:     ").append(record.getUsersScanned()).append("\n")
             .append("Users affected:    ").append(record.getUsersAffected()).append("\n")
             .append("Protected skipped: ").append(record.getSkippedProtected()).append("\n");
        List<String> affected = record.getAffectedUserIds();
        if (!affected.isEmpty()) {
            plain.append("\n").append(record.isDryRun() ? "Would delete:" : "Deleted users:").append("\n");
            for (String uid : affected) plain.append("  - ").append(uid).append("\n");
        } else {
            plain.append("\nNo users were ").append(record.isDryRun() ? "flagged" : "deleted").append(".\n");
        }
        plain.append(ctaLine("View Stale Users", "staleUsers"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "cleanup", subject, plain.toString(),
                SmtpHelper.buildCleanupReportHtml(cfg, record));
    }

    // -------------------------------------------------------------------------
    // Event: User manually deleted
    // -------------------------------------------------------------------------

    public static void sendUserDeleted(OmniAuthGlobalConfig cfg,
                                        String deletedUserId, String deletedBy) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] User deleted: " + deletedUserId;
        String plain = "OmniAuth User Deletion Notice\n"
                + "=============================\n\n"
                + "Deleted user: " + deletedUserId + "\n"
                + "Deleted by:   " + deletedBy + "\n"
                + ctaLine("View User Status", "userStatus")
                + "\n---\nJenkins OmniAuth Plugin";

        dispatch(cfg, "userDeleted", subject, plain,
                SmtpHelper.buildUserDeletedHtml(cfg, deletedUserId, deletedBy));
    }

    // -------------------------------------------------------------------------
    // Event: OmniAuth config changed
    // -------------------------------------------------------------------------

    public static void sendConfigChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                          String timestamp, List<String> diffLines) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Configuration changed by " + changedBy;

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Configuration Change\n")
             .append("=============================\n\n")
             .append("Changed by: ").append(changedBy).append("\n")
             .append("When:       ").append(timestamp).append("\n\n")
             .append("Changes:\n");
        for (String line : diffLines) plain.append("  ").append(line).append("\n");
        plain.append(ctaLine("Review Settings", "notifications"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "configChanged", subject, plain.toString(),
                SmtpHelper.buildConfigChangedHtml(cfg, changedBy, timestamp, diffLines));
    }

    // -------------------------------------------------------------------------
    // Event: Protected users list changed
    // -------------------------------------------------------------------------

    public static void sendProtectedListChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                                  List<String> added, List<String> removed) {
        if (cfg == null) return;
        if (added.isEmpty() && removed.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] Protected users list changed";

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Protected Users Change\n")
             .append("================================\n\n")
             .append("Changed by: ").append(changedBy).append("\n\n");
        if (!added.isEmpty()) {
            plain.append("Added to protected:\n");
            for (String u : added) plain.append("  + ").append(u).append("\n");
        }
        if (!removed.isEmpty()) {
            plain.append("Removed from protected:\n");
            for (String u : removed) plain.append("  - ").append(u).append("\n");
        }
        plain.append(ctaLine("View Protected Users", "staleUsers"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "protectedListChanged", subject, plain.toString(),
                SmtpHelper.buildProtectedListChangedHtml(cfg, changedBy, added, removed));
    }

    // -------------------------------------------------------------------------
    // Event: Brute force threshold hit
    // -------------------------------------------------------------------------

    public static void sendBruteForceAlert(OmniAuthGlobalConfig cfg,
                                            String username, int failureCount) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Possible brute force — "
                + failureCount + " failed logins for: " + username;
        String plain = "OmniAuth Brute Force Alert\n"
                + "==========================\n\n"
                + "Username:       " + username + "\n"
                + "Failed logins:  " + failureCount + "\n\n"
                + "Consecutive login failures have reached the configured threshold.\n"
                + "This may indicate a brute force or credential stuffing attempt.\n\n"
                + "The counter resets after a successful login.\n"
                + ctaLine("View User Status", "userStatus")
                + "\n---\nJenkins OmniAuth Plugin";

        dispatch(cfg, "bruteForce", subject, plain,
                SmtpHelper.buildBruteForceHtml(cfg, username, failureCount));
    }

    // -------------------------------------------------------------------------
    // Event: Stale warning digest
    // -------------------------------------------------------------------------

    public static void sendStaleWarningDigest(OmniAuthGlobalConfig cfg,
                                               List<String> approachingUsers,
                                               int windowDays, int thresholdDays) {
        if (cfg == null || approachingUsers.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] " + approachingUsers.size()
                + " user(s) approaching stale threshold";

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Stale User Warning\n")
             .append("===========================\n\n")
             .append("The following users have not logged in for more than ")
             .append(thresholdDays - windowDays).append(" days\n")
             .append("and will become stale (").append(thresholdDays)
             .append(" days) within the next ").append(windowDays).append(" days:\n\n");
        for (String uid : approachingUsers) plain.append("  - ").append(uid).append("\n");
        plain.append("\nConsider reaching out or adding them to the protected list if they should be kept.\n")
             .append(ctaLine("View Stale Users", "staleUsers"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "staleWarning", subject, plain.toString(),
                SmtpHelper.buildStaleWarningHtml(cfg, approachingUsers, windowDays, thresholdDays));
    }

    // -------------------------------------------------------------------------
    // Event: Admin permission granted
    // -------------------------------------------------------------------------

    public static void sendAdminGranted(OmniAuthGlobalConfig cfg,
                                         List<String> newAdmins, String grantedBy) {
        if (cfg == null || newAdmins.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] Admin permission granted to "
                + newAdmins.size() + " user(s)";

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Admin Grant Alert\n")
             .append("==========================\n\n")
             .append("Granted by: ").append(grantedBy).append("\n\n")
             .append("New admins:\n");
        for (String uid : newAdmins) plain.append("  + ").append(uid).append("\n");
        plain.append("\nThese users now have full Jenkins ADMINISTER permission.\n")
             .append(ctaLine("Review Access", "access"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "adminGranted", subject, plain.toString(),
                SmtpHelper.buildAdminGrantedHtml(cfg, newAdmins, grantedBy));
    }

    // -------------------------------------------------------------------------
    // Event: Access review digest
    // -------------------------------------------------------------------------

    public static void sendAccessReviewDigest(OmniAuthGlobalConfig cfg,
                                               List<OmniAuthAssignment> overdue,
                                               int thresholdDays) {
        if (cfg == null || overdue.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] " + overdue.size()
                + " access assignment(s) pending review (" + thresholdDays + "+ days old)";

        StringBuilder plain = new StringBuilder();
        plain.append("OmniAuth Access Review Digest\n")
             .append("=============================\n\n")
             .append("The following assignments have not been reviewed in over ")
             .append(thresholdDays).append(" days:\n\n");
        for (OmniAuthAssignment a : overdue) {
            plain.append("  - ").append(a.getUserId())
                 .append(" | ").append(a.getRoleId())
                 .append(" on ").append(a.getScope().isEmpty() ? "(global)" : a.getScope())
                 .append("\n");
        }
        plain.append("\nReview each assignment and keep or revoke as appropriate.\n")
             .append(ctaLine("Open Access Review", "accessReview"))
             .append("\n---\nJenkins OmniAuth Plugin");

        dispatch(cfg, "accessReview", subject, plain.toString(),
                SmtpHelper.buildAccessReviewHtml(cfg, overdue, thresholdDays));
    }

    // -------------------------------------------------------------------------
    // Event: Graph API failed
    // -------------------------------------------------------------------------

    public static void sendGraphApiFailed(OmniAuthGlobalConfig cfg,
                                           String userId, String errorMessage) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Graph API failure — group sync broken";
        String plain = "OmniAuth Graph API Failure\n"
                + "==========================\n\n"
                + "User affected: " + userId + "\n"
                + "Error:         " + errorMessage + "\n\n"
                + "Group sync is not working. Check your Entra app registration permissions.\n"
                + "Required: GroupMember.Read.All with admin consent.\n"
                + ctaLine("Open Dashboard", "")
                + "\n---\nJenkins OmniAuth Plugin";

        dispatch(cfg, "graphApiFailure", subject, plain,
                SmtpHelper.buildGraphApiFailedHtml(cfg, userId, errorMessage));
    }
}
