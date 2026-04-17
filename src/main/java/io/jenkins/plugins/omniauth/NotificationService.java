package io.jenkins.plugins.omniauth;

import java.util.List;

/**
 * Dispatches OmniAuth notification events to all subscribed channels (SMTP, Slack, Teams).
 * Each channel independently decides which events it receives.
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

    private static void dispatch(OmniAuthGlobalConfig cfg, String event, String subject, String body) {
        if (cfg == null || !cfg.isNotificationsEnabled()) return;
        if (cfg.isSmtpEvent(event))  SmtpHelper.send(cfg, subject, body);
        if (cfg.isSlackEvent(event)) SlackHelper.send(cfg, subject, body);
        if (cfg.isTeamsEvent(event)) TeamsHelper.send(cfg, subject, body);
    }

    // -------------------------------------------------------------------------
    // Event: Stale cleanup ran
    // -------------------------------------------------------------------------

    public static void sendCleanupReport(OmniAuthGlobalConfig cfg, OmniAuthGlobalConfig.CleanupRunRecord record) {
        if (cfg == null) return;
        String mode    = record.isDryRun() ? "Dry-run" : "Live";
        String subject = "[Jenkins OmniAuth] Stale user cleanup ran (" + mode + ")";
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Stale User Cleanup Report\n");
        body.append("===================================\n\n");
        body.append("Mode:              ").append(mode).append("\n");
        body.append("Run at:            ").append(record.getTimestamp()).append("\n");
        body.append("Users scanned:     ").append(record.getUsersScanned()).append("\n");
        body.append("Users affected:    ").append(record.getUsersAffected()).append("\n");
        body.append("Protected skipped: ").append(record.getSkippedProtected()).append("\n");
        List<String> affected = record.getAffectedUserIds();
        if (!affected.isEmpty()) {
            body.append("\n").append(record.isDryRun() ? "Would delete:" : "Deleted users:").append("\n");
            for (String uid : affected) body.append("  - ").append(uid).append("\n");
        } else {
            body.append("\nNo users were ").append(record.isDryRun() ? "flagged" : "deleted").append(".\n");
        }
        body.append(ctaLine("View Stale Users", "staleUsers"));
        body.append("\n---\nJenkins OmniAuth Plugin");
        dispatch(cfg, "cleanup", subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: User manually deleted
    // -------------------------------------------------------------------------

    public static void sendUserDeleted(OmniAuthGlobalConfig cfg, String deletedUserId, String deletedBy) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] User deleted: " + deletedUserId;
        String body = "OmniAuth User Deletion Notice\n"
                + "=============================\n\n"
                + "Deleted user: " + deletedUserId + "\n"
                + "Deleted by:   " + deletedBy + "\n"
                + ctaLine("View User Status", "userStatus")
                + "\n---\nJenkins OmniAuth Plugin";
        dispatch(cfg, "userDeleted", subject, body);
    }

    // -------------------------------------------------------------------------
    // Event: OmniAuth config changed
    // -------------------------------------------------------------------------

    public static void sendConfigChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                         String timestamp, List<String> diffLines) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Configuration changed by " + changedBy;
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Configuration Change\n");
        body.append("=============================\n\n");
        body.append("Changed by: ").append(changedBy).append("\n");
        body.append("When:       ").append(timestamp).append("\n\n");
        body.append("Changes:\n");
        for (String line : diffLines) body.append("  ").append(line).append("\n");
        body.append(ctaLine("Review Settings", "notifications"));
        body.append("\n---\nJenkins OmniAuth Plugin");
        dispatch(cfg, "configChanged", subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Protected users list changed
    // -------------------------------------------------------------------------

    public static void sendProtectedListChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                                 List<String> added, List<String> removed) {
        if (cfg == null) return;
        if (added.isEmpty() && removed.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] Protected users list changed";
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Protected Users Change\n");
        body.append("================================\n\n");
        body.append("Changed by: ").append(changedBy).append("\n\n");
        if (!added.isEmpty()) {
            body.append("Added to protected:\n");
            for (String u : added) body.append("  + ").append(u).append("\n");
        }
        if (!removed.isEmpty()) {
            body.append("Removed from protected:\n");
            for (String u : removed) body.append("  - ").append(u).append("\n");
        }
        body.append(ctaLine("View Protected Users", "protectedUsers"));
        body.append("\n---\nJenkins OmniAuth Plugin");
        dispatch(cfg, "protectedListChanged", subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Brute force threshold hit
    // -------------------------------------------------------------------------

    public static void sendBruteForceAlert(OmniAuthGlobalConfig cfg, String username, int failureCount) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Possible brute force — " + failureCount + " failed logins for: " + username;
        String body = "OmniAuth Brute Force Alert\n"
                + "==========================\n\n"
                + "Username:       " + username + "\n"
                + "Failed logins:  " + failureCount + "\n\n"
                + "Consecutive login failures have reached the configured threshold.\n"
                + "This may indicate a brute force or credential stuffing attempt.\n\n"
                + "The counter resets after a successful login.\n"
                + ctaLine("View User Status", "userStatus")
                + "\n---\nJenkins OmniAuth Plugin";
        dispatch(cfg, "bruteForce", subject, body);
    }

    // -------------------------------------------------------------------------
    // Event: Stale warning digest
    // -------------------------------------------------------------------------

    public static void sendStaleWarningDigest(OmniAuthGlobalConfig cfg, List<String> approachingUsers,
                                               int windowDays, int thresholdDays) {
        if (cfg == null || approachingUsers.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] " + approachingUsers.size() + " user(s) approaching stale threshold";
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Stale User Warning\n");
        body.append("===========================\n\n");
        body.append("The following users have not logged in for more than ")
            .append(thresholdDays - windowDays).append(" days\n");
        body.append("and will become stale (").append(thresholdDays).append(" days) within the next ")
            .append(windowDays).append(" days:\n\n");
        for (String uid : approachingUsers) body.append("  - ").append(uid).append("\n");
        body.append("\nConsider reaching out or adding them to the protected list if they should be kept.\n");
        body.append(ctaLine("View Stale Users", "staleUsers"));
        body.append("\n---\nJenkins OmniAuth Plugin");
        dispatch(cfg, "staleWarning", subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Admin permission granted
    // -------------------------------------------------------------------------

    public static void sendAdminGranted(OmniAuthGlobalConfig cfg, List<String> newAdmins, String grantedBy) {
        if (cfg == null || newAdmins.isEmpty()) return;
        String subject = "[Jenkins OmniAuth] Admin permission granted to " + newAdmins.size() + " user(s)";
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Admin Grant Alert\n");
        body.append("==========================\n\n");
        body.append("Granted by: ").append(grantedBy).append("\n\n");
        body.append("New admins:\n");
        for (String uid : newAdmins) body.append("  + ").append(uid).append("\n");
        body.append("\nThese users now have full Jenkins ADMINISTER permission.\n");
        body.append(ctaLine("Review Access", "access"));
        body.append("\n---\nJenkins OmniAuth Plugin");
        dispatch(cfg, "adminGranted", subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Graph API failed
    // -------------------------------------------------------------------------

    public static void sendGraphApiFailed(OmniAuthGlobalConfig cfg, String userId, String errorMessage) {
        if (cfg == null) return;
        String subject = "[Jenkins OmniAuth] Graph API failure — group sync broken";
        String body = "OmniAuth Graph API Failure\n"
                + "==========================\n\n"
                + "User affected: " + userId + "\n"
                + "Error:         " + errorMessage + "\n\n"
                + "Group sync is not working. Check your Entra app registration permissions.\n"
                + "Required: GroupMember.Read.All with admin consent.\n"
                + ctaLine("Open Dashboard", "")
                + "\n---\nJenkins OmniAuth Plugin";
        dispatch(cfg, "graphApiFailure", subject, body);
    }
}
