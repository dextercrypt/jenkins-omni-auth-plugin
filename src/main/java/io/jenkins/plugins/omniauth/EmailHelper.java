package io.jenkins.plugins.omniauth;

import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

/**
 * Sends OmniAuth notification emails via plain SMTP.
 * All SMTP settings come from OmniAuthGlobalConfig — independent of Jenkins' own email config.
 */
public class EmailHelper {

    private static final Logger LOGGER = Logger.getLogger(EmailHelper.class.getName());

    private EmailHelper() {}

    // -------------------------------------------------------------------------
    // Core send method
    // -------------------------------------------------------------------------

    private static void send(OmniAuthGlobalConfig cfg, String subject, String body) {
        if (cfg == null) return;
        if (!cfg.isNotificationsEnabled()) return;
        if (!cfg.isSmtpEnabled()) return;
        if (!cfg.isSmtpConfigured()) {
            LOGGER.warning("OmniAuth email: SMTP not configured — skipping notification: " + subject);
            return;
        }

        String recipients = cfg.getNotifyEmails();
        if (recipients == null || recipients.trim().isEmpty()) {
            LOGGER.warning("OmniAuth email: No recipient emails configured — skipping: " + subject);
            return;
        }

        // Capture config values before handing off to background thread
        final String smtpHost     = cfg.getSmtpHost();
        final int    smtpPort     = cfg.getSmtpPort();
        final String smtpUsername = cfg.getSmtpUsername();
        final String smtpPassword = cfg.getSmtpPassword() != null ? cfg.getSmtpPassword().getPlainText() : "";
        final boolean smtpTls     = cfg.isSmtpTls();
        final String fromAddress  = cfg.getSmtpFromAddress();
        final String fromName     = cfg.getSmtpFromName() != null ? cfg.getSmtpFromName() : "Jenkins OmniAuth";
        final String replyTo      = cfg.getSmtpReplyTo();
        final String to           = recipients;

        Thread t = new Thread(() -> sendNow(
                smtpHost, smtpPort, smtpUsername, smtpPassword, smtpTls,
                fromAddress, fromName, replyTo, to, subject, body));
        t.setDaemon(true);
        t.setName("omniauth-email");
        t.start();
    }

    private static void sendNow(String host, int port, String username, String password,
                                 boolean tls, String fromAddress, String fromName,
                                 String replyTo, String recipients, String subject, String body) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", host);
            props.put("mail.smtp.port", String.valueOf(port));
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.auth.mechanisms", "PLAIN LOGIN");
            if (tls) {
                props.put("mail.smtp.starttls.enable",   "true");
                props.put("mail.smtp.starttls.required", "true");
            }

            Session session = Session.getInstance(props, new Authenticator() {
                @Override protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });

            MimeMessage msg = new MimeMessage(session);
            msg.setFrom(new InternetAddress(fromAddress, fromName));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipients));
            msg.setSubject(subject);
            msg.setText(body, "UTF-8");

            if (replyTo != null && !replyTo.trim().isEmpty()) {
                msg.setReplyTo(InternetAddress.parse(replyTo));
            }

            Transport.send(msg);
            LOGGER.info("OmniAuth email sent: " + subject + " → " + recipients);

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "OmniAuth email failed: " + subject, e);
        }
    }

    // -------------------------------------------------------------------------
    // Test email — throws on failure so the caller can surface the error
    // -------------------------------------------------------------------------

    public static void testSmtp(String host, int port, String username, String password,
                                 boolean tls, String fromAddress, String fromName, String replyTo, String to)
            throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", String.valueOf(port));
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.auth.mechanisms", "PLAIN LOGIN");
        props.put("mail.smtp.connectiontimeout", "8000");
        props.put("mail.smtp.timeout", "8000");
        if (tls) {
            props.put("mail.smtp.starttls.enable",   "true");
            props.put("mail.smtp.starttls.required", "true");
        }

        final String u = username, p = password;
        Session session = Session.getInstance(props, new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(u, p);
            }
        });

        MimeMessage msg = new MimeMessage(session);
        String name = (fromName != null && !fromName.isEmpty()) ? fromName : "Jenkins OmniAuth";
        msg.setFrom(new InternetAddress(fromAddress, name));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        msg.setSubject("[Jenkins OmniAuth] Test email — SMTP is working");
        msg.setText("OmniAuth SMTP Test\n==================\n\n"
                + "If you received this, your SMTP configuration is correct.\n\n"
                + "Host: " + host + ":" + port + "\n"
                + "From: " + fromAddress + "\n"
                + "To:   " + to + "\n\n"
                + "---\nJenkins OmniAuth Plugin", "UTF-8");

        if (replyTo != null && !replyTo.trim().isEmpty()) {
            msg.setReplyTo(InternetAddress.parse(replyTo));
        }

        Transport.send(msg); // throws MessagingException on failure — do NOT catch here
    }

    // -------------------------------------------------------------------------
    // Event: Stale cleanup ran
    // -------------------------------------------------------------------------

    public static void sendCleanupReport(OmniAuthGlobalConfig cfg, OmniAuthGlobalConfig.CleanupRunRecord record) {
        if (cfg == null || !cfg.isNotifyOnCleanup()) return;

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

        body.append("\n---\nJenkins OmniAuth Plugin");
        send(cfg, subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: User manually deleted
    // -------------------------------------------------------------------------

    public static void sendUserDeleted(OmniAuthGlobalConfig cfg, String deletedUserId, String deletedBy) {
        if (cfg == null || !cfg.isNotifyOnUserDeleted()) return;

        String subject = "[Jenkins OmniAuth] User deleted: " + deletedUserId;
        String body = "OmniAuth User Deletion Notice\n"
                + "=============================\n\n"
                + "Deleted user: " + deletedUserId + "\n"
                + "Deleted by:   " + deletedBy + "\n\n"
                + "---\nJenkins OmniAuth Plugin";
        send(cfg, subject, body);
    }

    // -------------------------------------------------------------------------
    // Event: OmniAuth config changed
    // -------------------------------------------------------------------------

    public static void sendConfigChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                         String timestamp, List<String> diffLines) {
        if (cfg == null || !cfg.isNotifyOnConfigChange()) return;

        String subject = "[Jenkins OmniAuth] Configuration changed by " + changedBy;
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Configuration Change\n");
        body.append("=============================\n\n");
        body.append("Changed by: ").append(changedBy).append("\n");
        body.append("When:       ").append(timestamp).append("\n\n");
        body.append("Changes:\n");
        for (String line : diffLines) body.append("  ").append(line).append("\n");
        body.append("\n---\nJenkins OmniAuth Plugin");
        send(cfg, subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Protected users list changed
    // -------------------------------------------------------------------------

    public static void sendProtectedListChanged(OmniAuthGlobalConfig cfg, String changedBy,
                                                 List<String> added, List<String> removed) {
        if (cfg == null || !cfg.isNotifyOnProtectedListChange()) return;
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
        body.append("\n---\nJenkins OmniAuth Plugin");
        send(cfg, subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Brute force threshold hit
    // -------------------------------------------------------------------------

    public static void sendBruteForceAlert(OmniAuthGlobalConfig cfg, String username, int failureCount) {
        if (cfg == null || !cfg.isNotifyOnBruteForce()) return;

        String subject = "[Jenkins OmniAuth] Possible brute force — " + failureCount + " failed logins for: " + username;
        String body = "OmniAuth Brute Force Alert\n"
                + "==========================\n\n"
                + "Username:       " + username + "\n"
                + "Failed logins:  " + failureCount + "\n\n"
                + "Consecutive login failures have reached the configured threshold.\n"
                + "This may indicate a brute force or credential stuffing attempt.\n\n"
                + "The counter resets after a successful login.\n\n"
                + "---\nJenkins OmniAuth Plugin";
        send(cfg, subject, body);
    }

    // -------------------------------------------------------------------------
    // Event: Stale warning digest
    // -------------------------------------------------------------------------

    public static void sendStaleWarningDigest(OmniAuthGlobalConfig cfg, List<String> approachingUsers,
                                               int windowDays, int thresholdDays) {
        if (cfg == null || !cfg.isNotifyOnStaleWarning()) return;
        if (approachingUsers.isEmpty()) return;

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
        body.append("\n---\nJenkins OmniAuth Plugin");
        send(cfg, subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Admin permission granted
    // -------------------------------------------------------------------------

    public static void sendAdminGranted(OmniAuthGlobalConfig cfg, List<String> newAdmins, String grantedBy) {
        if (cfg == null || !cfg.isNotifyOnAdminGranted()) return;
        if (newAdmins.isEmpty()) return;

        String subject = "[Jenkins OmniAuth] Admin permission granted to " + newAdmins.size() + " user(s)";
        StringBuilder body = new StringBuilder();
        body.append("OmniAuth Admin Grant Alert\n");
        body.append("==========================\n\n");
        body.append("Granted by: ").append(grantedBy).append("\n\n");
        body.append("New admins:\n");
        for (String uid : newAdmins) body.append("  + ").append(uid).append("\n");
        body.append("\nThese users now have full Jenkins ADMINISTER permission.\n");
        body.append("\n---\nJenkins OmniAuth Plugin");
        send(cfg, subject, body.toString());
    }

    // -------------------------------------------------------------------------
    // Event: Graph API failed
    // -------------------------------------------------------------------------

    public static void sendGraphApiFailed(OmniAuthGlobalConfig cfg, String userId, String errorMessage) {
        if (cfg == null || !cfg.isNotifyOnGraphApiFailure()) return;

        String subject = "[Jenkins OmniAuth] Graph API failure — group sync broken";
        String body = "OmniAuth Graph API Failure\n"
                + "==========================\n\n"
                + "User affected: " + userId + "\n"
                + "Error:         " + errorMessage + "\n\n"
                + "Group sync is not working. Check your Entra app registration permissions.\n"
                + "Required: GroupMember.Read.All with admin consent.\n\n"
                + "---\nJenkins OmniAuth Plugin";
        send(cfg, subject, body);
    }
}
