package io.jenkins.plugins.omniauth;

import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

/**
 * Handles SMTP email delivery for OmniAuth notifications.
 * Each event type has its own typed HTML builder — swap LOGO_DEFAULT to change branding.
 */
public class SmtpHelper {

    private static final Logger LOGGER = Logger.getLogger(SmtpHelper.class.getName());

    // Default logo — swap with a base64 data URI for offline/air-gapped deployments:
    // "data:image/png;base64,<base64-encoded-png>"
    static final String LOGO_DEFAULT =
            "https://www.jenkins.io/images/logos/jenkins/jenkins.svg";

    private SmtpHelper() {}

    // -------------------------------------------------------------------------
    // Public async send
    // -------------------------------------------------------------------------

    // 3-arg overload for callers that only have plain text — wraps in a minimal readable HTML envelope
    static void send(OmniAuthGlobalConfig cfg, String subject, String body) {
        String fontStack = "-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif";
        String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'></head>"
                + "<body style='margin:0;padding:0;background:#dde3ed;font-family:" + fontStack + ";'>"
                + "<table width='100%' cellpadding='0' cellspacing='0' bgcolor='#dde3ed'>"
                + "<tr><td align='center' style='padding:40px 16px;'>"
                + "<table width='600' cellpadding='0' cellspacing='0' "
                + "style='background:#fff;border-radius:12px;overflow:hidden;'>"
                + "<tr><td style='padding:28px 32px;font-size:13px;color:#334155;line-height:1.7;'>"
                + "<pre style='font-family:" + fontStack + ";font-size:13px;color:#334155;"
                + "line-height:1.7;white-space:pre-wrap;margin:0;'>" + esc(body) + "</pre>"
                + "</td></tr></table></td></tr></table>"
                + "</body></html>";
        send(cfg, subject, html, body);
    }

    static void send(OmniAuthGlobalConfig cfg, String subject, String htmlBody, String plainBody) {
        if (cfg == null || !cfg.isNotificationsEnabled() || !cfg.isSmtpEnabled()) return;
        if (!cfg.isSmtpConfigured()) {
            LOGGER.warning("OmniAuth SMTP not configured — skipping: " + subject);
            return;
        }
        String recipients = cfg.getNotifyEmails();
        if (recipients == null || recipients.trim().isEmpty()) {
            LOGGER.warning("OmniAuth SMTP no recipients — skipping: " + subject);
            return;
        }
        final String host     = cfg.getSmtpHost();
        final int    port     = cfg.getSmtpPort();
        final String user     = cfg.getSmtpUsername();
        final String pass     = cfg.getSmtpPassword() != null ? cfg.getSmtpPassword().getPlainText() : "";
        final boolean tls     = cfg.isSmtpTls();
        final String from     = cfg.getSmtpFromAddress();
        final String fromName = cfg.getSmtpFromName() != null ? cfg.getSmtpFromName() : "Jenkins OmniAuth";
        final String replyTo  = cfg.getSmtpReplyTo();
        Thread t = new Thread(() -> sendNow(host, port, user, pass, tls,
                from, fromName, replyTo, recipients, subject, htmlBody, plainBody));
        t.setDaemon(true);
        t.setName("omniauth-email");
        t.start();
    }

    static void sendNow(String host, int port, String username, String password,
                        boolean tls, String fromAddress, String fromName,
                        String replyTo, String recipients,
                        String subject, String htmlBody, String plainBody) {
        try {
            NotifyRetry.run(
                () -> doSend(host, port, username, password, tls, fromAddress, fromName,
                             replyTo, recipients, subject, htmlBody, plainBody),
                LOGGER, "SMTP", subject);
            LOGGER.info("OmniAuth email sent: " + subject + " → " + recipients);
            NotificationLog.get().addEntry("[Email] " + subject, recipients, true, null);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "OmniAuth email failed after 3 attempts: " + subject, e);
            NotificationLog.get().addEntry("[Email] " + subject, recipients, false,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
    }

    private static void doSend(String host, int port, String username, String password,
                                boolean tls, String fromAddress, String fromName,
                                String replyTo, String recipients,
                                String subject, String htmlBody, String plainBody) throws Exception {
        Session session = Session.getInstance(buildProps(host, port, tls), new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(fromAddress, fromName));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipients));
        msg.setSubject(subject);
        if (replyTo != null && !replyTo.trim().isEmpty())
            msg.setReplyTo(InternetAddress.parse(replyTo));

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(plainBody, "UTF-8");
        MimeBodyPart htmlPart = new MimeBodyPart();
        htmlPart.setContent(htmlBody, "text/html; charset=UTF-8");
        Multipart mp = new MimeMultipart("alternative");
        mp.addBodyPart(textPart);
        mp.addBodyPart(htmlPart);
        msg.setContent(mp);

        Transport.send(msg);
    }

    // -------------------------------------------------------------------------
    // Per-event HTML builders
    // -------------------------------------------------------------------------

    public static String buildBruteForceHtml(OmniAuthGlobalConfig cfg, String username, int failureCount) {
        String ts = now();
        String content = kvTable(new String[][]{
                {"Target Account", code(esc(username))},
                {"Failed Attempts",
                        "<span style='font-size:22px;font-weight:800;color:#dc2626;letter-spacing:-.05em;line-height:1;'>"
                        + failureCount + "</span>"
                        + "<span style='font-size:12px;color:#94a3b8;margin-left:6px;'>consecutive</span>"},
                {"Alert Threshold", code(failureCount + " attempts")},
                {"Detected At", ts}
        }) + gap(12)
        + notice("#fef2f2", "#fecaca", "#991b1b",
                "The failure counter resets on a successful login. "
                + "If this account may be compromised, reset the password immediately.");

        return card(logoSrc(cfg), ts,
                "#dc2626", "#fee2e2", "&#9888;", "#dc2626",
                "#fee2e2", "#991b1b", "#dc2626",
                "Critical &nbsp;&middot;&nbsp; Security Alert",
                "Possible Brute Force Attack",
                "Consecutive login failures have exceeded the configured alert threshold. Immediate review is recommended.",
                content,
                "#dc2626", rootUrl() + "/manage/omniauth-management/userStatus",
                "View Security Dashboard &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildUserDeletedHtml(OmniAuthGlobalConfig cfg,
                                               String deletedUserId, String deletedBy) {
        String ts = now();
        String content = kvTable(new String[][]{
                {"Deleted Account", code(esc(deletedUserId))},
                {"Deleted By",      avatar(deletedBy) + "&nbsp;" + esc(deletedBy)},
                {"Timestamp",       ts}
        }) + gap(12)
        + notice("#f8fafc", "#e2e8f0", "#475569",
                "If this was unintended, the account can be re-provisioned by having the user "
                + "sign in via Microsoft Entra (if group membership is still active).");

        return card(logoSrc(cfg), ts,
                "#dc2626", "#fee2e2", "&times;", "#dc2626",
                "#fee2e2", "#991b1b", "#dc2626",
                "Critical &nbsp;&middot;&nbsp; User Removed",
                "User Account Deleted",
                "A Jenkins user account was permanently deleted by an administrator. This action cannot be undone.",
                content,
                "#0f172a", rootUrl() + "/manage/omniauth-management/userStatus",
                "View User Status &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildConfigChangedHtml(OmniAuthGlobalConfig cfg,
                                                  String changedBy, String timestamp,
                                                  List<String> diffLines) {
        String ts = fmtInstant(timestamp);
        StringBuilder content = new StringBuilder();
        content.append(sectionLabel("Changed By"))
               .append(personCard(changedBy, changedBy, ts))
               .append(gap(18))
               .append(sectionLabel("What Changed"));
        if (diffLines.isEmpty()) {
            content.append("<p style='font-size:13px;color:#64748b;'>No changes recorded.</p>");
        } else {
            content.append(diffTableOpen());
            for (String line : diffLines) content.append(diffRow(line));
            content.append(diffTableClose());
        }

        return card(logoSrc(cfg), ts,
                "#2563eb", "#dbeafe", "&#9965;", "#2563eb",
                "#dbeafe", "#1e40af", "#2563eb",
                "Info &nbsp;&middot;&nbsp; Settings Updated",
                "Configuration Changed",
                "OmniAuth plugin settings were modified by an administrator. "
                + "Review the changes below to ensure they are expected.",
                content.toString(),
                "#2563eb", rootUrl() + "/manage/omniauth-management/notifications",
                "Review Settings &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildCleanupReportHtml(OmniAuthGlobalConfig cfg,
                                                  OmniAuthGlobalConfig.CleanupRunRecord record) {
        String ts = fmtInstant(record.getTimestamp());
        String mode = record.isDryRun() ? "Dry-run" : "Live";
        StringBuilder content = new StringBuilder();
        content.append(sectionLabel("Run Summary"))
               .append(statsRow(
                       String.valueOf(record.getUsersScanned()),  "#0f172a", "Scanned",
                       String.valueOf(record.getUsersAffected()), "#dc2626", record.isDryRun() ? "Would Delete" : "Deleted",
                       String.valueOf(record.getSkippedProtected()), "#16a34a", "Protected"))
               .append(gap(18));

        List<String> affected = record.getAffectedUserIds();
        if (!affected.isEmpty()) {
            content.append(sectionLabel(record.isDryRun() ? "Would Be Deleted" : "Deleted Accounts"));
            for (String uid : affected)
                content.append(userItem(uid, "#6b7280", uid, "Removed &middot; " + mode));
        } else {
            content.append(notice("#f0fdf4", "#bbf7d0", "#166534",
                    "No users were " + (record.isDryRun() ? "flagged" : "deleted") + " in this run."));
        }

        return card(logoSrc(cfg), ts,
                "#d97706", "#fef3c7", "&#10007;", "#d97706",
                "#fef3c7", "#92400e", "#d97706",
                "Scheduled &nbsp;&middot;&nbsp; Cleanup Report",
                "Stale User Cleanup " + (record.isDryRun() ? "(Dry-run)" : "Complete"),
                "Automated cleanup ran and " + (record.isDryRun() ? "simulated removal of" : "removed")
                + " accounts that exceeded the inactivity threshold. Mode: " + mode + ".",
                content.toString(),
                "#d97706", rootUrl() + "/manage/omniauth-management/staleUsers",
                "View Stale Users &rarr;",
                "Inactivity threshold: " + cfg.getStaleThresholdDays() + " days", footerNote(cfg));
    }

    public static String buildAdminGrantedHtml(OmniAuthGlobalConfig cfg,
                                                 List<String> newAdmins, String grantedBy) {
        String ts = now();
        StringBuilder content = new StringBuilder();
        content.append(sectionLabel("Granted By"))
               .append(personCard(grantedBy, grantedBy, ts))
               .append(gap(18))
               .append(sectionLabel("New Administrators"));
        for (String uid : newAdmins)
            content.append(userItem(uid, "#059669", uid, "Full Jenkins ADMINISTER access"));
        content.append(gap(12))
               .append(notice("#fffbeb", "#fcd34d", "#92400e",
                       "Admin users can change security settings, delete accounts, and modify all Jenkins configuration. "
                       + "If you did not authorize this, revoke access immediately."));

        return card(logoSrc(cfg), ts,
                "#d97706", "#fef3c7", "&#9733;", "#d97706",
                "#fef3c7", "#92400e", "#d97706",
                "Warning &nbsp;&middot;&nbsp; Privilege Escalation",
                "Admin Permissions Granted",
                "Full Jenkins ADMINISTER access was granted to " + newAdmins.size()
                + " user(s). Verify this was intentional.",
                content.toString(),
                "#d97706", rootUrl() + "/manage/omniauth-management/access",
                "Review Access &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildStaleWarningHtml(OmniAuthGlobalConfig cfg,
                                                 List<String> approachingUsers,
                                                 int windowDays, int thresholdDays) {
        String ts = now();
        StringBuilder content = new StringBuilder();
        content.append(sectionLabel("Approaching Stale Threshold"));
        for (String uid : approachingUsers)
            content.append(userItem(uid, "#d97706", uid,
                    "Inactive &gt; " + (thresholdDays - windowDays) + " days"));
        content.append(gap(12))
               .append(notice("#fffbeb", "#fcd34d", "#92400e",
                       "These users will become stale (inactive &ge; " + thresholdDays + " days) within "
                       + windowDays + " days. Consider reaching out or adding them to the protected list."));

        return card(logoSrc(cfg), ts,
                "#d97706", "#fef3c7", "&#9651;", "#d97706",
                "#fef3c7", "#92400e", "#d97706",
                "Warning &nbsp;&middot;&nbsp; Stale Users Approaching",
                approachingUsers.size() + " User(s) Approaching Stale Threshold",
                "The following users have not logged in recently and will be flagged as stale soon.",
                content.toString(),
                "#d97706", rootUrl() + "/manage/omniauth-management/staleUsers",
                "View Stale Users &rarr;",
                "Inactivity threshold: " + thresholdDays + " days", footerNote(cfg));
    }

    public static String buildProtectedListChangedHtml(OmniAuthGlobalConfig cfg,
                                                         String changedBy,
                                                         List<String> added,
                                                         List<String> removed) {
        String ts = now();
        StringBuilder content = new StringBuilder();
        content.append(sectionLabel("Changed By"))
               .append(personCard(changedBy, changedBy, ts))
               .append(gap(18));
        if (!added.isEmpty()) {
            content.append(sectionLabel("Added to Protected"));
            for (String uid : added)
                content.append(userItem(uid, "#16a34a", uid, "Now protected from stale cleanup"));
        }
        if (!removed.isEmpty()) {
            content.append(removed.isEmpty() ? "" : gap(10));
            content.append(sectionLabel("Removed from Protected"));
            for (String uid : removed)
                content.append(userItem(uid, "#6b7280", uid, "No longer protected"));
        }

        return card(logoSrc(cfg), ts,
                "#2563eb", "#dbeafe", "&#9632;", "#2563eb",
                "#dbeafe", "#1e40af", "#2563eb",
                "Info &nbsp;&middot;&nbsp; Protected List Updated",
                "Protected Users List Changed",
                "The list of users protected from stale cleanup was modified.",
                content.toString(),
                "#2563eb", rootUrl() + "/manage/omniauth-management/staleUsers",
                "View Protected Users &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildGraphApiFailedHtml(OmniAuthGlobalConfig cfg,
                                                   String userId, String errorMessage) {
        String ts = now();
        String content = kvTable(new String[][]{
                {"User Affected", code(esc(userId))},
                {"Error",         "<span style='color:#991b1b;font-size:13px;'>" + esc(errorMessage) + "</span>"},
                {"Detected At",   ts}
        }) + gap(12)
        + notice("#fef2f2", "#fecaca", "#991b1b",
                "Group sync is not working. Check your Entra app registration permissions. "
                + "Required: GroupMember.Read.All with admin consent.");

        return card(logoSrc(cfg), ts,
                "#dc2626", "#fee2e2", "&#9888;", "#dc2626",
                "#fee2e2", "#991b1b", "#dc2626",
                "Critical &nbsp;&middot;&nbsp; Integration Failure",
                "Graph API Failure — Group Sync Broken",
                "Microsoft Graph API returned an error during group sync. User group membership cannot be resolved.",
                content,
                "#dc2626", rootUrl() + "/manage/omniauth-management/",
                "Open Dashboard &rarr;",
                "Automated Security Alert", footerNote(cfg));
    }

    public static String buildSmtpTestHtml(String host, int port, String fromAddress, String to) {
        String ts = now();
        String content = kvTable(new String[][]{
                {"Host",          code(esc(host) + ":" + port)},
                {"From Address",  code(esc(fromAddress))},
                {"TLS / STARTTLS", badge("#dcfce7", "#166534", "Enabled")},
                {"Test Sent To",  code(esc(to))},
                {"Tested At",     ts}
        });
        return card(LOGO_DEFAULT, ts,
                "#16a34a", "#dcfce7", "&#10003;", "#16a34a",
                "#dcfce7", "#166534", "#16a34a",
                "Success &nbsp;&middot;&nbsp; Connection Verified",
                "SMTP is Working",
                "Your email delivery configuration is verified. OmniAuth will use this SMTP setup "
                + "for all security alerts and notifications.",
                content,
                "#16a34a", rootUrl() + "/manage/omniauth-management/notificationLog",
                "View Notification Log &rarr;",
                "SMTP Test &nbsp;&middot;&nbsp; Triggered Manually", "");
    }

    // -------------------------------------------------------------------------
    // Card template — full email HTML with inline CSS
    // -------------------------------------------------------------------------

    private static String card(
            String logoSrc, String timestamp,
            String accentColor,
            String iconBg, String iconChar, String iconColor,
            String badgeBg, String badgeFg, String badgeDot,
            String badgeText, String title, String subtitle,
            String contentHtml,
            String ctaBg, String ctaUrl, String ctaLabel,
            String footerRight, String footerNote) {

        String fontStack = "-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif";

        return "<!DOCTYPE html>"
            + "<html lang='en'><head><meta charset='UTF-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "</head>"
            + "<body style='margin:0;padding:0;background:#dde3ed;font-family:" + fontStack + ";'>"

            // Outer
            + "<table width='100%' cellpadding='0' cellspacing='0' bgcolor='#dde3ed'>"
            + "<tr><td align='center' style='padding:40px 16px 56px;'>"

            // Card
            + "<table width='600' cellpadding='0' cellspacing='0' "
            + "style='max-width:600px;width:100%;background:#ffffff;border-radius:14px;"
            + "overflow:hidden;box-shadow:0 12px 40px rgba(15,23,42,.12),0 2px 6px rgba(15,23,42,.06);'>"

            // Header
            + "<tr><td bgcolor='#ffffff' style='padding:16px 28px;border-bottom:1px solid #f0f4f8;'>"
            + "<table width='100%' cellpadding='0' cellspacing='0'><tr>"
            + "<td style='vertical-align:middle;'>"
            + "<table cellpadding='0' cellspacing='0'><tr>"
            + "<td style='padding-right:9px;vertical-align:middle;'>"
            + "<img src='" + esc(logoSrc) + "' height='34' alt='Jenkins' "
            + "style='display:block;height:34px;width:auto;border:0;'>"
            + "</td>"
            + "<td style='vertical-align:middle;'>"
            + "<span style='font-size:15px;font-weight:700;color:#0f172a;letter-spacing:-.01em;'>OmniAuth</span>"
            + "<span style='font-size:12px;font-weight:400;color:#94a3b8;margin-left:6px;'>for Jenkins</span>"
            + "</td></tr></table></td>"
            + "<td align='right' style='vertical-align:middle;font-size:10.5px;color:#94a3b8;'>"
            + timestamp + "</td>"
            + "</tr></table>"
            + "</td></tr>"

            // Accent bar
            + "<tr><td height='4' bgcolor='" + accentColor + "' style='line-height:4px;font-size:4px;'>&nbsp;</td></tr>"

            // Hero
            + "<tr><td style='padding:32px 28px 24px;'>"
            + "<div style='width:52px;height:52px;border-radius:14px;background:" + iconBg + ";"
            + "text-align:center;line-height:52px;margin-bottom:18px;'>"
            + "<span style='font-size:22px;color:" + iconColor + ";font-weight:700;'>" + iconChar + "</span>"
            + "</div>"
            + "<div style='display:inline-block;font-size:10px;font-weight:700;letter-spacing:.09em;"
            + "text-transform:uppercase;padding:3px 10px 3px 8px;border-radius:20px;"
            + "background:" + badgeBg + ";color:" + badgeFg + ";margin-bottom:10px;'>"
            + "<span style='display:inline-block;width:5px;height:5px;border-radius:50%;"
            + "background:" + badgeDot + ";vertical-align:middle;margin-right:5px;margin-top:-1px;'></span>"
            + badgeText + "</div>"
            + "<div style='font-size:23px;font-weight:800;color:#0c1628;line-height:1.2;"
            + "letter-spacing:-.035em;margin-bottom:10px;margin-top:6px;'>" + title + "</div>"
            + "<div style='font-size:14px;color:#64748b;line-height:1.72;'>" + subtitle + "</div>"
            + "</td></tr>"

            // Divider
            + "<tr><td height='1' bgcolor='#f1f5f9' style='line-height:1px;font-size:1px;'>&nbsp;</td></tr>"

            // Content
            + "<tr><td style='padding:24px 28px;'>" + contentHtml + "</td></tr>"

            // CTA
            + "<tr><td style='padding:4px 28px 28px;'>"
            + "<a href='" + esc(ctaUrl) + "' "
            + "style='display:block;padding:14px;border-radius:10px;text-decoration:none;"
            + "text-align:center;font-family:" + fontStack + ";"
            + "font-weight:700;font-size:14px;color:#ffffff;background:" + ctaBg + ";'>"
            + ctaLabel + "</a>"
            + "</td></tr>"

            // Footer
            + "<tr><td bgcolor='#f8fafc' style='border-top:1px solid #f0f4f8;padding:18px 28px;'>"
            + "<table width='100%' cellpadding='0' cellspacing='0'><tr>"
            + "<td style='vertical-align:middle;'>"
            + "<table cellpadding='0' cellspacing='0'><tr>"
            + "<td style='padding-right:8px;vertical-align:middle;'>"
            + "<img src='" + esc(logoSrc) + "' height='18' alt='Jenkins' "
            + "style='display:block;height:18px;width:auto;border:0;opacity:.45;filter:grayscale(1);'>"
            + "</td>"
            + "<td style='vertical-align:middle;font-size:12px;font-weight:600;color:#94a3b8;'>"
            + "OmniAuth for Jenkins</td>"
            + "</tr></table></td>"
            + "<td align='right' style='vertical-align:middle;font-size:11px;color:#b0bac7;'>"
            + footerRight + "</td>"
            + "</tr></table>"
            + "<div style='height:1px;background:#e8edf3;margin:12px 0;'></div>"
            + (footerNote != null && !footerNote.isEmpty()
                ? "<div style='font-size:11px;color:#64748b;line-height:1.6;text-align:center;"
                  + "margin-bottom:8px;'>" + esc(footerNote) + "</div>"
                : "")
            + "<div style='font-size:10.5px;color:#b0bac7;line-height:1.7;text-align:center;'>"
            + "You are receiving this because you are listed as a security notification contact.<br>"
            + "Jenkins OmniAuth Plugin &nbsp;&middot;&nbsp; Your Jenkins Instance"
            + "</div>"
            + "</td></tr>"

            + "</table>" // card
            + "</td></tr></table>" // outer
            + "</body></html>";
    }

    // -------------------------------------------------------------------------
    // HTML component helpers
    // -------------------------------------------------------------------------

    private static String sectionLabel(String text) {
        return "<div style='font-size:9.5px;font-weight:700;text-transform:uppercase;"
                + "letter-spacing:.13em;color:#a0aec0;margin-bottom:12px;'>" + esc(text) + "</div>";
    }

    private static String kvTable(String[][] rows) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div style='border:1px solid #e8edf3;border-radius:10px;overflow:hidden;padding:0 16px;'>");
        for (int i = 0; i < rows.length; i++) {
            String border = i < rows.length - 1 ? "border-bottom:1px solid #f1f5f9;" : "";
            sb.append("<table width='100%' cellpadding='0' cellspacing='0'><tr>")
              .append("<td style='padding:11px 16px 11px 0;").append(border)
              .append("font-size:13px;color:#94a3b8;font-weight:500;width:40%;vertical-align:middle;'>")
              .append(esc(rows[i][0])).append("</td>")
              .append("<td style='padding:11px 0;").append(border)
              .append("font-size:13px;color:#0f172a;font-weight:500;vertical-align:middle;'>")
              .append(rows[i][1]).append("</td>")
              .append("</tr></table>");
        }
        sb.append("</div>");
        return sb.toString();
    }

    private static String diffTableOpen() {
        return "<table width='100%' cellpadding='0' cellspacing='0' "
                + "style='border:1px solid #e8edf3;border-radius:10px;overflow:hidden;'>"
                + "<tr style='background:#fafbfc;'>"
                + "<th style='padding:9px 14px;font-size:9.5px;font-weight:700;text-transform:uppercase;"
                + "letter-spacing:.12em;color:#b0bac7;text-align:left;border-bottom:1px solid #e8edf3;width:36%;'>Setting</th>"
                + "<th style='padding:9px 14px;font-size:9.5px;font-weight:700;text-transform:uppercase;"
                + "letter-spacing:.12em;color:#b0bac7;text-align:left;border-bottom:1px solid #e8edf3;'>Before</th>"
                + "<th style='padding:9px 14px;font-size:9.5px;font-weight:700;text-transform:uppercase;"
                + "letter-spacing:.12em;color:#b0bac7;text-align:left;border-bottom:1px solid #e8edf3;'>After</th>"
                + "</tr>";
    }

    private static String diffRow(String line) {
        String key = line, before = "", after = "";
        int arrow = line.indexOf(" → ");
        if (arrow > 0) {
            int colon = line.indexOf(':');
            if (colon > 0 && colon < arrow) {
                key    = line.substring(0, colon).trim();
                String rest = line.substring(colon + 1).trim();
                int a2 = rest.indexOf(" → ");
                before = a2 > 0 ? rest.substring(0, a2).trim() : rest;
                after  = a2 > 0 ? rest.substring(a2 + 3).trim() : "";
            } else {
                before = line.substring(0, arrow).trim();
                after  = line.substring(arrow + 3).trim();
            }
        }
        return "<tr style='border-top:1px solid #f1f5f9;'>"
                + "<td style='padding:10px 14px;font-size:12px;font-weight:600;color:#334155;"
                + "font-family:\"SF Mono\",Menlo,Consolas,monospace;'>" + esc(key) + "</td>"
                + "<td style='padding:10px 14px;'>"
                + "<span style='font-family:\"SF Mono\",Menlo,Consolas,monospace;font-size:12px;"
                + "background:#fef2f2;color:#b91c1c;padding:2px 8px;border-radius:4px;'>"
                + esc(before) + "</span></td>"
                + "<td style='padding:10px 14px;'>"
                + "<span style='font-family:\"SF Mono\",Menlo,Consolas,monospace;font-size:12px;"
                + "background:#f0fdf4;color:#15803d;padding:2px 8px;border-radius:4px;'>"
                + esc(after) + "</span></td>"
                + "</tr>";
    }

    private static String diffTableClose() { return "</table>"; }

    private static String notice(String bg, String border, String textColor, String text) {
        return "<div style='display:flex;gap:12px;align-items:flex-start;padding:13px 15px;"
                + "border-radius:9px;border:1px solid " + border + ";background:" + bg + ";'>"
                + "<span style='font-size:14px;color:" + textColor + ";flex-shrink:0;'>&#9432;</span>"
                + "<span style='font-size:13px;color:" + textColor + ";line-height:1.65;'>" + text + "</span>"
                + "</div>";
    }

    private static String personCard(String id, String name, String meta) {
        return "<div style='display:flex;align-items:center;gap:12px;padding:13px 16px;"
                + "background:#f8fafd;border:1px solid #e8edf3;border-radius:9px;'>"
                + "<div style='width:38px;height:38px;border-radius:50%;background:" + avatarColor(id) + ";"
                + "text-align:center;line-height:38px;font-size:13px;font-weight:700;color:#fff;"
                + "flex-shrink:0;'>" + esc(initials(id)) + "</div>"
                + "<div>"
                + "<div style='font-size:14px;font-weight:600;color:#0f172a;'>" + esc(name) + "</div>"
                + "<div style='font-size:12px;color:#94a3b8;margin-top:2px;'>" + meta + "</div>"
                + "</div></div>";
    }

    private static String userItem(String id, String avatarBg, String name, String meta) {
        return "<div style='display:flex;align-items:center;gap:12px;padding:11px 14px;"
                + "background:#f8fafd;border:1px solid #e8edf3;border-radius:9px;margin-bottom:7px;'>"
                + "<div style='width:36px;height:36px;border-radius:50%;background:" + avatarBg + ";"
                + "text-align:center;line-height:36px;font-size:12px;font-weight:700;color:#fff;"
                + "flex-shrink:0;'>" + esc(initials(id)) + "</div>"
                + "<div>"
                + "<div style='font-size:13.5px;font-weight:600;color:#0f172a;'>" + esc(name) + "</div>"
                + "<div style='font-size:11px;color:#94a3b8;margin-top:2px;'>" + meta + "</div>"
                + "</div></div>";
    }

    private static String avatar(String id) {
        return "<span style='display:inline-block;width:22px;height:22px;border-radius:50%;"
                + "background:" + avatarColor(id) + ";text-align:center;line-height:22px;"
                + "font-size:9px;font-weight:700;color:#fff;vertical-align:middle;'>"
                + esc(initials(id)) + "</span>";
    }

    private static String badge(String bg, String color, String text) {
        return "<span style='display:inline-block;font-size:10px;font-weight:700;letter-spacing:.08em;"
                + "text-transform:uppercase;padding:2px 9px;border-radius:20px;"
                + "background:" + bg + ";color:" + color + ";'>" + esc(text) + "</span>";
    }

    private static String statsRow(String n1, String c1, String l1,
                                    String n2, String c2, String l2,
                                    String n3, String c3, String l3) {
        return "<table width='100%' cellpadding='0' cellspacing='0'><tr>"
                + statCell(n1, c1, l1) + "<td width='10'></td>"
                + statCell(n2, c2, l2) + "<td width='10'></td>"
                + statCell(n3, c3, l3)
                + "</tr></table>";
    }

    private static String statCell(String number, String numColor, String label) {
        return "<td style='background:#f8fafd;border:1px solid #e8edf3;border-radius:10px;"
                + "padding:18px 10px;text-align:center;'>"
                + "<div style='font-size:30px;font-weight:800;letter-spacing:-.05em;"
                + "line-height:1;margin-bottom:6px;color:" + numColor + ";'>" + number + "</div>"
                + "<div style='font-size:9.5px;font-weight:700;text-transform:uppercase;"
                + "letter-spacing:.12em;color:#a0aec0;'>" + label + "</div>"
                + "</td>";
    }

    private static String gap(int px) {
        return "<div style='height:" + px + "px;'></div>";
    }

    private static String code(String value) {
        return "<span style='font-family:\"SF Mono\",\"Fira Code\",Menlo,Consolas,monospace;"
                + "font-size:12px;background:#f1f5f9;color:#334155;"
                + "padding:2px 8px;border-radius:5px;border:1px solid #e2e8f0;'>" + value + "</span>";
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static String footerNote(OmniAuthGlobalConfig cfg) {
        if (cfg == null) return "";
        String note = cfg.getNotificationFooterNote();
        return note != null ? note.trim() : "";
    }

    private static String logoSrc(OmniAuthGlobalConfig cfg) {
        if (cfg != null) {
            String url = cfg.getNotificationLogoUrl();
            if (url != null && !url.trim().isEmpty()) return url.trim();
        }
        return LOGO_DEFAULT;
    }

    private static String now() {
        return java.time.format.DateTimeFormatter
                .ofPattern("d MMM yyyy '&#183;' HH:mm 'UTC'")
                .withZone(java.time.ZoneId.of("UTC"))
                .format(java.time.Instant.now());
    }

    private static String fmtInstant(String iso) {
        if (iso == null || iso.isEmpty()) return now();
        try {
            return java.time.format.DateTimeFormatter
                    .ofPattern("d MMM yyyy '&#183;' HH:mm 'UTC'")
                    .withZone(java.time.ZoneId.of("UTC"))
                    .format(java.time.Instant.parse(iso));
        } catch (Exception e) { return esc(iso); }
    }

    private static String rootUrl() {
        try {
            String r = jenkins.model.Jenkins.get().getRootUrl();
            if (r == null || r.isEmpty()) return "";
            return r.endsWith("/") ? r.substring(0, r.length() - 1) : r;
        } catch (Exception e) { return ""; }
    }

    private static String initials(String id) {
        if (id == null || id.isEmpty()) return "?";
        String[] parts = id.trim().split("[\\s._@-]+");
        if (parts.length >= 2 && parts[0].length() > 0 && parts[1].length() > 0)
            return ("" + parts[0].charAt(0) + parts[1].charAt(0)).toUpperCase();
        return id.substring(0, Math.min(2, id.length())).toUpperCase();
    }

    private static String avatarColor(String id) {
        if (id == null) return "#6366f1";
        String[] pal = {"#6366f1","#0891b2","#059669","#1d4ed8","#b45309","#7c3aed","#db2777"};
        return pal[Math.abs(id.hashCode()) % pal.length];
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("→", "&#8594;");
    }

    // -------------------------------------------------------------------------
    // SMTP properties
    // -------------------------------------------------------------------------

    private static Properties buildProps(String host, int port, boolean tls) {
        Properties props = new Properties();
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", String.valueOf(port));
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.auth.mechanisms", "PLAIN LOGIN");
        if (tls) {
            props.put("mail.smtp.starttls.enable",   "true");
            props.put("mail.smtp.starttls.required", "true");
        }
        return props;
    }

    // -------------------------------------------------------------------------
    // Synchronous test — throws on failure so the caller can surface the error
    // -------------------------------------------------------------------------

    public static void test(String host, int port, String username, String password,
                             boolean tls, String fromAddress, String fromName,
                             String replyTo, String to) throws Exception {
        Properties props = buildProps(host, port, tls);
        props.put("mail.smtp.connectiontimeout", "8000");
        props.put("mail.smtp.timeout", "8000");
        final String u = username, p = password;
        Session session = Session.getInstance(props, new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(u, p);
            }
        });

        String plainBody = "OmniAuth SMTP Test\n==================\n\n"
                + "If you received this, your SMTP configuration is correct.\n\n"
                + "Host: " + host + ":" + port + "\n"
                + "From: " + fromAddress + "\n"
                + "To:   " + to + "\n"
                + "\n---\nJenkins OmniAuth Plugin";

        MimeMessage msg = new MimeMessage(session);
        String name = (fromName != null && !fromName.isEmpty()) ? fromName : "Jenkins OmniAuth";
        msg.setFrom(new InternetAddress(fromAddress, name));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        msg.setSubject("[Jenkins OmniAuth] Test email — SMTP is working");
        if (replyTo != null && !replyTo.trim().isEmpty())
            msg.setReplyTo(InternetAddress.parse(replyTo));

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(plainBody, "UTF-8");
        MimeBodyPart htmlPart = new MimeBodyPart();
        htmlPart.setContent(buildSmtpTestHtml(host, port, fromAddress, to), "text/html; charset=UTF-8");
        Multipart mp = new MimeMultipart("alternative");
        mp.addBodyPart(textPart);
        mp.addBodyPart(htmlPart);
        msg.setContent(mp);

        Transport.send(msg);
    }
}
