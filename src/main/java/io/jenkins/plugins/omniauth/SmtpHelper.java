package io.jenkins.plugins.omniauth;

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
 */
public class SmtpHelper {

    private static final Logger LOGGER = Logger.getLogger(SmtpHelper.class.getName());

    private SmtpHelper() {}

    // -------------------------------------------------------------------------
    // Async send — called by NotificationService
    // -------------------------------------------------------------------------

    static void send(OmniAuthGlobalConfig cfg, String subject, String body) {
        if (cfg == null) return;
        if (!cfg.isNotificationsEnabled()) return;
        if (!cfg.isSmtpEnabled()) return;
        if (!cfg.isSmtpConfigured()) {
            LOGGER.warning("OmniAuth SMTP not configured — skipping: " + subject);
            return;
        }

        String recipients = cfg.getNotifyEmails();
        if (recipients == null || recipients.trim().isEmpty()) {
            LOGGER.warning("OmniAuth SMTP no recipients configured — skipping: " + subject);
            return;
        }

        final String host      = cfg.getSmtpHost();
        final int    port      = cfg.getSmtpPort();
        final String username  = cfg.getSmtpUsername();
        final String password  = cfg.getSmtpPassword() != null ? cfg.getSmtpPassword().getPlainText() : "";
        final boolean tls      = cfg.isSmtpTls();
        final String fromAddr  = cfg.getSmtpFromAddress();
        final String fromName  = cfg.getSmtpFromName() != null ? cfg.getSmtpFromName() : "Jenkins OmniAuth";
        final String replyTo   = cfg.getSmtpReplyTo();
        final String logoUrl = cfg.getNotificationLogoUrl();

        Thread t = new Thread(() -> sendNow(host, port, username, password, tls,
                fromAddr, fromName, replyTo, recipients, subject, body, logoUrl));
        t.setDaemon(true);
        t.setName("omniauth-email");
        t.start();
    }

    static void sendNow(String host, int port, String username, String password,
                        boolean tls, String fromAddress, String fromName,
                        String replyTo, String recipients, String subject, String body,
                        String logoUrl) {
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

            // Multipart: plain text fallback + HTML
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(body, "UTF-8");

            MimeBodyPart htmlPart = new MimeBodyPart();
            htmlPart.setContent(buildHtml(subject, body, logoUrl), "text/html; charset=UTF-8");

            Multipart multipart = new MimeMultipart("alternative");
            multipart.addBodyPart(textPart);
            multipart.addBodyPart(htmlPart);
            msg.setContent(multipart);

            if (replyTo != null && !replyTo.trim().isEmpty()) {
                msg.setReplyTo(InternetAddress.parse(replyTo));
            }

            Transport.send(msg);
            LOGGER.info("OmniAuth email sent: " + subject + " → " + recipients);
            NotificationLog.get().addEntry("[Email] " + subject, recipients, true, null);

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "OmniAuth email failed: " + subject, e);
            NotificationLog.get().addEntry("[Email] " + subject, recipients, false,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
    }

    // -------------------------------------------------------------------------
    // HTML builder — enterprise notification email
    // -------------------------------------------------------------------------

    private static String[] extractCta(String body) {
        for (String line : body.split("\n")) {
            String t = line.trim();
            if (t.startsWith("CTA: ") && t.contains(" | ")) {
                String rest = t.substring(5);
                int pipe = rest.indexOf(" | ");
                return new String[]{ rest.substring(0, pipe).trim(), rest.substring(pipe + 3).trim() };
            }
        }
        return null;
    }

    private static String stripCta(String body) {
        return body.replaceAll("(?m)^CTA: .+\\r?\\n?", "");
    }

    static String buildHtml(String subject, String plainText, String logoUrl) {
        String[] cta = extractCta(plainText);
        plainText = stripCta(plainText);
        boolean hasLogo = logoUrl != null && !logoUrl.trim().isEmpty();
        String eventTitle = subject.replaceAll("^\\[Jenkins OmniAuth\\] ", "");
        String sl = subject.toLowerCase();

        // Severity tier + left-strip accent color + badge colors
        String accent, severity, badgeBg, badgeFg;
        if (sl.contains("brute force") || sl.contains("graph api")) {
            accent = "#dc2626"; severity = "CRITICAL"; badgeBg = "#fee2e2"; badgeFg = "#991b1b";
        } else if (sl.contains("deleted") || sl.contains("disabled")) {
            accent = "#dc2626"; severity = "CRITICAL"; badgeBg = "#fee2e2"; badgeFg = "#991b1b";
        } else if (sl.contains("cleanup") || sl.contains("stale")) {
            accent = "#d97706"; severity = "WARNING";  badgeBg = "#fef3c7"; badgeFg = "#92400e";
        } else if (sl.contains("granted") || sl.contains("enabled")) {
            accent = "#16a34a"; severity = "SUCCESS";  badgeBg = "#dcfce7"; badgeFg = "#166534";
        } else {
            accent = "#2563eb"; severity = "INFO";     badgeBg = "#dbeafe"; badgeFg = "#1e40af";
        }

        // First pass: extract actor + timestamp
        String actor = null, rawTime = null;
        String[] lines = plainText.split("\n");
        for (String line : lines) {
            String t = line.trim();
            int c = t.indexOf(':');
            if (c <= 0) continue;
            String k = t.substring(0, c).toLowerCase().replaceAll("\\s+", " ").trim();
            String v = t.substring(c + 1).trim();
            if (k.equals("changed by") || k.equals("granted by") || k.equals("deleted by")) actor = v;
            else if (k.equals("when") || k.equals("run at")) rawTime = v;
        }

        // Format timestamp nicely
        String displayTime = rawTime;
        if (rawTime != null) {
            try {
                java.time.Instant inst = java.time.Instant.parse(rawTime);
                displayTime = java.time.format.DateTimeFormatter
                    .ofPattern("MMM d, yyyy 'at' HH:mm 'UTC'")
                    .withZone(java.time.ZoneId.of("UTC"))
                    .format(inst);
            } catch (Exception ignored) {}
        }

        // Avatar initials + color derived from actor name
        String initials = "SY", avatarBg = "#6366f1";
        if (actor != null && !actor.isEmpty()) {
            String[] p = actor.trim().split("[\\s._@-]+");
            initials = (p.length >= 2 && p[0].length() > 0 && p[1].length() > 0)
                ? ("" + p[0].charAt(0) + p[1].charAt(0)).toUpperCase()
                : actor.substring(0, Math.min(2, actor.length())).toUpperCase();
            String[] pal = {"#6366f1","#0891b2","#059669","#b91c1c","#b45309","#7c3aed","#db2777"};
            avatarBg = pal[Math.abs(actor.hashCode()) % pal.length];
        }

        // Second pass: render body content
        StringBuilder content = new StringBuilder();
        boolean inKv = false, inDiff = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i], tr = line.trim();

            if (tr.matches("={3,}") || tr.matches("-{3,}")) continue;
            if (tr.equals("Jenkins OmniAuth Plugin")) continue;

            // Skip metadata lines shown in the header meta strip
            if (!tr.isEmpty()) {
                int c = tr.indexOf(':');
                if (c > 0) {
                    String k = tr.substring(0, c).toLowerCase().replaceAll("\\s+", " ").trim();
                    if (k.equals("changed by") || k.equals("granted by") || k.equals("deleted by")
                            || k.equals("when") || k.equals("run at")) continue;
                }
            }

            if (tr.isEmpty()) {
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                content.append("<div style='height:10px'></div>");
                continue;
            }

            // Section title (line before ===) — already in card header, skip
            if ((i + 1 < lines.length) && lines[i + 1].trim().matches("={3,}")) {
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                continue;
            }

            // Indented line: diff "  key: old → new" or plain "  some text"
            if (line.startsWith("  ") && !line.startsWith("  - ") && !line.startsWith("  + ")) {
                int arrow = tr.indexOf(" \u2192 ");
                if (arrow > 0) {
                    if (inKv) { content.append("</table>"); inKv = false; }
                    if (!inDiff) {
                        content.append("<table cellpadding='0' cellspacing='0' "
                            + "style='width:100%;border-collapse:collapse;margin:8px 0;"
                            + "border:1px solid #e5e7eb;border-radius:6px;font-family:"
                            + "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;'>")
                            .append("<tr style='background:#f9fafb;'>")
                            .append("<th style='padding:8px 14px;font-size:10px;font-weight:700;"
                                + "text-transform:uppercase;letter-spacing:0.08em;color:#6b7280;"
                                + "text-align:left;border-bottom:1px solid #e5e7eb;'>Setting</th>")
                            .append("<th style='padding:8px 14px;font-size:10px;font-weight:700;"
                                + "text-transform:uppercase;letter-spacing:0.08em;color:#6b7280;"
                                + "text-align:left;border-bottom:1px solid #e5e7eb;'>Before</th>")
                            .append("<th style='padding:8px 14px;font-size:10px;font-weight:700;"
                                + "text-transform:uppercase;letter-spacing:0.08em;color:#6b7280;"
                                + "text-align:left;border-bottom:1px solid #e5e7eb;'>After</th>")
                            .append("</tr>");
                        inDiff = true;
                    }
                    int colon = tr.indexOf(':');
                    String key      = colon > 0 ? tr.substring(0, colon).trim() : tr.substring(0, arrow).trim();
                    String diffPart = colon > 0 ? tr.substring(colon + 1).trim() : tr;
                    int da          = diffPart.indexOf(" \u2192 ");
                    String before   = da > 0 ? diffPart.substring(0, da).trim()  : diffPart;
                    String after    = da > 0 ? diffPart.substring(da + 3).trim() : "";
                    content.append("<tr style='border-top:1px solid #f3f4f6;'>")
                        .append("<td style='padding:9px 14px;font-size:12px;font-weight:500;color:#374151;"
                            + "font-family:SFMono-Regular,Consolas,monospace;'>").append(esc(key)).append("</td>")
                        .append("<td style='padding:9px 14px;'><span style='font-size:11px;color:#991b1b;"
                            + "background:#fee2e2;padding:2px 8px;border-radius:4px;"
                            + "font-family:SFMono-Regular,Consolas,monospace;'>").append(esc(before)).append("</span></td>")
                        .append("<td style='padding:9px 14px;'><span style='font-size:11px;color:#166534;"
                            + "background:#dcfce7;padding:2px 8px;border-radius:4px;"
                            + "font-family:SFMono-Regular,Consolas,monospace;'>").append(esc(after)).append("</span></td>")
                        .append("</tr>");
                    continue;
                }
                // Indented plain text bullet
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                content.append("<table cellpadding='0' cellspacing='0' style='margin:3px 0;'><tr>")
                    .append("<td style='padding-right:8px;font-size:12px;color:#9ca3af;vertical-align:top;'>&#x2022;</td>")
                    .append("<td style='font-size:13px;color:#374151;line-height:1.65;'>").append(esc(tr)).append("</td>")
                    .append("</tr></table>");
                continue;
            }

            // Removed bullet "  - item"
            if (line.startsWith("  - ")) {
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                content.append("<table cellpadding='0' cellspacing='0' style='margin:4px 0;'><tr>")
                    .append("<td style='padding-right:10px;font-size:13px;font-weight:700;color:#dc2626;"
                        + "vertical-align:top;width:14px;'>&#8212;</td>")
                    .append("<td style='font-size:13px;color:#374151;line-height:1.65;'>")
                    .append(esc(line.substring(4).trim())).append("</td></tr></table>");
                continue;
            }

            // Added bullet "  + item"
            if (line.startsWith("  + ")) {
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                content.append("<table cellpadding='0' cellspacing='0' style='margin:4px 0;'><tr>")
                    .append("<td style='padding-right:10px;font-size:13px;font-weight:700;color:#16a34a;"
                        + "vertical-align:top;width:14px;'>+</td>")
                    .append("<td style='font-size:13px;color:#374151;line-height:1.65;'>")
                    .append(esc(line.substring(4).trim())).append("</td></tr></table>");
                continue;
            }

            // Key: Value (top-level, not indented)
            int colon = tr.indexOf(':');
            if (!line.startsWith(" ") && colon > 0 && colon < tr.length() - 1) {
                String k = tr.substring(0, colon).trim();
                String v = tr.substring(colon + 1).trim();
                if (!v.isEmpty() && k.length() <= 32) {
                    if (inDiff) { content.append("</table>"); inDiff = false; }
                    if (!inKv) {
                        content.append("<table cellpadding='0' cellspacing='0' "
                            + "style='width:100%;border-collapse:collapse;margin:4px 0;'>");
                        inKv = true;
                    }
                    content.append("<tr>")
                        .append("<td style='padding:6px 16px 6px 0;font-size:12px;color:#6b7280;"
                            + "font-weight:500;white-space:nowrap;vertical-align:top;width:35%;'>").append(esc(k)).append("</td>")
                        .append("<td style='padding:6px 0;font-size:13px;color:#0d1117;font-weight:500;'>").append(esc(v)).append("</td>")
                        .append("</tr>");
                    continue;
                }
            }

            // Subheading "Section label:"
            if (!line.startsWith(" ") && tr.endsWith(":")) {
                if (inKv)   { content.append("</table>"); inKv   = false; }
                if (inDiff) { content.append("</table>"); inDiff = false; }
                content.append("<p style='margin:14px 0 6px;font-size:10px;font-weight:700;"
                    + "text-transform:uppercase;letter-spacing:0.1em;color:#9ca3af;'>")
                    .append(esc(tr.substring(0, tr.length() - 1))).append("</p>");
                continue;
            }

            // Plain paragraph
            if (inKv)   { content.append("</table>"); inKv   = false; }
            if (inDiff) { content.append("</table>"); inDiff = false; }
            content.append("<p style='margin:4px 0;font-size:13px;color:#57606a;line-height:1.7;'>")
                .append(esc(tr)).append("</p>");
        }
        if (inKv)   content.append("</table>");
        if (inDiff) content.append("</table>");

        // Meta strip (who + when)
        String metaStrip = "";
        if (actor != null || displayTime != null) {
            metaStrip =
                // hairline divider
                "<tr><td style='height:1px;background:#f0f2f5;font-size:0;line-height:0;padding:0;'></td></tr>"
                + "<tr><td style='background:#fafafa;padding:14px 24px;'>"
                + "<table cellpadding='0' cellspacing='0'><tr>"
                + "<td style='vertical-align:middle;'>"
                + "<div style='width:34px;height:34px;border-radius:50%;background:" + avatarBg
                + ";text-align:center;'><span style='font-size:12px;font-weight:700;color:#fff;"
                + "line-height:34px;display:inline-block;'>" + esc(initials) + "</span></div>"
                + "</td>"
                + "<td style='padding-left:11px;vertical-align:middle;'>"
                + "<div style='font-size:13px;font-weight:600;color:#0d1117;'>" + esc(actor != null ? actor : "System") + "</div>"
                + (displayTime != null ? "<div style='font-size:11px;color:#8b949e;margin-top:2px;'>" + esc(displayTime) + "</div>" : "")
                + "</td></tr></table>"
                + "</td></tr>";
        }

        // ── Assemble ──
        // Card uses a 2-column layout: 5px accent strip on the left, content on the right
        return "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'></head>"
            + "<body style='margin:0;padding:0;background:#f6f8fb;"
            + "font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>"
            + "<table width='100%' cellpadding='0' cellspacing='0' "
            + "style='background:#f6f8fb;padding:44px 16px;'><tr><td align='center'>"

            // Card
            + "<table width='580' cellpadding='0' cellspacing='0' "
            + "style='max-width:580px;width:100%;background:#fff;border:1px solid #d0d7de;"
            + "border-radius:8px;overflow:hidden;'>"
            + "<tr>"

            // Left accent strip
            + "<td style='width:5px;min-width:5px;background:" + accent + ";border-radius:7px 0 0 7px;'></td>"

            // Right content column (all sections nested here)
            + "<td style='padding:0;'>"
            + "<table width='100%' cellpadding='0' cellspacing='0'>"

            // ── Header ──
            + "<tr><td style='padding:24px 24px 20px;'>"
            // Logo row: OA monogram + plugin name | badge
            + "<table width='100%' cellpadding='0' cellspacing='0'><tr>"
            + "<td style='vertical-align:middle;'>"
            + "<table cellpadding='0' cellspacing='0'><tr>"
            + "<td style='vertical-align:middle;'>"
            + (hasLogo
                ? "<img src='" + esc(logoUrl.trim()) + "' height='28' style='height:28px;width:auto;"
                    + "display:block;border:0;border-radius:4px;' alt='Logo'>"
                : "<div style='width:28px;height:28px;border-radius:6px;background:#1d4ed8;text-align:center;'>"
                    + "<span style='font-size:11px;font-weight:800;color:#fff;line-height:28px;"
                    + "display:inline-block;letter-spacing:-0.02em;'>OA</span></div>")
            + "</td>"
            + "<td style='padding-left:9px;vertical-align:middle;'>"
            + "<span style='font-size:11px;font-weight:700;letter-spacing:0.07em;"
            + "text-transform:uppercase;color:#8b949e;'>Jenkins OmniAuth</span></td>"
            + "</tr></table></td>"
            // Badge
            + "<td align='right' style='vertical-align:middle;'>"
            + "<span style='display:inline-block;font-size:10px;font-weight:700;"
            + "letter-spacing:0.07em;text-transform:uppercase;color:" + badgeFg
            + ";background:" + badgeBg + ";padding:4px 10px;border-radius:12px;'>"
            + severity + "</span></td>"
            + "</tr></table>"
            // Event title
            + "<div style='margin-top:13px;font-size:20px;font-weight:700;color:#0d1117;"
            + "line-height:1.35;letter-spacing:-0.01em;'>" + esc(eventTitle) + "</div>"
            + "</td></tr>"

            // ── Meta strip (who/when) ──
            + metaStrip

            // ── Divider before body ──
            + "<tr><td style='height:1px;background:#f0f2f5;font-size:0;line-height:0;padding:0;'></td></tr>"

            // ── Body ──
            + "<tr><td style='padding:22px 24px " + (cta != null ? "18px" : "26px") + ";'>" + content + "</td></tr>"

            // ── CTA button ──
            + (cta != null
                ? "<tr><td style='padding:4px 24px 24px;text-align:center;'>"
                    + "<a href='" + esc(cta[1]) + "' style='display:inline-block;padding:11px 28px;"
                    + "background:" + accent + ";color:#ffffff;border-radius:7px;text-decoration:none;"
                    + "font-weight:600;font-size:13px;letter-spacing:0.01em;"
                    + "font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;'>"
                    + esc(cta[0]) + " &#8594;</a></td></tr>"
                : "")

            // ── Footer ──
            + "<tr><td style='background:#fafafa;border-top:1px solid #f0f2f5;"
            + "padding:13px 24px;text-align:center;'>"
            + "<span style='font-size:11px;color:#8b949e;letter-spacing:0.01em;'>"
            + "Jenkins OmniAuth Plugin &nbsp;&bull;&nbsp; Automated security notification</span>"
            + "</td></tr>"

            + "</table>" // inner table
            + "</td></tr>" // close content col + strip row
            + "</table>" // card
            + "</td></tr></table></body></html>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("\u2192", "&#8594;");
    }

    // -------------------------------------------------------------------------
    // Test — synchronous, throws on failure so the caller can surface the error
    // -------------------------------------------------------------------------

    public static void test(String host, int port, String username, String password,
                             boolean tls, String fromAddress, String fromName,
                             String replyTo, String to) throws Exception {
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

        String jenkinsUrl = "";
        try {
            String r = jenkins.model.Jenkins.get().getRootUrl();
            if (r != null && !r.isEmpty()) jenkinsUrl = r.endsWith("/") ? r.substring(0, r.length() - 1) : r;
        } catch (Exception ignored) {}
        String plainBody = "OmniAuth SMTP Test\n==================\n\n"
                + "If you received this, your SMTP configuration is correct.\n\n"
                + "Host: " + host + ":" + port + "\n"
                + "From: " + fromAddress + "\n"
                + "To:   " + to + "\n"
                + (jenkinsUrl.isEmpty() ? "" : "\nCTA: View Notification Log | " + jenkinsUrl + "/manage/omniauth-management/notificationLog")
                + "\n---\nJenkins OmniAuth Plugin";

        MimeMessage msg = new MimeMessage(session);
        String name = (fromName != null && !fromName.isEmpty()) ? fromName : "Jenkins OmniAuth";
        msg.setFrom(new InternetAddress(fromAddress, name));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        msg.setSubject("[Jenkins OmniAuth] Test email — SMTP is working");

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(plainBody, "UTF-8");
        MimeBodyPart htmlPart = new MimeBodyPart();
        htmlPart.setContent(buildHtml("[Jenkins OmniAuth] Test email — SMTP is working", plainBody, null), "text/html; charset=UTF-8");
        Multipart multipart = new MimeMultipart("alternative");
        multipart.addBodyPart(textPart);
        multipart.addBodyPart(htmlPart);
        msg.setContent(multipart);

        if (replyTo != null && !replyTo.trim().isEmpty()) {
            msg.setReplyTo(InternetAddress.parse(replyTo));
        }

        Transport.send(msg);
    }
}
