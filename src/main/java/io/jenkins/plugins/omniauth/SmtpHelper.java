package io.jenkins.plugins.omniauth;

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
        final String to        = recipients;

        Thread t = new Thread(() -> sendNow(host, port, username, password, tls,
                fromAddr, fromName, replyTo, to, subject, body));
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
            NotificationLog.get().addEntry(subject, recipients, true, null);

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "OmniAuth email failed: " + subject, e);
            NotificationLog.get().addEntry(subject, recipients, false,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
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

        Transport.send(msg);
    }
}
