package io.jenkins.plugins.omniauth;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends OmniAuth notifications to a Microsoft Teams incoming webhook (MessageCard format).
 * Compatible with Office 365 Connectors and Power Automate incoming webhook flows.
 */
public class TeamsHelper {

    private static final Logger LOGGER = Logger.getLogger(TeamsHelper.class.getName());
    private static final String PREFIX = "[Jenkins OmniAuth] ";

    private TeamsHelper() {}

    // -------------------------------------------------------------------------
    // Dispatch — async, captures config values before spawning thread
    // -------------------------------------------------------------------------

    public static void send(OmniAuthGlobalConfig cfg, String subject, String body) {
        if (cfg == null || !cfg.isNotificationsEnabled()) return;
        if (!cfg.isTeamsEnabled()) return;
        String url = cfg.getTeamsWebhookUrl();
        if (url == null || url.trim().isEmpty()) return;

        String title = subject.startsWith(PREFIX) ? subject.substring(PREFIX.length()) : subject;
        final String u = url.trim(), s = subject, t = title, b = body;
        Thread th = new Thread(() -> post(u, t, b, s));
        th.setDaemon(true);
        th.setName("omniauth-teams");
        th.start();
    }

    // -------------------------------------------------------------------------
    // Test — synchronous, throws on failure
    // -------------------------------------------------------------------------

    public static void test(String webhookUrl) throws Exception {
        String json = "{\"title\":\"Test notification\","
                + "\"text\":\"OmniAuth Teams webhook is working correctly.\"}";
        postJson(webhookUrl, json);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static void post(String webhookUrl, String title, String body, String subject) {
        try {
            String json = "{\"title\":" + escape(title) + ",\"text\":" + escape(body) + "}";
            postJson(webhookUrl, json);
            NotificationLog.get().addEntry("[Teams] " + subject, webhookUrl, true, null);
            LOGGER.info("OmniAuth Teams sent: " + subject);
        } catch (Exception e) {
            NotificationLog.get().addEntry("[Teams] " + subject, webhookUrl, false, e.getMessage());
            LOGGER.log(Level.WARNING, "OmniAuth Teams failed: " + subject, e);
        }
    }

    private static void postJson(String url, String json) throws Exception {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(json))
                .timeout(java.time.Duration.ofSeconds(10))
                .build();
        java.net.http.HttpResponse<String> resp =
                client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 300) {
            throw new Exception("HTTP " + resp.statusCode() + ": " + resp.body());
        }
    }

    private static String escape(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                        .replace("\n", "\\n").replace("\r", "") + "\"";
    }
}
