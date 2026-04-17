package io.jenkins.plugins.omniauth;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends OmniAuth notifications to a Slack incoming webhook.
 */
public class SlackHelper {

    private static final Logger LOGGER = Logger.getLogger(SlackHelper.class.getName());
    private static final String PREFIX = "[Jenkins OmniAuth] ";

    private SlackHelper() {}

    // -------------------------------------------------------------------------
    // Dispatch — async, captures config values before spawning thread
    // -------------------------------------------------------------------------

    public static void send(OmniAuthGlobalConfig cfg, String subject, String body) {
        if (cfg == null || !cfg.isNotificationsEnabled()) return;
        if (!cfg.isSlackEnabled()) return;
        String url = cfg.getSlackWebhookUrl();
        if (url == null || url.trim().isEmpty()) return;

        String title = subject.startsWith(PREFIX) ? subject.substring(PREFIX.length()) : subject;
        final String u = url.trim(), s = subject, t = title, b = body;
        Thread th = new Thread(() -> post(u, t, b, s));
        th.setDaemon(true);
        th.setName("omniauth-slack");
        th.start();
    }

    // -------------------------------------------------------------------------
    // Test — synchronous, throws on failure
    // -------------------------------------------------------------------------

    public static void test(String webhookUrl) throws Exception {
        String json = "{\"attachments\":[{\"color\":\"#27ae60\",\"title\":\"Test notification\","
                + "\"text\":\"OmniAuth Slack webhook is working correctly.\","
                + "\"footer\":\"Jenkins OmniAuth\"}]}";
        postJson(webhookUrl, json);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static void post(String webhookUrl, String title, String body, String subject) {
        try {
            String json = "{\"attachments\":[{\"color\":\"#0078d4\",\"title\":"
                    + escape(title) + ",\"text\":" + escape(body)
                    + ",\"footer\":\"Jenkins OmniAuth\"}]}";
            postJson(webhookUrl, json);
            NotificationLog.get().addEntry("[Slack] " + subject, webhookUrl, true, null);
            LOGGER.info("OmniAuth Slack sent: " + subject);
        } catch (Exception e) {
            NotificationLog.get().addEntry("[Slack] " + subject, webhookUrl, false, e.getMessage());
            LOGGER.log(Level.WARNING, "OmniAuth Slack failed: " + subject, e);
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
