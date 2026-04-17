package io.jenkins.plugins.omniauth;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends OmniAuth notifications to a Slack incoming webhook using Block Kit.
 */
public class SlackHelper {

    private static final Logger LOGGER = Logger.getLogger(SlackHelper.class.getName());
    private static final String PREFIX = "[Jenkins OmniAuth] ";

    private SlackHelper() {}

    // -------------------------------------------------------------------------
    // Dispatch — async
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
        String json = buildTestPayload();
        postJson(webhookUrl, json);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static void post(String webhookUrl, String title, String body, String subject) {
        try {
            postJson(webhookUrl, buildPayload(title, body));
            NotificationLog.get().addEntry("[Slack] " + subject, webhookUrl, true, null);
            LOGGER.info("OmniAuth Slack sent: " + subject);
        } catch (Exception e) {
            NotificationLog.get().addEntry("[Slack] " + subject, webhookUrl, false, e.getMessage());
            LOGGER.log(Level.WARNING, "OmniAuth Slack failed: " + subject, e);
        }
    }

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

    static String buildPayload(String title, String body) {
        String[] cta = extractCta(body);
        body = stripCta(body);
        String color = colorFor(title);

        // Extract actor + timestamp
        String actor = null, rawTime = null;
        for (String line : body.split("\n")) {
            String t = line.trim();
            int c = t.indexOf(':');
            if (c <= 0) continue;
            String k = t.substring(0, c).toLowerCase().replaceAll("\\s+", " ").trim();
            String v = t.substring(c + 1).trim();
            if (k.equals("changed by") || k.equals("granted by") || k.equals("deleted by")) actor = v;
            else if (k.equals("when") || k.equals("run at")) rawTime = v;
        }
        String displayTime = formatTime(rawTime);

        StringBuilder blocks = new StringBuilder("[");

        // Header
        blocks.append("{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":")
              .append(esc(title)).append(",\"emoji\":true}},");

        // Actor + time fields
        if (actor != null || displayTime != null) {
            blocks.append("{\"type\":\"section\",\"fields\":[");
            if (actor != null) {
                blocks.append("{\"type\":\"mrkdwn\",\"text\":").append(esc("*Actioned By*\n" + actor)).append("}");
                if (displayTime != null) blocks.append(",");
            }
            if (displayTime != null) {
                blocks.append("{\"type\":\"mrkdwn\",\"text\":").append(esc("*When*\n" + displayTime)).append("}");
            }
            blocks.append("]},");
            blocks.append("{\"type\":\"divider\"},");
        }

        // Body
        String mrkdwn = toMrkdwn(body);
        if (!mrkdwn.isEmpty()) {
            if (mrkdwn.length() > 2900) mrkdwn = mrkdwn.substring(0, 2900) + "…";
            blocks.append("{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":")
                  .append(esc(mrkdwn)).append("}},");
        }

        // CTA button
        if (cta != null) {
            blocks.append(",{\"type\":\"actions\",\"elements\":[{\"type\":\"button\","
                    + "\"text\":{\"type\":\"plain_text\",\"text\":").append(esc(cta[0] + " →")).append(",\"emoji\":true},"
                    + "\"url\":").append(esc(cta[1])).append(",\"style\":\"primary\"}]}");
        }

        // Footer context
        blocks.append(",{\"type\":\"context\",\"elements\":[{\"type\":\"mrkdwn\","
                + "\"text\":\"Jenkins OmniAuth Plugin\"}]}");
        blocks.append("]");

        return "{\"attachments\":[{\"color\":\"" + color + "\",\"blocks\":" + blocks + "}]}";
    }

    private static String buildTestPayload() {
        return buildPayload("Test Notification",
                "Jenkins OmniAuth\n================\n\n"
                + "This is a test message confirming your Slack webhook is configured correctly.\n\n"
                + "---\nJenkins OmniAuth Plugin");
    }

    // Convert plain-text body to Slack mrkdwn
    private static String toMrkdwn(String plainText) {
        StringBuilder sb = new StringBuilder();
        String[] lines = plainText.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i], tr = line.trim();
            if (tr.matches("={3,}") || tr.matches("-{3,}")) continue;
            if (tr.equals("Jenkins OmniAuth Plugin")) continue;
            // Skip metadata shown in header fields
            if (!tr.isEmpty()) {
                int c = tr.indexOf(':');
                if (c > 0) {
                    String k = tr.substring(0, c).toLowerCase().replaceAll("\\s+", " ").trim();
                    if (k.equals("changed by") || k.equals("granted by") || k.equals("deleted by")
                            || k.equals("when") || k.equals("run at")) continue;
                }
            }
            // Skip section title (line before ===)
            if (i + 1 < lines.length && lines[i + 1].trim().matches("={3,}")) continue;

            if (tr.isEmpty()) { sb.append("\n"); continue; }

            // Diff line: "  key: old → new"
            if (line.startsWith("  ") && !line.startsWith("  - ") && !line.startsWith("  + ")) {
                int arrow = tr.indexOf(" \u2192 ");
                if (arrow > 0) {
                    int colon = tr.indexOf(':');
                    String key      = colon > 0 ? tr.substring(0, colon).trim() : tr.substring(0, arrow).trim();
                    String diffPart = colon > 0 ? tr.substring(colon + 1).trim() : tr;
                    int da          = diffPart.indexOf(" \u2192 ");
                    String before   = da > 0 ? diffPart.substring(0, da).trim()  : diffPart;
                    String after    = da > 0 ? diffPart.substring(da + 3).trim() : "";
                    sb.append("\u2022 *").append(md(key)).append(":*  ~").append(md(before))
                      .append("~  \u2192  *").append(md(after)).append("*\n");
                    continue;
                }
                sb.append("\u2022 ").append(md(tr)).append("\n");
                continue;
            }
            // Removed bullet
            if (line.startsWith("  - ")) {
                sb.append("\u2022 ~").append(md(line.substring(4).trim())).append("~\n");
                continue;
            }
            // Added bullet
            if (line.startsWith("  + ")) {
                sb.append("\u2022 *").append(md(line.substring(4).trim())).append("*\n");
                continue;
            }
            // Subheading "Label:"
            if (!line.startsWith(" ") && tr.endsWith(":")) {
                sb.append("\n*").append(md(tr.substring(0, tr.length() - 1).toUpperCase())).append("*\n");
                continue;
            }
            // Key: Value
            int colon = tr.indexOf(':');
            if (!line.startsWith(" ") && colon > 0 && colon < tr.length() - 1) {
                String k = tr.substring(0, colon).trim();
                String v = tr.substring(colon + 1).trim();
                if (!v.isEmpty() && k.length() <= 32) {
                    sb.append("*").append(md(k)).append(":*  ").append(md(v)).append("\n");
                    continue;
                }
            }
            sb.append(md(tr)).append("\n");
        }
        return sb.toString().trim();
    }

    private static String colorFor(String title) {
        String sl = title.toLowerCase();
        if (sl.contains("brute force") || sl.contains("deleted") || sl.contains("disabled")
                || sl.contains("graph api") || sl.contains("failure")) return "#dc2626";
        if (sl.contains("cleanup") || sl.contains("stale"))  return "#d97706";
        if (sl.contains("granted") || sl.contains("enabled")) return "#16a34a";
        return "#2563eb";
    }

    private static String formatTime(String rawTime) {
        if (rawTime == null) return null;
        try {
            java.time.Instant inst = java.time.Instant.parse(rawTime);
            return java.time.format.DateTimeFormatter
                .ofPattern("MMM d, yyyy 'at' HH:mm 'UTC'")
                .withZone(java.time.ZoneId.of("UTC"))
                .format(inst);
        } catch (Exception ignored) {
            return rawTime;
        }
    }

    // Escape for JSON string value
    private static String esc(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "").replace("\t", "\\t") + "\"";
    }

    // Escape Slack mrkdwn special chars
    private static String md(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static void postJson(String url, String json) throws Exception {
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
}
