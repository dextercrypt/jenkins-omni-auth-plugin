package io.jenkins.plugins.omniauth;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends OmniAuth notifications to a Microsoft Teams incoming webhook using Adaptive Cards.
 * Compatible with Teams Workflows (Power Automate) webhooks.
 */
public class TeamsHelper {

    private static final Logger LOGGER = Logger.getLogger(TeamsHelper.class.getName());
    private static final String PREFIX = "[Jenkins OmniAuth] ";

    private TeamsHelper() {}

    // -------------------------------------------------------------------------
    // Dispatch — async
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
        postJson(webhookUrl, buildTestPayload());
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static void post(String webhookUrl, String title, String body, String subject) {
        try {
            postJson(webhookUrl, buildPayload(title, body));
            NotificationLog.get().addEntry("[Teams] " + subject, webhookUrl, true, null);
            LOGGER.info("OmniAuth Teams sent: " + subject);
        } catch (Exception e) {
            NotificationLog.get().addEntry("[Teams] " + subject, webhookUrl, false, e.getMessage());
            LOGGER.log(Level.WARNING, "OmniAuth Teams failed: " + subject, e);
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
        String sl = title.toLowerCase();
        String severityLabel, accentStyle, accentColor;
        if (sl.contains("brute force") || sl.contains("deleted") || sl.contains("disabled")
                || sl.contains("graph api") || sl.contains("failure")) {
            severityLabel = "CRITICAL"; accentStyle = "attention"; accentColor = "Attention";
        } else if (sl.contains("cleanup") || sl.contains("stale")) {
            severityLabel = "WARNING";  accentStyle = "warning";   accentColor = "Warning";
        } else if (sl.contains("granted") || sl.contains("enabled")) {
            severityLabel = "SUCCESS";  accentStyle = "good";      accentColor = "Good";
        } else {
            severityLabel = "INFO";     accentStyle = "accent";    accentColor = "Accent";
        }

        String eventTitle = title.replaceAll("^\\[Jenkins OmniAuth\\] ", "");

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

        StringBuilder items = new StringBuilder();

        // Header container — severity chip + event title
        items.append("{\"type\":\"Container\",\"style\":\"").append(accentStyle).append("\","
                + "\"bleed\":true,\"items\":["
                + "{\"type\":\"TextBlock\",\"text\":").append(esc(severityLabel))
              .append(",\"size\":\"Small\",\"weight\":\"Bolder\",\"color\":\"").append(accentColor).append("\"},"
                + "{\"type\":\"TextBlock\",\"text\":").append(esc(eventTitle))
              .append(",\"size\":\"Large\",\"weight\":\"Bolder\",\"wrap\":true,\"spacing\":\"None\"}"
                + "]}");

        // Actor + time columns
        if (actor != null || displayTime != null) {
            items.append(",{\"type\":\"ColumnSet\",\"spacing\":\"Medium\",\"columns\":[");
            if (actor != null) {
                items.append("{\"type\":\"Column\",\"width\":\"stretch\",\"items\":["
                        + "{\"type\":\"TextBlock\",\"text\":\"Actioned By\","
                        + "\"size\":\"Small\",\"weight\":\"Bolder\",\"isSubtle\":true},"
                        + "{\"type\":\"TextBlock\",\"text\":").append(esc(actor))
                      .append(",\"size\":\"Small\",\"spacing\":\"None\"}]}");
                if (displayTime != null) items.append(",");
            }
            if (displayTime != null) {
                items.append("{\"type\":\"Column\",\"width\":\"stretch\",\"items\":["
                        + "{\"type\":\"TextBlock\",\"text\":\"When\","
                        + "\"size\":\"Small\",\"weight\":\"Bolder\",\"isSubtle\":true},"
                        + "{\"type\":\"TextBlock\",\"text\":").append(esc(displayTime))
                      .append(",\"size\":\"Small\",\"spacing\":\"None\"}]}");
            }
            items.append("]}");
        }

        // Body content
        String bodyText = toAdaptiveText(body);
        if (!bodyText.isEmpty()) {
            items.append(",{\"type\":\"TextBlock\",\"text\":").append(esc(bodyText))
                 .append(",\"wrap\":true,\"spacing\":\"Medium\",\"separator\":true}");
        }

        // Footer
        items.append(",{\"type\":\"TextBlock\",\"text\":\"Jenkins OmniAuth Plugin\","
                + "\"size\":\"Small\",\"isSubtle\":true,\"spacing\":\"Medium\"}");

        String actions = cta != null
                ? ",\"actions\":[{\"type\":\"Action.OpenUrl\","
                    + "\"title\":" + esc(cta[0]) + ",\"url\":" + esc(cta[1]) + "}]"
                : "";

        String card = "{\"$schema\":\"http://adaptivecards.io/schemas/adaptive-card.json\","
                + "\"type\":\"AdaptiveCard\",\"version\":\"1.4\","
                + "\"body\":[" + items + "]" + actions + "}";

        return "{\"type\":\"message\",\"attachments\":[{"
                + "\"contentType\":\"application/vnd.microsoft.card.adaptive\","
                + "\"content\":" + card + "}]}";
    }

    private static String buildTestPayload() {
        return buildPayload("Test Notification",
                "Jenkins OmniAuth\n================\n\n"
                + "This is a test message confirming your Microsoft Teams webhook is configured correctly.\n\n"
                + "---\nJenkins OmniAuth Plugin");
    }

    // Convert plain-text body to Adaptive Cards markdown
    private static String toAdaptiveText(String plainText) {
        StringBuilder sb = new StringBuilder();
        String[] lines = plainText.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i], tr = line.trim();
            if (tr.matches("={3,}") || tr.matches("-{3,}")) continue;
            if (tr.equals("Jenkins OmniAuth Plugin")) continue;
            if (!tr.isEmpty()) {
                int c = tr.indexOf(':');
                if (c > 0) {
                    String k = tr.substring(0, c).toLowerCase().replaceAll("\\s+", " ").trim();
                    if (k.equals("changed by") || k.equals("granted by") || k.equals("deleted by")
                            || k.equals("when") || k.equals("run at")) continue;
                }
            }
            if (i + 1 < lines.length && lines[i + 1].trim().matches("={3,}")) continue;
            if (tr.isEmpty()) { sb.append("\r\n"); continue; }

            // Diff: "  key: old → new"
            if (line.startsWith("  ") && !line.startsWith("  - ") && !line.startsWith("  + ")) {
                int arrow = tr.indexOf(" \u2192 ");
                if (arrow > 0) {
                    int colon = tr.indexOf(':');
                    String key      = colon > 0 ? tr.substring(0, colon).trim() : tr.substring(0, arrow).trim();
                    String diffPart = colon > 0 ? tr.substring(colon + 1).trim() : tr;
                    int da          = diffPart.indexOf(" \u2192 ");
                    String before   = da > 0 ? diffPart.substring(0, da).trim()  : diffPart;
                    String after    = da > 0 ? diffPart.substring(da + 3).trim() : "";
                    sb.append("- **").append(key).append(":** ~~").append(before)
                      .append("~~ \u2192 **").append(after).append("**\r\n");
                    continue;
                }
                sb.append("- ").append(tr).append("\r\n");
                continue;
            }
            if (line.startsWith("  - ")) {
                sb.append("- ~~").append(line.substring(4).trim()).append("~~\r\n");
                continue;
            }
            if (line.startsWith("  + ")) {
                sb.append("- **").append(line.substring(4).trim()).append("**\r\n");
                continue;
            }
            if (!line.startsWith(" ") && tr.endsWith(":")) {
                sb.append("\r\n**").append(tr.substring(0, tr.length() - 1).toUpperCase()).append("**\r\n");
                continue;
            }
            int colon = tr.indexOf(':');
            if (!line.startsWith(" ") && colon > 0 && colon < tr.length() - 1) {
                String k = tr.substring(0, colon).trim();
                String v = tr.substring(colon + 1).trim();
                if (!v.isEmpty() && k.length() <= 32) {
                    sb.append("**").append(k).append(":** ").append(v).append("\r\n");
                    continue;
                }
            }
            sb.append(tr).append("\r\n");
        }
        return sb.toString().trim();
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

    private static String esc(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "").replace("\t", "\\t") + "\"";
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
