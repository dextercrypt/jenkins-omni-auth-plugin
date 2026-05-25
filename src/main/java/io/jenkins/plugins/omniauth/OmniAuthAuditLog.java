package io.jenkins.plugins.omniauth;

import hudson.Extension;
import jenkins.model.Jenkins;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class OmniAuthAuditLog {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthAuditLog.class.getName());
    private static final int MAX_MONTHS = 12;
    private static final DateTimeFormatter MONTH_FMT = DateTimeFormatter.ofPattern("yyyy-MM");

    public static OmniAuthAuditLog get() {
        return Jenkins.get().getExtensionList(OmniAuthAuditLog.class).get(0);
    }

    // -------------------------------------------------------------------------
    // Convenience log methods
    // -------------------------------------------------------------------------

    public void logGrant(String by, String user, String role, String scope, String expiresAt) {
        Map<String, String> e = event("grant");
        e.put("by", by); e.put("user", user); e.put("role", role); e.put("scope", scopeLabel(scope));
        if (expiresAt != null && !expiresAt.isBlank()) e.put("expiresAt", expiresAt);
        write(e);
    }

    public void logRevoke(String by, String user, String scope, String role) {
        Map<String, String> e = event("revoke");
        e.put("by", by); e.put("user", user); e.put("scope", scopeLabel(scope));
        if (role != null && !role.isBlank()) e.put("role", role);
        write(e);
    }

    public void logEdit(String by, String user, String scope, String oldRole, String newRole, String expiresAt) {
        Map<String, String> e = event("edit");
        e.put("by", by); e.put("user", user); e.put("scope", scopeLabel(scope));
        e.put("oldRole", oldRole); e.put("newRole", newRole);
        if (expiresAt != null && !expiresAt.isBlank()) e.put("expiresAt", expiresAt);
        write(e);
    }

    public void logExpired(String user, String scope) {
        Map<String, String> e = event("expired");
        e.put("user", user); e.put("scope", scopeLabel(scope));
        write(e);
    }

    public void logRoleCreated(String by, String name) {
        Map<String, String> e = event("role_created");
        e.put("by", by); e.put("role", name);
        write(e);
    }

    public void logRoleEdited(String by, String name) {
        Map<String, String> e = event("role_edited");
        e.put("by", by); e.put("role", name);
        write(e);
    }

    public void logRoleDeleted(String by, String name) {
        Map<String, String> e = event("role_deleted");
        e.put("by", by); e.put("role", name);
        write(e);
    }

    public void logLoginSuccess(String user, String authType, String ip) {
        Map<String, String> e = event("login_success");
        e.put("user", user); e.put("authType", authType); e.put("ip", normalizeIp(ip));
        write(e);
    }

    public void logLoginFailure(String username, String ip) {
        Map<String, String> e = event("login_failure");
        e.put("user", username); e.put("ip", normalizeIp(ip));
        write(e);
    }

    public void logUserCreated(String by, String user) {
        Map<String, String> e = event("user_created");
        e.put("by", by); e.put("user", user);
        write(e);
    }

    public void logUserDeleted(String by, String user) {
        Map<String, String> e = event("user_deleted");
        e.put("by", by); e.put("user", user);
        write(e);
    }

    public void logBreakGlassActivate(String by, String reason) {
        Map<String, String> e = event("break_glass_activate");
        e.put("by", by); e.put("reason", reason);
        write(e);
    }

    public void logBreakGlassFailed(String by, String reason) {
        Map<String, String> e = event("break_glass_failed");
        e.put("by", by); e.put("reason", reason);
        write(e);
    }

    public void logBreakGlassDeactivate(String by) {
        Map<String, String> e = event("break_glass_deactivate");
        e.put("by", by);
        write(e);
    }

    public void logBreakGlassEnrolled(String by) {
        Map<String, String> e = event("break_glass_enrolled");
        e.put("by", by);
        write(e);
    }

    public void logBreakGlassUnenrolled(String by) {
        Map<String, String> e = event("break_glass_unenrolled");
        e.put("by", by);
        write(e);
    }

    public void logReviewConfirmed(String by, String user, String role, String scope) {
        Map<String, String> e = event("review_confirmed");
        e.put("by", by); e.put("user", user);
        if (role != null && !role.isBlank()) e.put("role", role);
        e.put("scope", scopeLabel(scope));
        write(e);
    }

    // -------------------------------------------------------------------------
    // Read for UI — returns last maxLines events across current + previous month
    // -------------------------------------------------------------------------

    public int[] getFailureCountsByDay(int days) {
        int[] counts = new int[days];
        try {
            java.time.LocalDate today = java.time.LocalDate.now(java.time.ZoneOffset.UTC);
            List<Map<String, String>> entries = readRecent(5000);
            for (Map<String, String> entry : entries) {
                if (!"login_failure".equals(entry.get("action"))) continue;
                String ts = entry.get("ts");
                if (ts == null) continue;
                try {
                    java.time.LocalDate entryDate = java.time.Instant.parse(ts)
                            .atZone(java.time.ZoneOffset.UTC).toLocalDate();
                    long daysAgo = java.time.temporal.ChronoUnit.DAYS.between(entryDate, today);
                    if (daysAgo >= 0 && daysAgo < days) counts[(int)(days - 1 - daysAgo)]++;
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return counts;
    }

    public List<Map<String, String>> readRecent(int maxLines) {
        List<String> lines = new ArrayList<>();
        File logsDir = logsDir();
        if (logsDir == null) return Collections.emptyList();

        // Collect files sorted newest first
        File[] files = logsDir.listFiles((d, n) -> n.startsWith("omniauth-audit-") && n.endsWith(".json"));
        if (files == null) return Collections.emptyList();
        List<File> sorted = new ArrayList<>();
        for (File f : files) sorted.add(f);
        sorted.sort((a, b) -> b.getName().compareTo(a.getName())); // newest first

        for (File f : sorted) {
            if (lines.size() >= maxLines * 2) break; // read extra, then trim
            try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                List<String> fileLines = new ArrayList<>();
                String line;
                while ((line = br.readLine()) != null) {
                    if (!line.isBlank()) fileLines.add(line);
                }
                // Prepend (newer files first, newer lines within file first)
                Collections.reverse(fileLines);
                lines.addAll(0, fileLines); // actually we want newest first overall
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "Failed to read audit log: " + f.getName(), ex);
            }
        }

        // lines is now newest-first across all files; trim to maxLines
        List<Map<String, String>> result = new ArrayList<>();
        int limit = Math.min(maxLines, lines.size());
        for (int i = 0; i < limit; i++) {
            Map<String, String> parsed = parseLine(lines.get(i));
            if (parsed != null) result.add(parsed);
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private Map<String, String> event(String action) {
        Map<String, String> e = new LinkedHashMap<>();
        e.put("ts", java.time.Instant.now().toString());
        e.put("action", action);
        try {
            org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (req != null) {
                String forwarded = req.getHeader("X-Forwarded-For");
                String raw = (forwarded != null && !forwarded.isBlank())
                        ? forwarded.split(",")[0].trim()
                        : req.getRemoteAddr();
                String ip = normalizeIp(raw);
                if (ip != null && !ip.isBlank()) e.put("ip", ip);
            }
        } catch (Exception ignored) {}
        return e;
    }

    public synchronized int purgeAll() {
        File dir = logsDir();
        if (dir == null) return 0;
        File[] files = dir.listFiles((d, n) -> n.startsWith("omniauth-audit-") && n.endsWith(".json"));
        if (files == null) return 0;
        int deleted = 0;
        for (File f : files) {
            if (f.delete()) deleted++;
        }
        return deleted;
    }

    private String scopeLabel(String scope) {
        return (scope == null || scope.isBlank()) ? "global" : scope;
    }

    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) return "";
        String s = ip.replaceAll("[\\[\\]]", ""); // strip IPv6 brackets
        if (s.equals("::1") || s.equals("0:0:0:0:0:0:0:1") || s.equals("127.0.0.1")) return "localhost";
        return s;
    }

    private synchronized void write(Map<String, String> fields) {
        File logFile = currentLogFile();
        if (logFile == null) return;
        try {
            logFile.getParentFile().mkdirs();
            try (PrintWriter pw = new PrintWriter(new FileWriter(logFile, true))) {
                pw.println(toJson(fields));
            }
            cleanupOldFiles();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to write audit log entry", e);
        }
    }

    private File currentLogFile() {
        File dir = logsDir();
        if (dir == null) return null;
        String month = YearMonth.now().format(MONTH_FMT);
        return new File(dir, "omniauth-audit-" + month + ".json");
    }

    private File logsDir() {
        try {
            return new File(Jenkins.get().getRootDir(), "logs");
        } catch (Exception e) {
            return null;
        }
    }

    private void cleanupOldFiles() {
        File dir = logsDir();
        if (dir == null) return;
        File[] files = dir.listFiles((d, n) -> n.startsWith("omniauth-audit-") && n.endsWith(".json"));
        if (files == null || files.length <= MAX_MONTHS) return;
        List<File> sorted = new ArrayList<>();
        for (File f : files) sorted.add(f);
        sorted.sort((a, b) -> a.getName().compareTo(b.getName())); // oldest first
        while (sorted.size() > MAX_MONTHS) {
            sorted.get(0).delete();
            sorted.remove(0);
        }
    }

    private String toJson(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(jsonEscape(entry.getKey())).append("\":");
            sb.append("\"").append(jsonEscape(entry.getValue())).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private Map<String, String> parseLine(String line) {
        if (line == null || line.isBlank()) return null;
        try {
            Map<String, String> map = new LinkedHashMap<>();
            String s = line.trim();
            if (s.startsWith("{")) s = s.substring(1);
            if (s.endsWith("}")) s = s.substring(0, s.length() - 1);
            for (String pair : s.split(",(?=\")")) {
                int colon = pair.indexOf(':');
                if (colon < 0) continue;
                String key = pair.substring(0, colon).trim().replace("\"", "");
                String val = pair.substring(colon + 1).trim();
                if (val.startsWith("\"") && val.endsWith("\"")) val = val.substring(1, val.length() - 1);
                map.put(key, val.replace("\\\"", "\"").replace("\\n", "\n").replace("\\\\", "\\"));
            }
            return map;
        } catch (Exception e) {
            return null;
        }
    }
}
