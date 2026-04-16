package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Extension
public class OmniAuthGlobalConfig extends GlobalConfiguration {

    private static final int MAX_HISTORY = 10;

    // ── Protected users ───────────────────────────────────────────────────────
    private List<String> protectedUsers = new ArrayList<>();

    // ── Thresholds ────────────────────────────────────────────────────────────
    private int staleThresholdDays  = 90;
    private int activeThresholdDays = 30;

    // ── Automated cleanup ─────────────────────────────────────────────────────
    private boolean cleanupEnabled      = false;
    private boolean cleanupDryRun       = true;
    private String  cleanupCron         = "0 2 * * 0";
    private int     cleanupMaxDeletions = 50;
    private String  cleanupNotifyEmail  = "";

    // ── Cleanup history ───────────────────────────────────────────────────────
    private List<CleanupRunRecord> cleanupHistory = new ArrayList<>();

    // ── Singleton ─────────────────────────────────────────────────────────────

    public static OmniAuthGlobalConfig get() {
        return GlobalConfiguration.all().get(OmniAuthGlobalConfig.class);
    }

    public OmniAuthGlobalConfig() { load(); }

    // ── Getters ───────────────────────────────────────────────────────────────

    public List<String> getProtectedUsers()  { return Collections.unmodifiableList(protectedUsers); }
    public boolean isProtected(String uid)   { return uid != null && protectedUsers.contains(uid); }
    public int getStaleThresholdDays()       { return staleThresholdDays; }
    public int getActiveThresholdDays()      { return activeThresholdDays; }
    public boolean isCleanupEnabled()        { return cleanupEnabled; }
    public boolean isCleanupDryRun()         { return cleanupDryRun; }
    public String getCleanupCron()           { return cleanupCron; }
    public int getCleanupMaxDeletions()      { return cleanupMaxDeletions; }
    public String getCleanupNotifyEmail()    { return cleanupNotifyEmail; }
    public List<CleanupRunRecord> getCleanupHistory() {
        return Collections.unmodifiableList(cleanupHistory);
    }

    public List<User> getAllUsers() {
        List<User> users = new ArrayList<>(User.getAll());
        users.sort((a, b) -> a.getId().compareToIgnoreCase(b.getId()));
        return users;
    }

    // ── History mutation ──────────────────────────────────────────────────────

    public synchronized void addCleanupRecord(CleanupRunRecord record) {
        cleanupHistory.add(0, record); // newest first
        if (cleanupHistory.size() > MAX_HISTORY) {
            cleanupHistory = new ArrayList<>(cleanupHistory.subList(0, MAX_HISTORY));
        }
        save();
    }

    // ── configure() ───────────────────────────────────────────────────────────

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        // Protected users
        protectedUsers = new ArrayList<>();
        Object raw = json.opt("protectedUsers");
        if (raw instanceof JSONArray) {
            for (Object o : (JSONArray) raw) protectedUsers.add(o.toString());
        } else if (raw instanceof String && !((String) raw).isEmpty()) {
            protectedUsers.add(raw.toString());
        }

        staleThresholdDays  = jsonInt(json, "staleThresholdDays",  90);
        activeThresholdDays = jsonInt(json, "activeThresholdDays", 30);
        cleanupEnabled      = json.optBoolean("cleanupEnabled",  false);
        // If auto-cleanup is disabled, always force dry-run ON (safety default)
        cleanupDryRun       = !cleanupEnabled || json.optBoolean("cleanupDryRun", true);
        cleanupCron         = jsonStr(json, "cleanupCron",         "0 2 * * 0");
        cleanupMaxDeletions = jsonInt(json, "cleanupMaxDeletions", 50);
        cleanupNotifyEmail  = jsonStr(json, "cleanupNotifyEmail",  "");

        save();
        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static int jsonInt(JSONObject json, String key, int fallback) {
        try {
            Object v = json.opt(key);
            return v == null ? fallback : Integer.parseInt(v.toString().trim());
        } catch (NumberFormatException e) { return fallback; }
    }

    private static String jsonStr(JSONObject json, String key, String fallback) {
        Object v = json.opt(key);
        if (v == null) return fallback;
        String s = v.toString().trim();
        return s.isEmpty() ? fallback : s;
    }

    // ── CleanupRunRecord ──────────────────────────────────────────────────────

    public static final class CleanupRunRecord {
        private final String       timestamp;
        private final boolean      dryRun;
        private final int          usersScanned;
        private final int          usersAffected;
        private final int          skippedProtected;
        private final List<String> affectedUserIds;

        public CleanupRunRecord(String timestamp, boolean dryRun,
                                int usersScanned, int usersAffected,
                                int skippedProtected, List<String> affectedUserIds) {
            this.timestamp        = timestamp;
            this.dryRun           = dryRun;
            this.usersScanned     = usersScanned;
            this.usersAffected    = usersAffected;
            this.skippedProtected = skippedProtected;
            this.affectedUserIds  = new ArrayList<>(affectedUserIds);
        }

        public String       getTimestamp()        { return timestamp; }
        public boolean      isDryRun()            { return dryRun; }
        public int          getUsersScanned()     { return usersScanned; }
        public int          getUsersAffected()    { return usersAffected; }
        public int          getSkippedProtected() { return skippedProtected; }
        public List<String> getAffectedUserIds()  { return Collections.unmodifiableList(affectedUserIds); }
    }
}
