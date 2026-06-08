package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import hudson.util.Secret;
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
    private String  cleanupNotifyEmail  = ""; // legacy — kept for migration, replaced by notifyEmails

    // ── Notifications master + channels ──────────────────────────────────────
    private boolean notificationsEnabled = false;
    private boolean smtpEnabled          = false;
    private boolean slackEnabled         = false;
    private String  slackWebhookUrl      = "";
    private boolean teamsEnabled         = false;
    private String  teamsWebhookUrl      = "";

    // ── SMTP configuration ────────────────────────────────────────────────────
    private String  smtpHost        = "";
    private int     smtpPort        = 587;
    private String  smtpUsername    = "";
    private Secret  smtpPassword    = null;
    private boolean smtpTls         = true;
    private String  smtpFromAddress = "";
    private String  smtpFromName    = "Jenkins OmniAuth";
    private String  smtpReplyTo     = "";
    private String  notifyEmails    = ""; // comma-separated recipients

    // ── Brute force detection ─────────────────────────────────────────────────
    private int bruteForceThreshold = 5;

    // ── Stale warning ─────────────────────────────────────────────────────────
    private boolean staleWarningEnabled    = false;
    private String  staleWarningCron       = "0 9 * * 1";
    private int     staleWarningWindowDays = 14;

    // ── Access review ─────────────────────────────────────────────────────────
    private boolean accessReviewEnabled       = false;
    private int     accessReviewThresholdDays = 90;

    // ── JIT history retention ─────────────────────────────────────────────────
    private int jitHistoryRetentionDays = 90;

    // ── Login page branding ───────────────────────────────────────────────────
    private String loginHeading          = "";
    private String loginTabTitle         = "";
    private String loginAnnouncementText = "";
    private String loginFooterText       = "";
    // Which background the login panel shows. Known values: "omniauth" (animated reactor,
    // default) and "starburst" (Jenkins' native starburst). New designs can be added later.
    private String loginBackground       = "omniauth";
    // Where the company logo sits on the login form. Known values: "a" (top of the
    // form column, left-aligned — default), "e" (pinned top-right corner of the panel),
    // "f" (logo centred above the form). Only takes effect when a logo is uploaded.
    private String loginLogoPosition     = "a";
    // Company-logo height on the login form, in px. Known values: "20", "30", "40" (default).
    private String loginLogoSize         = "40";
    // Centre figure on the animated login panel. Known values: "default" (native Jenkins
    // butler) and "austin" (the "Willie Nelson"/Austin Jenkins butler, CC BY-SA 3.0).
    private String loginButler           = "default";

    // ── Notification branding ─────────────────────────────────────────────────
    private String notificationLogoUrl  = "";
    private String notificationFooterNote = "";

    // ── Per-channel event subscriptions ──────────────────────────────────────
    private List<String> smtpEvents  = new ArrayList<>(java.util.Arrays.asList(ALL_EVENTS));
    private List<String> slackEvents = new ArrayList<>();
    private List<String> teamsEvents = new ArrayList<>();

    public static final String[] ALL_EVENTS = {
        "cleanup", "userDeleted", "configChanged", "protectedListChanged",
        "graphApiFailure", "adminGranted", "bruteForce", "staleWarning", "accessReview"
    };

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

    // SMTP
    public String  getSmtpHost()        { return smtpHost; }
    public int     getSmtpPort()        { return smtpPort; }
    public String  getSmtpUsername()    { return smtpUsername; }
    public Secret  getSmtpPassword()    { return smtpPassword; }
    public boolean isSmtpTls()          { return smtpTls; }
    public String  getSmtpFromAddress() { return smtpFromAddress; }
    public String  getSmtpFromName()    { return smtpFromName; }
    public String  getLoginHeading()   { return loginHeading  != null ? loginHeading.trim()  : ""; }
    public String  getLoginTabTitle()  { return loginTabTitle != null ? loginTabTitle.trim() : ""; }
    public void    setLoginHeading(String v)  { this.loginHeading  = v != null ? v.trim() : ""; }
    public void    setLoginTabTitle(String v) { this.loginTabTitle = v != null ? v.trim() : ""; }
    public String  getLoginAnnouncementText() { return loginAnnouncementText != null ? loginAnnouncementText.trim() : ""; }
    public String  getLoginFooterText()       { return loginFooterText != null ? loginFooterText.trim() : ""; }
    public void    setLoginAnnouncementText(String v) { this.loginAnnouncementText = v != null ? v.trim() : ""; }
    public void    setLoginFooterText(String v)       { this.loginFooterText       = v != null ? v.trim() : ""; }
    public String  getLoginBackground() {
        String v = loginBackground != null ? loginBackground.trim() : "";
        return v.isEmpty() ? "omniauth" : v;
    }
    public void    setLoginBackground(String v) { this.loginBackground = (v != null && !v.trim().isEmpty()) ? v.trim() : "omniauth"; }
    public String  getLoginLogoPosition() {
        String v = loginLogoPosition != null ? loginLogoPosition.trim() : "";
        return (v.equals("a") || v.equals("e") || v.equals("f")) ? v : "a";
    }
    public void    setLoginLogoPosition(String v) {
        String t = v != null ? v.trim() : "";
        this.loginLogoPosition = (t.equals("e") || t.equals("f")) ? t : "a";
    }
    public String  getLoginLogoSize() {
        String v = loginLogoSize != null ? loginLogoSize.trim() : "";
        return (v.equals("20") || v.equals("30") || v.equals("40")) ? v : "40";
    }
    public void    setLoginLogoSize(String v) {
        String t = v != null ? v.trim() : "";
        this.loginLogoSize = (t.equals("20") || t.equals("30")) ? t : "40";
    }
    public String  getLoginButler() {
        String v = loginButler != null ? loginButler.trim() : "";
        return v.equals("austin") ? "austin" : "default";
    }
    public void    setLoginButler(String v) {
        String t = v != null ? v.trim() : "";
        this.loginButler = t.equals("austin") ? "austin" : "default";
    }

    public String  getNotificationLogoUrl() {
        return notificationLogoUrl != null ? notificationLogoUrl.trim() : "";
    }
    public String  getNotificationFooterNote() {
        return notificationFooterNote != null ? notificationFooterNote.trim() : "";
    }
    public String  getSmtpReplyTo()     { return smtpReplyTo; }
    public String  getNotifyEmails()    { return notifyEmails; }

    public boolean isSmtpConfigured() {
        return smtpHost != null && !smtpHost.isEmpty()
            && smtpFromAddress != null && !smtpFromAddress.isEmpty()
            && smtpUsername != null && !smtpUsername.isEmpty()
            && smtpPassword != null;
    }

    // Notifications master + channels
    public boolean isNotificationsEnabled() { return notificationsEnabled; }
    public boolean isSmtpEnabled()          { return smtpEnabled; }
    public boolean isSlackEnabled()         { return slackEnabled; }
    public String  getSlackWebhookUrl()     { return slackWebhookUrl; }
    public boolean isTeamsEnabled()         { return teamsEnabled; }
    public String  getTeamsWebhookUrl()     { return teamsWebhookUrl; }

    // JIT history retention
    public int getJitHistoryRetentionDays() { return jitHistoryRetentionDays > 0 ? jitHistoryRetentionDays : 90; }
    public void setJitHistoryRetentionDays(int v) { this.jitHistoryRetentionDays = v > 0 ? v : 90; }

    // Brute force
    public int getBruteForceThreshold() { return bruteForceThreshold; }

    // Stale warning
    public boolean isStaleWarningEnabled()    { return staleWarningEnabled; }
    public String  getStaleWarningCron()      { return staleWarningCron; }
    public int     getStaleWarningWindowDays(){ return staleWarningWindowDays; }

    // Access review
    public boolean isAccessReviewEnabled()       { return accessReviewEnabled; }
    public int     getAccessReviewThresholdDays() { return accessReviewThresholdDays; }

    // Per-channel event subscriptions
    public List<String> getSmtpEvents()  { return Collections.unmodifiableList(smtpEvents); }
    public List<String> getSlackEvents() { return Collections.unmodifiableList(slackEvents); }
    public List<String> getTeamsEvents() { return Collections.unmodifiableList(teamsEvents); }

    public boolean isSmtpEvent(String event)  { return smtpEvents.contains(event); }
    public boolean isSlackEvent(String event) { return slackEvents.contains(event); }
    public boolean isTeamsEvent(String event) { return teamsEvents.contains(event); }

    public String getSmtpEventsJoined()  { return String.join(",", smtpEvents); }
    public String getSlackEventsJoined() { return String.join(",", slackEvents); }
    public String getTeamsEventsJoined() { return String.join(",", teamsEvents); }

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
        cleanupDryRun       = !cleanupEnabled || json.optBoolean("cleanupDryRun", true);
        cleanupCron         = jsonStr(json, "cleanupCron",         "0 2 * * 0");
        cleanupMaxDeletions = jsonInt(json, "cleanupMaxDeletions", 50);

        // SMTP — split host:port if user pasted a combined value
        String rawHost  = jsonStr(json, "smtpHost", "");
        if (rawHost.contains(":")) {
            String[] hp = rawHost.split(":", 2);
            smtpHost = hp[0].trim();
            try { smtpPort = Integer.parseInt(hp[1].trim()); } catch (NumberFormatException ignored) { smtpPort = 587; }
        } else {
            smtpHost = rawHost;
            smtpPort = jsonInt(json, "smtpPort", 587);
        }
        smtpUsername    = jsonStr(json, "smtpUsername",    "");
        String rawPass  = jsonStr(json, "smtpPassword",    "");
        if (!rawPass.isEmpty()) smtpPassword = Secret.fromString(rawPass);
        smtpTls         = json.optBoolean("smtpTls", true);
        smtpFromAddress = jsonStr(json, "smtpFromAddress", "");
        smtpFromName    = jsonStr(json, "smtpFromName",    "Jenkins OmniAuth");
        smtpReplyTo     = jsonStr(json, "smtpReplyTo",     "");
        notifyEmails          = jsonStr(json, "notifyEmails",          "");
        loginHeading          = jsonStr(json, "loginHeading",          "");
        loginTabTitle         = jsonStr(json, "loginTabTitle",         "");
        loginAnnouncementText = jsonStr(json, "loginAnnouncementText", "");
        loginFooterText       = jsonStr(json, "loginFooterText",       "");
        loginBackground       = jsonStr(json, "loginBackground",       "omniauth");
        loginLogoPosition     = jsonStr(json, "loginLogoPosition",     "a");
        loginLogoSize         = jsonStr(json, "loginLogoSize",         "40");
        loginButler           = jsonStr(json, "loginButler",           "default");
        notificationLogoUrl   = jsonStr(json, "notificationLogoUrl",   "");
        notificationFooterNote = jsonStr(json, "notificationFooterNote", "");

        // Notifications master + channels
        notificationsEnabled = json.optBoolean("notificationsEnabled", false);
        smtpEnabled          = json.optBoolean("smtpEnabled",          false);
        slackEnabled         = json.optBoolean("slackEnabled",         false);
        slackWebhookUrl      = jsonStr(json, "slackWebhookUrl",        "");
        teamsEnabled         = json.optBoolean("teamsEnabled",         false);
        teamsWebhookUrl      = jsonStr(json, "teamsWebhookUrl",        "");

        // Brute force
        bruteForceThreshold = jsonInt(json, "bruteForceThreshold", 5);

        // Stale warning
        staleWarningEnabled    = json.optBoolean("staleWarningEnabled", false);
        staleWarningCron       = jsonStr(json, "staleWarningCron",       "0 9 * * 1");
        staleWarningWindowDays = jsonInt(json, "staleWarningWindowDays", 14);

        // Access review
        accessReviewEnabled       = json.optBoolean("accessReviewEnabled", false);
        accessReviewThresholdDays = jsonInt(json, "accessReviewThresholdDays", 90);

        // Per-channel event subscriptions
        smtpEvents  = jsonStringList(json, "smtpEvents");
        slackEvents = jsonStringList(json, "slackEvents");
        teamsEvents = jsonStringList(json, "teamsEvents");

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

    private static List<String> jsonStringList(JSONObject json, String key) {
        List<String> result = new ArrayList<>();
        Object raw = json.opt(key);
        if (raw instanceof JSONArray) {
            for (Object o : (JSONArray) raw) if (o != null) result.add(o.toString());
        } else if (raw instanceof String && !((String) raw).isEmpty()) {
            result.add(raw.toString());
        }
        return result;
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
