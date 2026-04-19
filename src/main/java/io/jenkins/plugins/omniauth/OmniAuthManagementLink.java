package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.ManagementLink;
import hudson.model.Run;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Adds "OmniAuth — Entra User Management" under Manage Jenkins → Security.
 *
 * Sub-pages (served via Stapler view forwarding):
 *   /manage/omniauth-management/           → index.jelly   (overview)
 *   /manage/omniauth-management/userStatus → userStatus.jelly
 *   /manage/omniauth-management/staleUsers → staleUsers.jelly
 *   /manage/omniauth-management/access     → access.jelly
 */
@Extension
public class OmniAuthManagementLink extends ManagementLink {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthManagementLink.class.getName());
    static final int DEFAULT_STALE_THRESHOLD_DAYS = 90;

    private static int staleThresholdDays() {
        OmniAuthGlobalConfig c = OmniAuthGlobalConfig.get();
        return c != null ? c.getStaleThresholdDays() : DEFAULT_STALE_THRESHOLD_DAYS;
    }

    private static int activeThresholdDays() {
        OmniAuthGlobalConfig c = OmniAuthGlobalConfig.get();
        return c != null ? c.getActiveThresholdDays() : 30;
    }

    // -------------------------------------------------------------------------
    // ManagementLink metadata
    // -------------------------------------------------------------------------

    @Override public String getIconFileName()    { return "symbol-people"; }
    @Override public String getDisplayName()     { return "OmniAuth Management"; }
    @Override public String getDescription()     { return "Manage users, review access, monitor security, and clean up stale accounts."; }
    @Override public String getUrlName()         { return "omniauth-management"; }
    @Override public Permission getRequiredPermission() { return Jenkins.ADMINISTER; }
    @Override public Category getCategory()      { return Category.SECURITY; }

    // -------------------------------------------------------------------------
    // Sub-page routing
    // -------------------------------------------------------------------------

    public void doUserStatus(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "userStatus.jelly").forward(req, rsp);
    }

    public void doStaleUsers(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "staleUsers.jelly").forward(req, rsp);
    }

    public void doAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "access.jelly").forward(req, rsp);
    }

    public void doSettings(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "settings.jelly").forward(req, rsp);
    }

    public void doAbout(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "about.jelly").forward(req, rsp);
    }

    public void doNotifications(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "notifications.jelly").forward(req, rsp);
    }

    public void doSessions(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        javax.servlet.http.HttpSession s = req.getSession(false);
        if (s != null) req.setAttribute("currentSessionId", s.getId());
        req.getView(this, "sessions.jelly").forward(req, rsp);
    }

    public java.util.List<ActiveSessionManager.ActiveSession> getActiveSessions() {
        return ActiveSessionManager.getAll();
    }

    @POST
    public void doClearBruteForce(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String userId = req.getParameter("userId");
        if (userId != null && !userId.isEmpty()) BruteForceTracker.clearAlert(userId);
        rsp.sendRedirect("security");
    }

    @POST
    public void doRevokeSession(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        Jenkins.get().checkPermission(Jenkins.ADMINISTER); // CSRF already enforced via @POST
        String sessionId = req.getParameter("sessionId");
        String currentSessionId = req.getSession(false) != null ? req.getSession(false).getId() : null;
        if (sessionId == null || sessionId.equals(currentSessionId)) {
            rsp.sendRedirect("sessions?error=self");
            return;
        }
        ActiveSessionManager.revoke(sessionId);
        rsp.sendRedirect("sessions?revoked=true");
    }

    public NotificationLog getNotificationLog() {
        return NotificationLog.get();
    }

    public void doNotificationLog(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "notificationLog.jelly").forward(req, rsp);
    }

    @POST
    public void doSendTestSlack(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String url = req.getParameter("slackWebhookUrl");
        String json;
        if (url == null || url.trim().isEmpty()) {
            json = "{\"ok\":false,\"msg\":\"Webhook URL is required\"}";
        } else {
            try {
                SlackHelper.test(url.trim());
                json = "{\"ok\":true,\"msg\":\"Test message sent to Slack\"}";
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
                json = "{\"ok\":false,\"msg\":\"" + escapeJson(msg) + "\"}";
            }
        }
        writeJson(rsp, json);
    }

    @POST
    public void doSendTestTeams(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String url = req.getParameter("teamsWebhookUrl");
        String json;
        if (url == null || url.trim().isEmpty()) {
            json = "{\"ok\":false,\"msg\":\"Webhook URL is required\"}";
        } else {
            try {
                TeamsHelper.test(url.trim());
                json = "{\"ok\":true,\"msg\":\"Test message sent to Teams\"}";
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
                json = "{\"ok\":false,\"msg\":\"" + escapeJson(msg) + "\"}";
            }
        }
        writeJson(rsp, json);
    }

    private static void writeJson(StaplerResponse rsp, String json) throws Exception {
        rsp.setContentType("application/json;charset=UTF-8");
        byte[] bytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        rsp.setContentLength(bytes.length);
        rsp.getOutputStream().write(bytes);
    }

    @POST
    public void doClearNotificationLog(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        NotificationLog.get().clear();
        rsp.sendRedirect("notificationLog?cleared=true");
    }

    @POST
    public void doSaveNotifications(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config != null) {
            // Snapshot full channel state BEFORE the save
            boolean masterWasOn   = config.isNotificationsEnabled();
            boolean smtpWasOn     = config.isSmtpEnabled();
            boolean slackWasOn    = config.isSlackEnabled();
            boolean teamsWasOn    = config.isTeamsEnabled();
            boolean smtpHadConfigChanged  = masterWasOn && smtpWasOn  && config.isSmtpConfigured()              && config.isSmtpEvent("configChanged");
            boolean slackHadConfigChanged = masterWasOn && slackWasOn && !config.getSlackWebhookUrl().isEmpty() && config.isSlackEvent("configChanged");
            boolean teamsHadConfigChanged = masterWasOn && teamsWasOn && !config.getTeamsWebhookUrl().isEmpty() && config.isTeamsEvent("configChanged");
            // Also snapshot whether the configChanged event was subscribed (independently of enabled state)
            boolean smtpHadEvent  = config.isSmtpEvent("configChanged");
            boolean slackHadEvent = config.isSlackEvent("configChanged");
            boolean teamsHadEvent = config.isTeamsEvent("configChanged");

            // Capture raw SMTP credentials before the save — used if SMTP gets disabled in the same operation
            final String snapHost      = config.getSmtpHost();
            final int    snapPort      = config.getSmtpPort();
            final String snapUsername  = config.getSmtpUsername();
            final String snapPassword  = config.getSmtpPassword() != null ? config.getSmtpPassword().getPlainText() : "";
            final boolean snapTls      = config.isSmtpTls();
            final String snapFromAddr  = config.getSmtpFromAddress();
            final String snapFromName  = config.getSmtpFromName() != null ? config.getSmtpFromName() : "Jenkins OmniAuth";
            final String snapReplyTo   = config.getSmtpReplyTo();
            final String snapRecipients = config.getNotifyEmails();
            final String snapSlackUrl   = config.getSlackWebhookUrl();
            final String snapTeamsUrl   = config.getTeamsWebhookUrl();
            final String snapLogoUrl    = config.getNotificationLogoUrl();

            net.sf.json.JSONObject json = new net.sf.json.JSONObject();
            // master + channels
            json.put("notificationsEnabled", req.getParameter("notificationsEnabled") != null);
            json.put("smtpEnabled",          req.getParameter("smtpEnabled")          != null);
            json.put("slackEnabled",         req.getParameter("slackEnabled")         != null);
            putParam(json, req, "slackWebhookUrl");
            json.put("teamsEnabled",         req.getParameter("teamsEnabled")         != null);
            putParam(json, req, "teamsWebhookUrl");
            // SMTP fields
            putParam(json, req, "smtpHost");
            putParam(json, req, "smtpPort");
            putParam(json, req, "smtpUsername");
            putParam(json, req, "smtpPassword");
            json.put("smtpTls", req.getParameter("smtpTls") != null);
            putParam(json, req, "smtpFromAddress");
            putParam(json, req, "smtpFromName");
            putParam(json, req, "smtpReplyTo");
            putParam(json, req, "notifyEmails");
            putParam(json, req, "notificationLogoUrl");
            // brute force
            String bft = req.getParameter("bruteForceThreshold");
            if (bft != null) json.put("bruteForceThreshold", bft.trim());
            // stale warning
            json.put("staleWarningEnabled", req.getParameter("staleWarningEnabled") != null);
            String swCron = req.getParameter("staleWarningCron");
            String swWin  = req.getParameter("staleWarningWindowDays");
            if (swCron != null) json.put("staleWarningCron",       swCron.trim());
            if (swWin  != null) json.put("staleWarningWindowDays", swWin.trim());
            // per-channel event subscriptions
            net.sf.json.JSONArray smtpEvtsArr = new net.sf.json.JSONArray();
            String[] se = req.getParameterValues("smtpEvents");
            if (se != null) for (String e : se) smtpEvtsArr.add(e);
            json.put("smtpEvents", smtpEvtsArr);
            net.sf.json.JSONArray slackEvtsArr = new net.sf.json.JSONArray();
            String[] sle = req.getParameterValues("slackEvents");
            if (sle != null) for (String e : sle) slackEvtsArr.add(e);
            json.put("slackEvents", slackEvtsArr);
            net.sf.json.JSONArray teamsEvtsArr = new net.sf.json.JSONArray();
            String[] te = req.getParameterValues("teamsEvents");
            if (te != null) for (String e : te) teamsEvtsArr.add(e);
            json.put("teamsEvents", teamsEvtsArr);
            // preserve fields managed by other forms
            net.sf.json.JSONArray arr = new net.sf.json.JSONArray();
            for (String u : config.getProtectedUsers()) arr.add(u);
            json.put("protectedUsers", arr);
            json.put("staleThresholdDays",  config.getStaleThresholdDays());
            json.put("activeThresholdDays", config.getActiveThresholdDays());
            json.put("cleanupEnabled",      config.isCleanupEnabled());
            json.put("cleanupDryRun",       config.isCleanupDryRun());
            json.put("cleanupCron",         config.getCleanupCron());
            json.put("cleanupMaxDeletions", config.getCleanupMaxDeletions());
            config.configure(req, json);

            // Fire a farewell alert on any channel that previously had configChanged enabled
            // but no longer does — using PRE-SAVE credentials so disabling SMTP/master cannot silence it.
            boolean smtpLost  = smtpHadConfigChanged  && !(config.isNotificationsEnabled() && config.isSmtpEnabled()  && config.isSmtpEvent("configChanged"));
            boolean slackLost = slackHadConfigChanged && !(config.isNotificationsEnabled() && config.isSlackEnabled() && config.isSlackEvent("configChanged"));
            boolean teamsLost = teamsHadConfigChanged && !(config.isNotificationsEnabled() && config.isTeamsEnabled() && config.isTeamsEvent("configChanged"));
            if (smtpLost || slackLost || teamsLost) {
                String changedBy = currentUserId();
                List<String> diff = new ArrayList<>();
                // Master switch
                if (masterWasOn && !config.isNotificationsEnabled())
                    diff.add("All notifications were globally disabled");
                if (smtpLost) {
                    if (!masterWasOn || config.isNotificationsEnabled()) {
                        if (smtpWasOn && !config.isSmtpEnabled())
                            diff.add("Email (SMTP) notification channel was disabled");
                        else
                            diff.add("Configuration change alerts were removed from email (SMTP)");
                    }
                }
                if (slackLost) {
                    if (!masterWasOn || config.isNotificationsEnabled()) {
                        if (slackWasOn && !config.isSlackEnabled())
                            diff.add("Slack notification channel was disabled");
                        else
                            diff.add("Configuration change alerts were removed from Slack");
                    }
                }
                if (teamsLost) {
                    if (!masterWasOn || config.isNotificationsEnabled()) {
                        if (teamsWasOn && !config.isTeamsEnabled())
                            diff.add("Microsoft Teams notification channel was disabled");
                        else
                            diff.add("Configuration change alerts were removed from Microsoft Teams");
                    }
                }
                String subject = "[Jenkins OmniAuth] Configuration change alerts have been disabled by " + changedBy;
                StringBuilder body = new StringBuilder();
                body.append("Notification Settings Change\n");
                body.append("============================\n\n");
                body.append("Changed by: ").append(changedBy).append("\n");
                body.append("When:       ").append(java.time.Instant.now()).append("\n\n");
                body.append("This is the final configuration change alert for the affected channel(s).\n");
                body.append("The following changes have disabled configuration change notifications:\n\n");
                for (String line : diff) body.append("  - ").append(line).append("\n");
                body.append("\nNo further alerts of this type will be delivered until notifications are re-enabled.\n");
                body.append(mgmtCta("Review Settings", "notifications"));
                body.append("\n---\nJenkins OmniAuth Plugin");
                final String msg = body.toString();
                // All channels use pre-save credentials and run async
                if (smtpLost && !snapRecipients.isEmpty()) {
                    Thread t = new Thread(() -> SmtpHelper.sendNow(snapHost, snapPort, snapUsername, snapPassword,
                            snapTls, snapFromAddr, snapFromName, snapReplyTo, snapRecipients, subject, msg, snapLogoUrl));
                    t.setDaemon(true); t.setName("omniauth-farewell-smtp"); t.start();
                }
                if (slackLost && !snapSlackUrl.isEmpty()) {
                    final String slackPayload = SlackHelper.buildPayload(subject, msg);
                    Thread t = new Thread(() -> { try { SlackHelper.postJson(snapSlackUrl, slackPayload); } catch (Exception e) { LOGGER.warning("Farewell Slack alert failed: " + e.getMessage()); } });
                    t.setDaemon(true); t.setName("omniauth-farewell-slack"); t.start();
                }
                if (teamsLost && !snapTeamsUrl.isEmpty()) {
                    final String teamsPayload = TeamsHelper.buildPayload(subject, msg);
                    Thread t = new Thread(() -> { try { TeamsHelper.postJson(snapTeamsUrl, teamsPayload); } catch (Exception e) { LOGGER.warning("Farewell Teams alert failed: " + e.getMessage()); } });
                    t.setDaemon(true); t.setName("omniauth-farewell-teams"); t.start();
                }
            }
            // Alert when config-change notifications are re-enabled on any channel
            boolean smtpGained  = !smtpHadConfigChanged  && config.isNotificationsEnabled() && config.isSmtpEnabled()  && config.isSmtpConfigured()              && config.isSmtpEvent("configChanged");
            boolean slackGained = !slackHadConfigChanged && config.isNotificationsEnabled() && config.isSlackEnabled() && !config.getSlackWebhookUrl().isEmpty() && config.isSlackEvent("configChanged");
            boolean teamsGained = !teamsHadConfigChanged && config.isNotificationsEnabled() && config.isTeamsEnabled() && !config.getTeamsWebhookUrl().isEmpty() && config.isTeamsEvent("configChanged");
            if (smtpGained || slackGained || teamsGained) {
                String changedBy = currentUserId();
                List<String> diff = new ArrayList<>();
                if (!masterWasOn && config.isNotificationsEnabled())
                    diff.add("All notifications were globally enabled");
                if (smtpGained) {
                    if (!smtpWasOn) diff.add("Email (SMTP) notification channel was enabled");
                    else if (!smtpHadEvent) diff.add("Configuration change alerts were added to email (SMTP)");
                }
                if (slackGained) {
                    if (!slackWasOn) diff.add("Slack notification channel was enabled");
                    else if (!slackHadEvent) diff.add("Configuration change alerts were added to Slack");
                }
                if (teamsGained) {
                    if (!teamsWasOn) diff.add("Microsoft Teams notification channel was enabled");
                    else if (!teamsHadEvent) diff.add("Configuration change alerts were added to Microsoft Teams");
                }
                String subject = "[Jenkins OmniAuth] Configuration change alerts have been enabled by " + changedBy;
                StringBuilder body = new StringBuilder();
                body.append("Notification Settings Change\n");
                body.append("============================\n\n");
                body.append("Changed by: ").append(changedBy).append("\n");
                body.append("When:       ").append(java.time.Instant.now()).append("\n\n");
                body.append("Configuration change alerts have been enabled on one or more notification channels.\n");
                body.append("All future configuration changes will be reported accordingly.\n\n");
                body.append("The following changes were applied:\n\n");
                for (String line : diff) body.append("  + ").append(line).append("\n");
                body.append(mgmtCta("Review Settings", "notifications"));
                body.append("\n---\nJenkins OmniAuth Plugin");
                // Use new config — channels are now live
                if (smtpGained)  SmtpHelper.send(config, subject, body.toString());
                if (slackGained) SlackHelper.send(config, subject, body.toString());
                if (teamsGained) TeamsHelper.send(config, subject, body.toString());
            }
        }
        rsp.sendRedirect("notifications?saved=true");
    }

    public void doProtectedUsers(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "protectedUsers.jelly").forward(req, rsp);
    }

    @POST
    public void doSaveProtectedUsers(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String[] selected = req.getParameterValues("protectedUsers");
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config != null) {
            List<String> oldProtected = new ArrayList<>(config.getProtectedUsers());

            net.sf.json.JSONObject json = new net.sf.json.JSONObject();
            if (selected != null && selected.length > 0) {
                net.sf.json.JSONArray arr = new net.sf.json.JSONArray();
                for (String s : selected) arr.add(s);
                json.put("protectedUsers", arr);
            }
            config.configure(req, json);

            List<String> newProtected = new ArrayList<>(config.getProtectedUsers());
            List<String> added   = new ArrayList<>(newProtected);
            added.removeAll(oldProtected);
            List<String> removed = new ArrayList<>(oldProtected);
            removed.removeAll(newProtected);

            NotificationService.sendProtectedListChanged(config, currentUserId(), added, removed);
        }
        rsp.sendRedirect("protectedUsers");
    }

    @POST
    public void doSaveSettings(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config != null) {
            // snapshot before
            int    oldStale          = config.getStaleThresholdDays();
            int    oldActive         = config.getActiveThresholdDays();
            boolean oldCleanupEnabled = config.isCleanupEnabled();
            boolean oldDryRun        = config.isCleanupDryRun();
            String oldCron           = config.getCleanupCron();
            int    oldMaxDel         = config.getCleanupMaxDeletions();
            int    oldBft            = config.getBruteForceThreshold();

            net.sf.json.JSONObject json = new net.sf.json.JSONObject();
            // thresholds
            String stale  = req.getParameter("staleThresholdDays");
            String active = req.getParameter("activeThresholdDays");
            if (stale  != null) json.put("staleThresholdDays",  stale.trim());
            if (active != null) json.put("activeThresholdDays", active.trim());
            // cleanup
            boolean cleanupEnabled = req.getParameter("cleanupEnabled") != null;
            json.put("cleanupEnabled", cleanupEnabled);
            boolean dryRun = !cleanupEnabled || req.getParameter("cleanupDryRun") != null;
            json.put("cleanupDryRun", dryRun);
            String cron = req.getParameter("cleanupCron");
            String maxD = req.getParameter("cleanupMaxDeletions");
            if (cron != null) json.put("cleanupCron",         cron.trim());
            if (maxD != null) json.put("cleanupMaxDeletions", maxD.trim());
            // SMTP
            putParam(json, req, "smtpHost");
            putParam(json, req, "smtpPort");
            putParam(json, req, "smtpUsername");
            putParam(json, req, "smtpPassword");
            json.put("smtpTls", req.getParameter("smtpTls") != null);
            putParam(json, req, "smtpFromAddress");
            putParam(json, req, "smtpFromName");
            putParam(json, req, "smtpReplyTo");
            putParam(json, req, "notifyEmails");
            // brute force
            String bft = req.getParameter("bruteForceThreshold");
            if (bft != null) json.put("bruteForceThreshold", bft.trim());
            // stale warning
            json.put("staleWarningEnabled", req.getParameter("staleWarningEnabled") != null);
            String swCron = req.getParameter("staleWarningCron");
            String swWin  = req.getParameter("staleWarningWindowDays");
            if (swCron != null) json.put("staleWarningCron",       swCron.trim());
            if (swWin  != null) json.put("staleWarningWindowDays", swWin.trim());
            // preserve fields managed by the Notifications page
            json.put("notificationsEnabled", config.isNotificationsEnabled());
            json.put("smtpEnabled",          config.isSmtpEnabled());
            json.put("smtpHost",             config.getSmtpHost());
            json.put("smtpPort",             config.getSmtpPort());
            json.put("smtpUsername",         config.getSmtpUsername());
            json.put("smtpTls",              config.isSmtpTls());
            json.put("smtpFromAddress",      config.getSmtpFromAddress());
            json.put("smtpFromName",         config.getSmtpFromName());
            json.put("smtpReplyTo",          config.getSmtpReplyTo());
            json.put("notifyEmails",         config.getNotifyEmails());
            json.put("slackEnabled",         config.isSlackEnabled());
            json.put("slackWebhookUrl",      config.getSlackWebhookUrl());
            json.put("teamsEnabled",         config.isTeamsEnabled());
            json.put("teamsWebhookUrl",      config.getTeamsWebhookUrl());
            json.put("bruteForceThreshold",  config.getBruteForceThreshold());
            json.put("staleWarningEnabled",    config.isStaleWarningEnabled());
            json.put("staleWarningCron",       config.getStaleWarningCron());
            json.put("staleWarningWindowDays", config.getStaleWarningWindowDays());
            net.sf.json.JSONArray smtpEvts = new net.sf.json.JSONArray();
            for (String e : config.getSmtpEvents()) smtpEvts.add(e);
            json.put("smtpEvents", smtpEvts);
            net.sf.json.JSONArray slackEvts = new net.sf.json.JSONArray();
            for (String e : config.getSlackEvents()) slackEvts.add(e);
            json.put("slackEvents", slackEvts);
            net.sf.json.JSONArray teamsEvts = new net.sf.json.JSONArray();
            for (String e : config.getTeamsEvents()) teamsEvts.add(e);
            json.put("teamsEvents", teamsEvts);
            // preserve protected users
            net.sf.json.JSONArray arr = new net.sf.json.JSONArray();
            for (String u : config.getProtectedUsers()) arr.add(u);
            json.put("protectedUsers", arr);
            config.configure(req, json);

            // diff and notify
            List<String> diff = new ArrayList<>();
            if (config.getStaleThresholdDays()  != oldStale)         diff.add("staleThresholdDays: "  + oldStale   + " → " + config.getStaleThresholdDays());
            if (config.getActiveThresholdDays() != oldActive)        diff.add("activeThresholdDays: " + oldActive  + " → " + config.getActiveThresholdDays());
            if (config.isCleanupEnabled()       != oldCleanupEnabled) diff.add("cleanupEnabled: "     + oldCleanupEnabled + " → " + config.isCleanupEnabled());
            if (config.isCleanupDryRun()        != oldDryRun)        diff.add("cleanupDryRun: "       + oldDryRun  + " → " + config.isCleanupDryRun());
            if (!config.getCleanupCron().equals(oldCron))            diff.add("cleanupCron: "         + oldCron    + " → " + config.getCleanupCron());
            if (config.getCleanupMaxDeletions() != oldMaxDel)        diff.add("cleanupMaxDeletions: " + oldMaxDel  + " → " + config.getCleanupMaxDeletions());
            if (config.getBruteForceThreshold() != oldBft)           diff.add("bruteForceThreshold: " + oldBft     + " → " + config.getBruteForceThreshold());
            if (!diff.isEmpty()) {
                NotificationService.sendConfigChanged(config, currentUserId(), java.time.Instant.now().toString(), diff);
            }
        }
        rsp.sendRedirect("settings?saved=true");
    }

    @POST
    public void doSendTestEmail(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        // Read current form values — no save needed
        OmniAuthGlobalConfig saved = OmniAuthGlobalConfig.get();

        String host     = param(req, "smtpHost",    saved != null ? saved.getSmtpHost()        : "");
        String portStr  = param(req, "smtpPort",    saved != null ? String.valueOf(saved.getSmtpPort()) : "587");
        String username = param(req, "smtpUsername",saved != null ? saved.getSmtpUsername()    : "");
        String fromAddr = param(req, "smtpFromAddress", saved != null ? saved.getSmtpFromAddress() : "");
        String fromName = param(req, "smtpFromName",saved != null ? saved.getSmtpFromName()    : "Jenkins OmniAuth");
        String replyTo  = param(req, "smtpReplyTo", saved != null ? saved.getSmtpReplyTo()     : "");
        String to       = param(req, "notifyEmails",saved != null ? saved.getNotifyEmails()    : "");
        boolean tls     = "1".equals(req.getParameter("smtpTls"));

        // Split host:port if user pasted a combined value (e.g. from Grafana config)
        if (host.contains(":")) {
            String[] parts = host.split(":", 2);
            host = parts[0].trim();
            if (portStr.isEmpty() || portStr.equals("587")) portStr = parts[1].trim();
        }

        // Password: use form value if provided, else fall back to saved
        String password = req.getParameter("smtpPassword");
        if (password == null || password.trim().isEmpty()) {
            password = (saved != null && saved.getSmtpPassword() != null)
                    ? saved.getSmtpPassword().getPlainText() : "";
        } else {
            password = password.trim(); // remove accidental trailing whitespace/newlines from paste
        }

        int port = 587;
        try { port = Integer.parseInt(portStr.trim()); } catch (NumberFormatException ignored) {}

        String json;
        if (host.isEmpty() || fromAddr.isEmpty() || username.isEmpty() || password.isEmpty()) {
            json = "{\"ok\":false,\"msg\":\"Fill in host, username, password and from address first\"}";
        } else if (to.isEmpty()) {
            json = "{\"ok\":false,\"msg\":\"Fill in at least one notification recipient\"}";
        } else {
            try {
                SmtpHelper.test(host, port, username, password, tls, fromAddr, fromName, replyTo, to);
                json = "{\"ok\":true,\"msg\":\"Test email sent to " + escapeJson(to) + "\"}";
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
                json = "{\"ok\":false,\"msg\":\"" + escapeJson(msg) + "\"}";
            }
        }

        writeJson(rsp, json);
    }

    public void doPreviewEmail(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        String logoUrl = cfg != null ? cfg.getNotificationLogoUrl() : "";
        String rootUrl = "";
        try {
            String r = Jenkins.get().getRootUrl();
            if (r != null && !r.isEmpty()) rootUrl = r.endsWith("/") ? r.substring(0, r.length() - 1) : r;
        } catch (Exception ignored) {}
        String subject = "Configuration Changed by admin";
        String body =
            "Notification Settings Change\n============================\n\n"
            + "Changed by: admin\nWhen:       " + java.time.Instant.now() + "\n\n"
            + "Settings changed:\n\n"
            + "  smtpHost: old-mail.corp.com \u2192 mail.corp.com\n"
            + "  smtpPort: 25 \u2192 587\n"
            + "  smtpTls: false \u2192 true\n"
            + "  + Brute force alerting enabled\n"
            + "  - Legacy relay removed\n"
            + (rootUrl.isEmpty() ? "" : "\nCTA: Review Settings | " + rootUrl + "/manage/omniauth-management/notifications")
            + "\n---\nJenkins OmniAuth Plugin";
        String html = SmtpHelper.buildHtml(subject, body, logoUrl);
        byte[] bytes = html.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        rsp.setContentType("text/html;charset=UTF-8");
        rsp.setContentLength(bytes.length);
        rsp.getOutputStream().write(bytes);
    }

    private static String param(StaplerRequest req, String name, String fallback) {
        String v = req.getParameter(name);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static void putParam(net.sf.json.JSONObject json, StaplerRequest req, String name) {
        String v = req.getParameter(name);
        if (v != null) json.put(name, v.trim());
    }

    private static String mgmtCta(String label, String page) {
        try {
            String r = Jenkins.get().getRootUrl();
            if (r == null || r.isEmpty()) return "";
            if (r.endsWith("/")) r = r.substring(0, r.length() - 1);
            return "\nCTA: " + label + " | " + r + "/manage/omniauth-management/" + page;
        } catch (Exception e) { return ""; }
    }

    private static String currentUserId() {
        Authentication auth = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        return (auth != null && auth.getName() != null) ? auth.getName() : "unknown";
    }

    // -------------------------------------------------------------------------
    // Settings helpers
    // -------------------------------------------------------------------------

    public OmniAuthGlobalConfig getOmniAuthGlobalConfig() {
        return OmniAuthGlobalConfig.get();
    }

    public EntraOAuthConfig getEntraConfig() {
        jenkins.model.Jenkins j = jenkins.model.Jenkins.get();
        if (j.getSecurityRealm() instanceof OmniAuthSecurityRealm) {
            return ((OmniAuthSecurityRealm) j.getSecurityRealm()).getEntraConfig();
        }
        return null;
    }

    public String getEntraRedirectUri() {
        String root = jenkins.model.Jenkins.get().getRootUrl();
        if (root == null) return "(Jenkins root URL not configured)";
        if (root.endsWith("/")) root = root.substring(0, root.length() - 1);
        return root + "/omniauth/finishLogin";
    }

    // -------------------------------------------------------------------------
    // Internal Jenkins users that must never appear in plugin user lists
    // -------------------------------------------------------------------------

    // Well-known Jenkins internal/virtual users that must never appear in plugin user lists.
    // SYSTEM  — Jenkins itself (runs internal tasks, scheduled jobs)
    // anonymous — unauthenticated visitors
    private static final java.util.Set<String> INTERNAL_USERS = new java.util.HashSet<>(
            java.util.Arrays.asList("SYSTEM", "anonymous"));

    private static boolean isInternalUser(User u) {
        return INTERNAL_USERS.contains(u.getId());
    }

    // -------------------------------------------------------------------------
    // Overview stats (used by index.jelly)
    // -------------------------------------------------------------------------

    public int getActiveSessionCount()  { return ActiveSessionManager.getAll().size(); }

    public int getFailedLoginsLast24h() {
        Instant cutoff = Instant.now().minus(1, ChronoUnit.DAYS);
        int count = 0;
        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            LoginHistoryProperty hp = user.getProperty(LoginHistoryProperty.class);
            if (hp == null) continue;
            for (LoginEvent e : hp.getEvents()) {
                try {
                    if (!e.isSuccess() && Instant.parse(e.getTimestamp()).isAfter(cutoff)) count++;
                } catch (Exception ignored) {}
            }
        }
        return count;
    }

    public void doSecurity(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        int hours = 24;
        try {
            String w = req.getParameter("window");
            if (w != null) hours = Integer.parseInt(w);
        } catch (Exception ignored) {}
        req.setAttribute("failedLogins", getFailedLogins(hours));
        req.setAttribute("windowHours", String.valueOf(hours));
        req.getView(this, "security.jelly").forward(req, rsp);
    }

    public List<FailedLoginEntry> getFailedLogins(int hours) {
        Instant cutoff = Instant.now().minus(hours, ChronoUnit.HOURS);
        List<FailedLoginEntry> result = new ArrayList<>();
        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            LoginHistoryProperty hp = user.getProperty(LoginHistoryProperty.class);
            if (hp == null) continue;
            for (LoginEvent e : hp.getEvents()) {
                try {
                    if (!e.isSuccess() && Instant.parse(e.getTimestamp()).isAfter(cutoff)) {
                        result.add(new FailedLoginEntry(user.getId(), user.getFullName(), e));
                    }
                } catch (Exception ignored) {}
            }
        }
        result.sort((a, b) -> b.event.getTimestamp().compareTo(a.event.getTimestamp()));
        return result;
    }

    public List<BruteForceEntry> getBruteForceEntries() {
        Map<String, Integer> live    = BruteForceTracker.getAllFailureCounts();
        Map<String, String>  alerted = BruteForceTracker.getAlertedUsers();
        Map<String, BruteForceEntry> merged = new HashMap<>();

        for (Map.Entry<String, Integer> e : live.entrySet()) {
            String username = e.getKey();
            User user = User.getById(username, false);
            String fullName = (user != null) ? user.getFullName() : username;
            merged.put(username, new BruteForceEntry(username, fullName, e.getValue(), null));
        }
        for (Map.Entry<String, String> e : alerted.entrySet()) {
            String username = e.getKey();
            if (!merged.containsKey(username)) {
                User user = User.getById(username, false);
                String fullName = (user != null) ? user.getFullName() : username;
                merged.put(username, new BruteForceEntry(username, fullName, 0, e.getValue()));
            } else {
                BruteForceEntry existing = merged.get(username);
                merged.put(username, new BruteForceEntry(existing.userId, existing.fullName, existing.failureCount, e.getValue()));
            }
        }
        List<BruteForceEntry> result = new ArrayList<>(merged.values());
        result.sort((a, b) -> Integer.compare(b.failureCount, a.failureCount));
        return result;
    }

    public static final class FailedLoginEntry {
        public final String userId;
        public final String fullName;
        public final LoginEvent event;
        public FailedLoginEntry(String userId, String fullName, LoginEvent event) {
            this.userId = userId; this.fullName = fullName; this.event = event;
        }
        public String getUserId()    { return userId; }
        public String getFullName()  { return fullName; }
        public LoginEvent getEvent() { return event; }
    }

    public static final class BruteForceEntry {
        public final String userId;
        public final String fullName;
        public final int failureCount;
        public final String alertedAt;
        public BruteForceEntry(String userId, String fullName, int failureCount, String alertedAt) {
            this.userId = userId; this.fullName = fullName;
            this.failureCount = failureCount; this.alertedAt = alertedAt;
        }
        public String getUserId()     { return userId; }
        public String getFullName()   { return fullName; }
        public int getFailureCount()  { return failureCount; }
        public String getAlertedAt()  { return alertedAt; }
        public boolean isAlerted()    { return alertedAt != null; }
        public String getRelativeAlertedAt() { return alertedAt != null ? relativeTime(alertedAt) : null; }
    }

    public List<RecentLoginEntry> getRecentLoginEvents() {
        List<RecentLoginEntry> all = new ArrayList<>();
        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            LoginHistoryProperty hp = user.getProperty(LoginHistoryProperty.class);
            if (hp == null) continue;
            for (LoginEvent e : hp.getEvents()) {
                all.add(new RecentLoginEntry(user.getId(), user.getFullName(), e));
            }
        }
        all.sort((a, b) -> b.event.getTimestamp().compareTo(a.event.getTimestamp()));
        return all.size() > 7 ? all.subList(0, 7) : all;
    }

    public static final class RecentLoginEntry {
        public final String userId;
        public final String fullName;
        public final LoginEvent event;
        public RecentLoginEntry(String userId, String fullName, LoginEvent event) {
            this.userId   = userId;
            this.fullName = fullName;
            this.event    = event;
        }
        public String getUserId()   { return userId; }
        public String getFullName() { return fullName; }
        public LoginEvent getEvent(){ return event; }
    }

    public int getTotalUserCount()     { return (int) User.getAll().stream().filter(u -> !isInternalUser(u)).count(); }
    public int getEntraUserCount()     { return (int) User.getAll().stream().filter(u -> !isInternalUser(u) && u.getProperty(OmniAuthUserProperty.class) != null).count(); }
    public int getLegacyUserCount()    { return getTotalUserCount() - getEntraUserCount(); }
    public int getStaleUserCount()     { return getStaleUsers(staleThresholdDays()).size(); }
    public int getProtectedUserCount() { OmniAuthGlobalConfig c = OmniAuthGlobalConfig.get(); return c == null ? 0 : c.getProtectedUsers().size(); }
    public int getActiveUserCount() {
        int threshold = activeThresholdDays();
        Instant cutoff = Instant.now().minus(threshold, ChronoUnit.DAYS);
        int count = 0;
        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
            LastLoginProperty    loginProp  = user.getProperty(LastLoginProperty.class);
            String lastLogin = resolveLastLogin(entraProp, loginProp);
            if (lastLogin != null && Instant.parse(lastLogin).isAfter(cutoff)) count++;
        }
        return count;
    }

    // -------------------------------------------------------------------------
    // User Status list (used by userStatus.jelly)
    // -------------------------------------------------------------------------

    public List<UserStatusInfo> getUserStatusList() {
        Map<String, LastJobInfo> lastJobMap = buildLastJobMap();
        List<UserStatusInfo> result = new ArrayList<>();

        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            OmniAuthUserProperty  entraProp = user.getProperty(OmniAuthUserProperty.class);
            LastLoginProperty     loginProp = user.getProperty(LastLoginProperty.class);
            LoginHistoryProperty  histProp  = user.getProperty(LoginHistoryProperty.class);

            String userType  = (entraProp != null) ? "Entra" : "Native";
            String lastLogin = resolveLastLogin(entraProp, loginProp);
            LastJobInfo lastJob = lastJobMap.get(user.getId());
            String status = deriveStatus(lastLogin, lastJob);

            UserStatusInfo info = new UserStatusInfo(
                    user.getId(),
                    user.getFullName(),
                    userType,
                    lastLogin,
                    lastJob != null ? lastJob.jobName    : null,
                    lastJob != null ? lastJob.triggeredAt : null,
                    status
            );
            if (histProp != null) info.setLatestEvent(histProp.getLatestEvent());
            result.add(info);
        }

        // Sort: active first, then by last login descending
        result.sort((a, b) -> {
            int sa = statusOrder(a.getStatus());
            int sb = statusOrder(b.getStatus());
            if (sa != sb) return Integer.compare(sa, sb);
            if (a.getLastLoginAt() == null && b.getLastLoginAt() == null) return 0;
            if (a.getLastLoginAt() == null) return 1;
            if (b.getLastLoginAt() == null) return -1;
            return b.getLastLoginAt().compareTo(a.getLastLoginAt()); // newest first
        });

        return result;
    }

    // -------------------------------------------------------------------------
    // Stale Users list (used by staleUsers.jelly)
    // -------------------------------------------------------------------------

    public List<UserInfo> getStaleUsers(int thresholdDays) {
        Instant cutoff = Instant.now().minus(thresholdDays, ChronoUnit.DAYS);
        List<UserInfo> result = new ArrayList<>();

        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
            LastLoginProperty    loginProp = user.getProperty(LastLoginProperty.class);

            String lastLogin = resolveLastLogin(entraProp, loginProp);
            boolean isStale  = (lastLogin == null) || Instant.parse(lastLogin).isBefore(cutoff);
            if (!isStale) continue;

            result.add(new UserInfo(
                    user.getId(),
                    user.getFullName(),
                    (entraProp != null) ? "Entra" : "Legacy",
                    lastLogin,
                    entraProp != null ? entraProp.getEntraObjectId() : null
            ));
        }

        result.sort((a, b) -> {
            if (a.getLastLoginAt() == null) return -1;
            if (b.getLastLoginAt() == null) return 1;
            return a.getLastLoginAt().compareTo(b.getLastLoginAt()); // oldest first
        });

        return result;
    }

    // -------------------------------------------------------------------------
    // Access detail (used by access.jelly)
    // -------------------------------------------------------------------------

    public AccessInfo getAccessInfo(StaplerRequest req) {
        String userId = req.getParameter("userId");
        if (userId == null || userId.isEmpty()) return null;

        User user = User.getById(userId, false);
        if (user == null) return null;

        OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
        String userType = (entraProp != null) ? "Entra" : "Legacy";

        // Check key permissions using ACL.as2() so the thread-local auth context is set correctly
        boolean isAdmin      = false;
        boolean canRead      = false;
        boolean canBuild     = false;
        boolean canCreate    = false;
        boolean canConfigure = false;
        try {
            Authentication auth = user.impersonate2();
            try (ACLContext ignored = ACL.as2(auth)) {
                Jenkins j = Jenkins.get();
                isAdmin      = j.hasPermission(Jenkins.ADMINISTER);
                canRead      = j.hasPermission(Jenkins.READ);
                canBuild     = j.hasPermission(Item.BUILD);
                canCreate    = j.hasPermission(Item.CREATE);
                canConfigure = j.hasPermission(Item.CONFIGURE);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not check permissions for user: " + userId, e);
        }

        // Job access — scan all jobs and check per-job permissions via impersonation
        List<JobAccessInfo> jobAccess = buildJobAccessList(userId);

        // Last login
        LastLoginProperty loginProp = user.getProperty(LastLoginProperty.class);
        String lastLogin = resolveLastLogin(entraProp, loginProp);

        // Authorization strategy name — shown in UI to help diagnose per-job permission support
        String authStrategy = Jenkins.get().getAuthorizationStrategy().getClass().getSimpleName();

        // Login history
        LoginHistoryProperty histProp = user.getProperty(LoginHistoryProperty.class);
        List<LoginEvent> loginHistory = histProp != null
                ? new ArrayList<>(histProp.getEvents()) : Collections.emptyList();

        return new AccessInfo(
                userId,
                user.getFullName(),
                userType,
                entraProp != null ? entraProp.getEntraObjectId() : null,
                entraProp != null ? entraProp.getEntraUpn() : null,
                lastLogin,
                jobAccess,
                authStrategy,
                isAdmin, canRead, canBuild, canCreate, canConfigure,
                loginHistory
        );
    }

    // -------------------------------------------------------------------------
    // POST actions
    // -------------------------------------------------------------------------

    @POST
    public void doRunCleanupNow(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config != null) {
            StaleUserCleanupWork.runCleanup(config);
        }
        rsp.sendRedirect("staleUsers?ran=true");
    }

    @POST
    public void doDeleteUser(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String userId = req.getParameter("userId");
        String from   = req.getParameter("from");
        String back   = ("userStatus".equals(from)) ? "userStatus" : "staleUsers";
        if (userId != null && !userId.isEmpty()) {
            OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
            if (config != null && config.isProtected(userId)) {
                LOGGER.warning("Deletion blocked — user is protected: " + userId);
                rsp.sendRedirect(back + "?error=protected");
                return;
            }
            User user = User.getById(userId, false);
            if (user != null) {
                String deletedBy = currentUserId();
                LOGGER.info("Manual user deletion by " + deletedBy + ": " + userId + " (from " + back + ")");
                user.delete();
                NotificationService.sendUserDeleted(config, userId, deletedBy);
            }
        }
        rsp.sendRedirect(back + "?deleted=true");
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Resolves the best available last-login timestamp for a user.
     * Prefers OmniAuthUserProperty.lastLoginAt for Entra users,
     * falls back to LastLoginProperty for all users.
     */
    private static String resolveLastLogin(OmniAuthUserProperty entraProp,
                                           LastLoginProperty loginProp) {
        if (entraProp != null && entraProp.getLastLoginAt() != null) {
            return entraProp.getLastLoginAt();
        }
        if (loginProp != null && loginProp.getLastLoginAt() != null) {
            return loginProp.getLastLoginAt();
        }
        return null;
    }

    /**
     * Scans recent builds (last 90 days) across all jobs to find the
     * most recent build triggered by each user.
     * Capped to avoid performance issues on large instances.
     */
    private static Map<String, LastJobInfo> buildLastJobMap() {
        Map<String, LastJobInfo> result = new HashMap<>();
        Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);

        try {
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                for (Run<?, ?> run : job.getBuilds()) {
                    // Builds are ordered newest first — stop when we pass the cutoff
                    if (run.getTime().toInstant().isBefore(cutoff)) break;
                    hudson.model.Cause.UserIdCause cause =
                            run.getCause(hudson.model.Cause.UserIdCause.class);
                    if (cause != null && cause.getUserId() != null) {
                        String uid = cause.getUserId();
                        if (!result.containsKey(uid)) {
                            result.put(uid, new LastJobInfo(
                                    job.getFullName(),
                                    run.getTime().toInstant().toString()
                            ));
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning build history for last job map", e);
        }

        return result;
    }

    private static final int JOB_ACCESS_CAP = 200;

    private static List<JobAccessInfo> buildJobAccessList(String userId) {
        List<JobAccessInfo> result = new ArrayList<>();
        User user = User.getById(userId, false);
        if (user == null) return result;

        Authentication auth;
        try {
            auth = user.impersonate2();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not impersonate user for job access scan: " + userId, e);
            return result;
        }

        // Fetch all jobs as admin (fast — no per-job permission overhead during iteration),
        // then check each job's permissions under the impersonated auth context.
        List<Job> allJobs = Jenkins.get().getAllItems(Job.class);

        try (ACLContext ignored = ACL.as2(auth)) {
            for (Job job : allJobs) {
                if (result.size() >= JOB_ACCESS_CAP) break;
                boolean read      = job.hasPermission(Item.READ);
                boolean build     = job.hasPermission(Item.BUILD);
                boolean configure = job.hasPermission(Item.CONFIGURE);
                if (read || build || configure) {
                    result.add(new JobAccessInfo(job.getFullName(), read, build, configure));
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning job access for user: " + userId, e);
        }

        result.sort((a, b) -> a.getJobName().compareToIgnoreCase(b.getJobName()));
        return result;
    }

    private static String deriveStatus(String lastLogin, LastJobInfo lastJob) {
        Instant activeCutoff = Instant.now().minus(activeThresholdDays(), ChronoUnit.DAYS);

        if (lastLogin != null && Instant.parse(lastLogin).isAfter(activeCutoff)) {
            return "Active";
        }
        if (lastJob != null && Instant.parse(lastJob.triggeredAt).isAfter(activeCutoff)) {
            return "Active via Jobs";
        }
        if (lastLogin == null && lastJob == null) {
            return "Never Active";
        }
        return "Inactive";
    }

    private static int statusOrder(String status) {
        switch (status) {
            case "Active":         return 0;
            case "Active via Jobs": return 1;
            case "Inactive":       return 2;
            case "Never Active":   return 3;
            default:               return 4;
        }
    }

    // -------------------------------------------------------------------------
    // Data holders
    // -------------------------------------------------------------------------

    public static final class UserStatusInfo {
        private final String userId;
        private final String fullName;
        private final String userType;
        private final String lastLoginAt;
        private final String lastJobName;
        private final String lastJobTriggeredAt;
        private final String status;

        public UserStatusInfo(String userId, String fullName, String userType,
                              String lastLoginAt, String lastJobName,
                              String lastJobTriggeredAt, String status) {
            this.userId            = userId;
            this.fullName          = fullName;
            this.userType          = userType;
            this.lastLoginAt       = lastLoginAt;
            this.lastJobName       = lastJobName;
            this.lastJobTriggeredAt = lastJobTriggeredAt;
            this.status            = status;
        }

        public String getUserId()                    { return userId; }
        public String getFullName()                  { return fullName; }
        public String getUserType()                  { return userType; }
        public String getLastLoginAt()               { return lastLoginAt; }
        public String getLastJobName()               { return lastJobName; }
        public String getLastJobTriggeredAt()        { return lastJobTriggeredAt; }
        public String getStatus()                    { return status; }
        public boolean isNeverLoggedIn()             { return lastLoginAt == null; }
        public boolean isNeverTriggered()            { return lastJobName == null; }
        public String getRelativeLastLoginAt()        { return relativeTime(lastLoginAt); }
        public String getRelativeLastJobTriggeredAt() { return relativeTime(lastJobTriggeredAt); }
        public String getFormattedLastLoginAt()       { return formatDate(lastLoginAt); }
        public String getFormattedLastJobTriggeredAt(){ return formatDate(lastJobTriggeredAt); }

        private LoginEvent latestEvent; // set externally after construction
        public void setLatestEvent(LoginEvent e) { this.latestEvent = e; }
        public LoginEvent getLatestEvent()        { return latestEvent; }
    }

    static String relativeTime(String isoStr) {
        if (isoStr == null) return null;
        try {
            long diffSec = java.time.Duration.between(Instant.parse(isoStr), Instant.now()).getSeconds();
            if (diffSec < 60)    return "just now";
            if (diffSec < 3600)  return (diffSec / 60) + "m";
            if (diffSec < 86400) return (diffSec / 3600) + "h";
            long days = diffSec / 86400;
            if (days < 30)  return days + "d";
            if (days < 365) return (days / 30) + "mo";
            return (days / 365) + "y";
        } catch (Exception e) {
            return isoStr;
        }
    }

    static String formatDate(String isoStr) {
        if (isoStr == null) return null;
        try {
            java.time.ZonedDateTime zdt = Instant.parse(isoStr)
                    .atZone(java.time.ZoneId.systemDefault());
            return String.format("%d %s %d, %02d:%02d",
                    zdt.getDayOfMonth(),
                    zdt.getMonth().getDisplayName(java.time.format.TextStyle.SHORT, java.util.Locale.ENGLISH),
                    zdt.getYear(),
                    zdt.getHour(),
                    zdt.getMinute());
        } catch (Exception e) {
            return isoStr;
        }
    }

    public static final class UserInfo {
        private final String userId;
        private final String fullName;
        private final String userType;
        private final String lastLoginAt;
        private final String entraOid;

        public UserInfo(String userId, String fullName, String userType,
                        String lastLoginAt, String entraOid) {
            this.userId      = userId;
            this.fullName    = fullName;
            this.userType    = userType;
            this.lastLoginAt = lastLoginAt;
            this.entraOid    = entraOid;
        }

        public String getUserId()      { return userId; }
        public String getFullName()    { return fullName; }
        public String getUserType()    { return userType; }
        public String getLastLoginAt() { return lastLoginAt; }
        public String getEntraOid()    { return entraOid; }
        public boolean isNeverLoggedIn() { return lastLoginAt == null; }
    }

    public static final class AccessInfo {
        private final String userId;
        private final String fullName;
        private final String userType;
        private final String entraOid;
        private final String entraUpn;
        private final String lastLoginAt;
        private final List<JobAccessInfo> jobAccess;
        private final String authStrategy;
        private final boolean isAdmin;
        private final boolean canRead;
        private final boolean canBuild;
        private final boolean canCreate;
        private final boolean canConfigure;
        private final List<LoginEvent> loginHistory;

        public AccessInfo(String userId, String fullName, String userType,
                          String entraOid, String entraUpn, String lastLoginAt,
                          List<JobAccessInfo> jobAccess, String authStrategy,
                          boolean isAdmin, boolean canRead, boolean canBuild,
                          boolean canCreate, boolean canConfigure,
                          List<LoginEvent> loginHistory) {
            this.userId        = userId;
            this.fullName      = fullName;
            this.userType      = userType;
            this.entraOid      = entraOid;
            this.entraUpn      = entraUpn;
            this.lastLoginAt   = lastLoginAt;
            this.jobAccess     = jobAccess != null ? jobAccess : Collections.emptyList();
            this.authStrategy  = authStrategy;
            this.isAdmin       = isAdmin;
            this.canRead       = canRead;
            this.canBuild      = canBuild;
            this.canCreate     = canCreate;
            this.canConfigure  = canConfigure;
            this.loginHistory  = loginHistory != null ? loginHistory : Collections.emptyList();
        }

        public String getUserId()                  { return userId; }
        public String getFullName()                { return fullName; }
        public String getUserType()                { return userType; }
        public String getEntraOid()                { return entraOid; }
        public String getEntraUpn()                { return entraUpn; }
        public String getLastLoginAt()             { return lastLoginAt; }
        public List<JobAccessInfo> getJobAccess()  { return jobAccess; }
        public String getAuthStrategy()            { return authStrategy; }
        public boolean isAdmin()                   { return isAdmin; }
        public boolean isCanRead()                 { return canRead; }
        public boolean isCanBuild()                { return canBuild; }
        public boolean isCanCreate()               { return canCreate; }
        public boolean isCanConfigure()            { return canConfigure; }
        public List<LoginEvent> getLoginHistory()  { return loginHistory; }
        public boolean isEntraUser()               { return "Entra".equals(userType); }
        public boolean isPerJobSupported() {
            return authStrategy != null && authStrategy.toLowerCase().contains("projectmatrix");
        }
    }

    public static final class JobAccessInfo {
        private final String jobName;
        private final boolean canRead;
        private final boolean canBuild;
        private final boolean canConfigure;

        public JobAccessInfo(String jobName, boolean canRead, boolean canBuild, boolean canConfigure) {
            this.jobName      = jobName;
            this.canRead      = canRead;
            this.canBuild     = canBuild;
            this.canConfigure = canConfigure;
        }

        public String getJobName()      { return jobName; }
        public boolean isCanRead()      { return canRead; }
        public boolean isCanBuild()     { return canBuild; }
        public boolean isCanConfigure() { return canConfigure; }
    }

    private static final class LastJobInfo {
        final String jobName;
        final String triggeredAt;
        LastJobInfo(String jobName, String triggeredAt) {
            this.jobName     = jobName;
            this.triggeredAt = triggeredAt;
        }
    }
}
