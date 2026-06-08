package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Job;
import hudson.model.ManagementLink;
import hudson.model.Run;
import hudson.model.User;
import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
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

    @Override public String getIconFileName()    { return "/plugin/omni-auth/images/icon.svg"; }
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

    public void doUserOverview(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "access.jelly").forward(req, rsp);
    }

    public void doAccessManagement(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "accessManagement.jelly").forward(req, rsp);
    }

    public void doAccessReview(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "accessReview.jelly").forward(req, rsp);
    }

    public void doJitRequests(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "jitRequests.jelly").forward(req, rsp);
    }

    public void doAuditLog(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "auditLog.jelly").forward(req, rsp);
    }

    public List<Map<String, String>> getAuditEvents() {
        OmniAuthAuditLog log = OmniAuthAuditLog.get();
        return log != null ? log.readRecent(200) : Collections.emptyList();
    }

    @POST
    public void doPurgeAuditLog(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String password = req.getParameter("confirmPassword");
        String currentUser = Jenkins.getAuthentication2().getName();

        // Verify password via security realm
        try {
            Jenkins.get().getSecurityRealm().getSecurityComponents().manager2
                    .authenticate(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(currentUser, password));
        } catch (Exception e) {
            LoginContextFilter.FRESH_LOGINS.remove("__failed__" + currentUser);
            rsp.setContentType("application/json");
            rsp.getWriter().write("{\"error\":\"wrongPassword\"}");
            return;
        }
        // Suppress the login event that manager2.authenticate() fires — this is a password
        // verification, not a real login, so it should not appear in the audit log
        LoginContextFilter.FRESH_LOGINS.remove(currentUser);

        OmniAuthAuditLog log = OmniAuthAuditLog.get();
        if (log != null) log.purgeAll();
        rsp.setContentType("application/json");
        rsp.getWriter().write("{\"ok\":true}");
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

    public OmniAuthUserProperty getCurrentUserBreakGlassProp() {
        User current = User.current();
        if (current == null) return null;
        return current.getProperty(OmniAuthUserProperty.class);
    }

    public void doBreakGlass(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "breakglass.jelly").forward(req, rsp);
    }

    @POST
    public void doBreakGlassEnrollInit(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");

        byte[] secretBytes = new byte[20];
        new java.security.SecureRandom().nextBytes(secretBytes);
        String secret = org.jboss.aerogear.security.otp.api.Base32.encode(secretBytes);

        User currentUser = User.current();
        String userId = currentUser != null ? currentUser.getId() : "unknown";

        // Account label: prefer Entra UPN (their corporate email), fallback to Jenkins username
        OmniAuthUserProperty bgProp = currentUser != null ? currentUser.getProperty(OmniAuthUserProperty.class) : null;
        String account = (bgProp != null && bgProp.getEntraUpn() != null && !bgProp.getEntraUpn().isEmpty())
                ? bgProp.getEntraUpn() : userId;

        // Issuer: "Jenkins (hostname) OA" — fits on mobile, identifies instance, hints OmniAuth
        String rootUrl = Jenkins.get().getRootUrl();
        String host = "jenkins";
        if (rootUrl != null) {
            try { host = new java.net.URL(rootUrl).getHost(); } catch (Exception ignored) {}
        }
        String issuer = "Jenkins (" + host + ") OA";

        String issuerEnc  = java.net.URLEncoder.encode(issuer,  "UTF-8").replace("+", "%20");
        String accountEnc = java.net.URLEncoder.encode(account, "UTF-8").replace("+", "%20");
        String uri = "otpauth://totp/" + issuerEnc + "%3A" + accountEnc
                   + "?secret=" + secret + "&issuer=" + issuerEnc;

        com.google.zxing.qrcode.QRCodeWriter writer = new com.google.zxing.qrcode.QRCodeWriter();
        com.google.zxing.common.BitMatrix matrix = writer.encode(uri, com.google.zxing.BarcodeFormat.QR_CODE, 220, 220);
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        com.google.zxing.client.j2se.MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
        String qr = java.util.Base64.getEncoder().encodeToString(baos.toByteArray());

        String escaped = secret.replace("\\", "\\\\").replace("\"", "\\\"");
        rsp.getWriter().write("{\"secret\":\"" + escaped + "\",\"qr\":\"data:image/png;base64," + qr + "\"}");
    }

    @POST
    public void doBreakGlassEnrollVerify(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");

        String secret     = req.getParameter("secret");
        String code       = req.getParameter("code");
        String deviceName = req.getParameter("deviceName");
        if (secret == null || secret.isBlank() || code == null || code.trim().length() != 6) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Invalid request.\"}");
            return;
        }
        if (deviceName == null || deviceName.isBlank()) deviceName = "My Device";
        try {
            if (!new org.jboss.aerogear.security.otp.Totp(secret.trim()).verify(code.trim())) {
                rsp.getWriter().write("{\"success\":false,\"error\":\"Code is incorrect. Check your app and try again.\"}");
                return;
            }
        } catch (Exception ex) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Invalid secret format.\"}");
            return;
        }
        User current = User.current();
        if (current == null) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Not authenticated.\"}");
            return;
        }
        OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
        if (prop == null) {
            prop = new OmniAuthUserProperty(null, null);
            current.addProperty(prop);
        }
        if (!prop.addBreakGlassDevice(deviceName.trim(), secret.trim())) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Maximum of 3 devices reached. Remove one before adding another.\"}");
            return;
        }
        current.save();
        OmniAuthAuditLog.get().logBreakGlassEnrolled(current.getId());
        rsp.getWriter().write("{\"success\":true}");
    }

    @POST
    public void doBreakGlassEnrollRemove(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");
        String deviceId = req.getParameter("deviceId");
        User current = User.current();
        if (current != null && deviceId != null) {
            OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
            if (prop != null) {
                prop.removeBreakGlassDevice(deviceId);
                current.save();
                OmniAuthAuditLog.get().logBreakGlassUnenrolled(current.getId());
            }
        }
        rsp.getWriter().write("{\"success\":true}");
    }

    @POST
    public void doBreakGlassActivate(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");

        String reason = req.getParameter("reason");
        String totpCode = req.getParameter("totpCode");

        if (reason == null || reason.trim().isEmpty()) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Reason is required.\"}");
            return;
        }
        if (totpCode == null || totpCode.trim().length() != 6) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Enter the 6-digit TOTP code.\"}");
            return;
        }

        User current = User.current();
        if (current == null) {
            rsp.getWriter().write("{\"success\":false,\"error\":\"Not authenticated.\"}");
            return;
        }
        String userId = current.getId();

        OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
        if (prop == null || !prop.isBreakGlassTotpEnrolled()) {
            OmniAuthAuditLog.get().logBreakGlassFailed(userId, "No TOTP enrolled");
            rsp.getWriter().write("{\"success\":false,\"error\":\"No TOTP enrolled. Configure Break Glass in OmniAuth → Break Glass.\"}");
            return;
        }

        if (!prop.verifyBreakGlassCode(totpCode.trim())) {
            OmniAuthAuditLog.get().logBreakGlassFailed(userId, "Invalid TOTP code");
            rsp.getWriter().write("{\"success\":false,\"error\":\"Invalid TOTP code. Try again.\"}");
            return;
        }

        long expiry = System.currentTimeMillis() + 15L * 60 * 1000;
        req.getSession().setAttribute("omniauth.breakGlass.expiry", expiry);
        req.getSession().setAttribute("omniauth.breakGlass.user", userId);
        req.getSession().setAttribute("omniauth.breakGlass.reason", reason.trim());

        OmniAuthAuditLog.get().logBreakGlassActivate(userId, reason.trim());
        rsp.getWriter().write("{\"success\":true}");
    }

    @POST
    public void doBreakGlassDeactivate(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");

        req.getSession().removeAttribute("omniauth.breakGlass.expiry");
        req.getSession().removeAttribute("omniauth.breakGlass.user");
        req.getSession().removeAttribute("omniauth.breakGlass.reason");

        User current = User.current();
        String userId = current != null ? current.getId() : "unknown";
        OmniAuthAuditLog.get().logBreakGlassDeactivate(userId);
        rsp.getWriter().write("{\"success\":true}");
    }

    public void doTotpReminder(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "totpReminder.jelly").forward(req, rsp);
    }

    @POST
    public void doTotpReminderSkip(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/json;charset=UTF-8");
        User current = User.current();
        if (current != null) {
            OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
            if (prop == null) {
                prop = new OmniAuthUserProperty(null, null);
                current.addProperty(prop);
            }
            if (prop.getBreakGlassEnrollSkips() < 3) {
                prop.setBreakGlassEnrollSkips(prop.getBreakGlassEnrollSkips() + 1);
                current.save();
            }
        }
        req.getSession().setAttribute("omniauth.totp.reminderDoneThisSession", Boolean.TRUE);
        String returnTo = (String) req.getSession().getAttribute("omniauth.totp.returnTo");
        req.getSession().removeAttribute("omniauth.totp.returnTo");
        String redirect = (returnTo != null && !returnTo.isEmpty()) ? returnTo : req.getContextPath() + "/";
        rsp.getWriter().write("{\"success\":true,\"redirect\":\"" + redirect.replace("\"", "\\\"") + "\"}");
    }

    public int getCurrentUserEnrollSkips() {
        User current = User.current();
        if (current == null) return 0;
        OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
        return prop != null ? prop.getBreakGlassEnrollSkips() : 0;
    }

    public boolean isBreakGlassEnrollmentForced() { return getCurrentUserEnrollSkips() >= 3; }
    public int getBreakGlassSkipsAfterThis() { return Math.max(0, 2 - getCurrentUserEnrollSkips()); }

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
            // preserve login branding (managed by Settings page)
            json.put("loginHeading",          config.getLoginHeading());
            json.put("loginTabTitle",         config.getLoginTabTitle());
            json.put("loginAnnouncementText", config.getLoginAnnouncementText());
            json.put("loginFooterText",       config.getLoginFooterText());
            json.put("loginBackground",       config.getLoginBackground());
            putParam(json, req, "notificationFooterNote");
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
                // Use new config — channels are now live; respect master toggle
                if (config.isNotificationsEnabled()) {
                    if (smtpGained)  SmtpHelper.send(config, subject, body.toString());
                    if (slackGained) SlackHelper.send(config, subject, body.toString());
                    if (teamsGained) TeamsHelper.send(config, subject, body.toString());
                }
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
            // access review
            json.put("accessReviewEnabled", req.getParameter("accessReviewEnabled") != null);
            String arDays = req.getParameter("accessReviewThresholdDays");
            if (arDays != null) json.put("accessReviewThresholdDays", arDays.trim());
            // login page branding (managed by this page)
            String lh  = req.getParameter("loginHeading");
            String ltt = req.getParameter("loginTabTitle");
            String lat = req.getParameter("loginAnnouncementText");
            String lft = req.getParameter("loginFooterText");
            String lbg = req.getParameter("loginBackground");
            if (lh  != null) json.put("loginHeading",          lh.trim());
            if (ltt != null) json.put("loginTabTitle",          ltt.trim());
            if (lat != null) json.put("loginAnnouncementText", lat.trim());
            if (lft != null) json.put("loginFooterText",       lft.trim());
            if (lbg != null) json.put("loginBackground",       lbg.trim());
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
        String eventType = param(req, "eventType", "configChanged");
        String logoOverride     = param(req, "logoUrl",     "");
        String footerNoteOverride = req.getParameter("footerNote"); // null = not sent, "" = cleared
        String html = buildPreviewHtml(cfg, eventType, logoOverride, footerNoteOverride);
        byte[] bytes = html.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        rsp.setContentType("text/html;charset=UTF-8");
        rsp.setContentLength(bytes.length);
        rsp.getOutputStream().write(bytes);
    }

    private static String buildPreviewHtml(OmniAuthGlobalConfig cfg, String eventType,
                                            String logoOverride, String footerNoteOverride) {
        String now = java.time.Instant.now().toString();
        String html;
        switch (eventType) {
            case "bruteForce":
                html = SmtpHelper.buildBruteForceHtml(cfg, "john.doe@corp.com", 8); break;
            case "userDeleted":
                html = SmtpHelper.buildUserDeletedHtml(cfg, "alice.smith", "admin"); break;
            case "cleanup": {
                OmniAuthGlobalConfig.CleanupRunRecord rec = new OmniAuthGlobalConfig.CleanupRunRecord(
                    now, false, 142, 3, 5,
                    java.util.Arrays.asList("inactive.user1", "old.contractor", "ex.employee99"));
                html = SmtpHelper.buildCleanupReportHtml(cfg, rec); break;
            }
            case "adminGranted":
                html = SmtpHelper.buildAdminGrantedHtml(cfg,
                    java.util.Arrays.asList("bob.jones", "carol.dev"), "admin"); break;
            case "staleWarning":
                html = SmtpHelper.buildStaleWarningHtml(cfg,
                    java.util.Arrays.asList("dave.legacy", "eve.contractor", "frank.temp"), 7, 90); break;
            case "protectedListChanged":
                html = SmtpHelper.buildProtectedListChangedHtml(cfg, "admin",
                    java.util.Arrays.asList("alice.smith"),
                    java.util.Arrays.asList("old.vendor")); break;
            case "accessReview": {
                OmniAuthAssignment a1 = new OmniAuthAssignment("alice.smith", "USER", "developer",
                        "platform/payments-api", "JOB",
                        java.util.Collections.emptyList(),
                        java.time.Instant.now().minus(95, java.time.temporal.ChronoUnit.DAYS).toString(), "admin");
                OmniAuthAssignment a2 = new OmniAuthAssignment("bob.jones", "USER", "admin",
                        "", "GLOBAL",
                        java.util.Collections.emptyList(),
                        java.time.Instant.now().minus(120, java.time.temporal.ChronoUnit.DAYS).toString(), "admin");
                OmniAuthAssignment a3 = new OmniAuthAssignment("contractors", "GROUP", "read-only",
                        "platform", "FOLDER",
                        java.util.Collections.emptyList(),
                        java.time.Instant.now().minus(200, java.time.temporal.ChronoUnit.DAYS).toString(), "admin");
                html = SmtpHelper.buildAccessReviewHtml(cfg,
                        java.util.Arrays.asList(a1, a2, a3),
                        cfg != null ? cfg.getAccessReviewThresholdDays() : 90);
                break;
            }
            case "graphApiFailure":
                html = SmtpHelper.buildGraphApiFailedHtml(cfg, "john.doe@corp.com",
                    "403 Forbidden: Insufficient privileges to complete the operation."); break;
            case "smtpTest": {
                String host = cfg != null ? cfg.getSmtpHost()        : "mail.corp.com";
                int port    = cfg != null ? cfg.getSmtpPort()        : 587;
                String from = cfg != null ? cfg.getSmtpFromAddress() : "jenkins@corp.com";
                String to   = cfg != null ? cfg.getNotifyEmails()    : "admin@corp.com";
                html = SmtpHelper.buildSmtpTestHtml(host, port, from, to); break;
            }
            default: // configChanged
                html = SmtpHelper.buildConfigChangedHtml(cfg, "admin", now,
                    java.util.Arrays.asList(
                        "smtpHost: old-mail.corp.com \u2192 mail.corp.com",
                        "smtpPort: 25 \u2192 587",
                        "smtpTls: false \u2192 true",
                        "staleThresholdDays: 60 \u2192 90"));
        }
        if (!logoOverride.isEmpty()) {
            String savedLogo = (cfg != null && cfg.getNotificationLogoUrl() != null
                                && !cfg.getNotificationLogoUrl().trim().isEmpty())
                ? cfg.getNotificationLogoUrl().trim()
                : SmtpHelper.LOGO_DEFAULT;
            html = html.replace("src='" + savedLogo + "'", "src='" + logoOverride + "'");
        }
        if (footerNoteOverride != null) {
            // Splice the live footer note between the separator line and the fine-print div.
            String sep      = "<div style='height:1px;background:#e8edf3;margin:12px 0;'></div>";
            String finePrint = "<div style='font-size:10.5px;color:#b0bac7;line-height:1.7;text-align:center;'>";
            int sepIdx = html.indexOf(sep);
            int fpIdx  = html.indexOf(finePrint);
            if (sepIdx >= 0 && fpIdx > sepIdx) {
                String escaped = footerNoteOverride.trim()
                    .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
                String noteHtml = escaped.isEmpty() ? ""
                    : "<div style='font-size:11px;color:#64748b;line-height:1.6;"
                      + "text-align:center;margin-bottom:8px;'>" + escaped + "</div>";
                html = html.substring(0, sepIdx + sep.length()) + noteHtml + html.substring(fpIdx);
            }
        }
        return html;
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

    public boolean isLoginLogoUploaded() {
        java.io.File dir = new java.io.File(Jenkins.get().getRootDir(), "omniauth-branding");
        java.io.File[] files = dir.listFiles(f -> f.getName().startsWith("login-logo."));
        return files != null && files.length > 0;
    }

    public String getLoginLogoPreviewUrl() {
        java.io.File dir = new java.io.File(Jenkins.get().getRootDir(), "omniauth-branding");
        java.io.File[] files = dir.listFiles(f -> f.getName().startsWith("login-logo."));
        if (files == null || files.length == 0) return "";
        String root = Jenkins.get().getRootUrl();
        if (root == null) return "";
        if (root.endsWith("/")) root = root.substring(0, root.length() - 1);
        // Cache-bust by last-modified so a freshly uploaded logo shows immediately.
        return root + "/securityRealm/loginLogo?v=" + files[0].lastModified();
    }

    @POST
    public void doUploadLoginLogo(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        org.apache.commons.fileupload.FileItem fileItem = req.getFileItem("loginLogo");
        if (fileItem == null || fileItem.getSize() == 0) {
            writeJson(rsp, "{\"ok\":false,\"msg\":\"No file received.\"}");
            return;
        }
        String originalName = fileItem.getName();
        String ext = "";
        if (originalName != null) {
            int dot = originalName.lastIndexOf('.');
            if (dot >= 0) ext = originalName.substring(dot + 1).toLowerCase().trim();
        }
        java.util.Set<String> allowed = new java.util.HashSet<>(
                java.util.Arrays.asList("png", "jpg", "jpeg", "svg", "gif", "webp", "ico"));
        if (!allowed.contains(ext)) {
            writeJson(rsp, "{\"ok\":false,\"msg\":\"Unsupported file type. Use PNG, JPG, SVG, GIF, or WebP.\"}");
            return;
        }
        if (fileItem.getSize() > 2 * 1024 * 1024) {
            writeJson(rsp, "{\"ok\":false,\"msg\":\"File too large. Maximum 2 MB.\"}");
            return;
        }
        java.io.File brandingDir = new java.io.File(Jenkins.get().getRootDir(), "omniauth-branding");
        brandingDir.mkdirs();
        java.io.File[] existing = brandingDir.listFiles(f -> f.getName().startsWith("login-logo."));
        if (existing != null) for (java.io.File f : existing) f.delete();
        java.io.File dest = new java.io.File(brandingDir, "login-logo." + ext);
        try { fileItem.write(dest); } catch (Exception e) {
            writeJson(rsp, "{\"ok\":false,\"msg\":\"Failed to save file: " + escapeJson(e.getMessage()) + "\"}");
            return;
        }
        writeJson(rsp, "{\"ok\":true,\"msg\":\"Logo uploaded.\"}");
    }

    @POST
    public void doRemoveLoginLogo(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        java.io.File dir = new java.io.File(Jenkins.get().getRootDir(), "omniauth-branding");
        java.io.File[] files = dir.listFiles(f -> f.getName().startsWith("login-logo."));
        if (files != null) for (java.io.File f : files) f.delete();
        writeJson(rsp, "{\"ok\":true}");
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

    /** Returns true if the user has global Administer access via any source (OmniAuth or Jenkins-native). */
    public boolean isUserGlobalAdmin(String sid) {
        if (sid == null || sid.isEmpty()) return false;
        try {
            User u = User.getById(sid, false);
            if (u == null) return false;
            Authentication auth = u.impersonate2();
            try (ACLContext ignored = ACL.as2(auth)) {
                return Jenkins.get().hasPermission(Jenkins.ADMINISTER);
            }
        } catch (Exception ignored) {}
        return false;
    }


    // -------------------------------------------------------------------------
    // Overview stats (used by index.jelly)
    // -------------------------------------------------------------------------

    public int getActiveSessionCount()  { return ActiveSessionManager.getAll().size(); }

    // Break Glass live state — reads from current HTTP session
    public boolean isBreakGlassActive() {
        try {
            org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (req == null) return false;
            jakarta.servlet.http.HttpSession sess = req.getSession(false);
            if (sess == null) return false;
            String expiry = (String) sess.getAttribute("omniauth.breakGlass.expiry");
            return expiry != null && java.time.Instant.parse(expiry).isAfter(java.time.Instant.now());
        } catch (Exception e) { return false; }
    }

    public String getBreakGlassActivatedBy() {
        try {
            org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (req == null) return null;
            jakarta.servlet.http.HttpSession sess = req.getSession(false);
            return sess != null ? (String) sess.getAttribute("omniauth.breakGlass.user") : null;
        } catch (Exception e) { return null; }
    }

    public String getBreakGlassExpiresAt() {
        try {
            org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
            if (req == null) return null;
            jakarta.servlet.http.HttpSession sess = req.getSession(false);
            return sess != null ? (String) sess.getAttribute("omniauth.breakGlass.expiry") : null;
        } catch (Exception e) { return null; }
    }

    // 7-day login failure trend for chart
    public String getLoginFailureTrendJson() {
        OmniAuthAuditLog log = OmniAuthAuditLog.get();
        int[] counts = (log != null) ? log.getFailureCountsByDay(7) : new int[7];
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < counts.length; i++) { if (i > 0) sb.append(","); sb.append(counts[i]); }
        return sb.append("]").toString();
    }

    // Recent audit events for overview feed
    public List<java.util.Map<String, String>> getRecentAuditEntries() {
        OmniAuthAuditLog log = OmniAuthAuditLog.get();
        return log != null ? log.readRecent(8) : java.util.Collections.emptyList();
    }

    // Count of admins who have at least one Break Glass TOTP device enrolled
    public int getBreakGlassEnrolledAdminCount() {
        int count = 0;
        for (User user : User.getAll()) {
            OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
            if (prop != null && prop.isBreakGlassTotpEnrolled()) count++;
        }
        return count;
    }

    // Users flagged for deletion
    public int getPendingReviewCount() {
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (cfg == null || !cfg.isAccessReviewEnabled()) return 0;
        OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
        if (ac == null) return 0;
        int threshold = cfg.getAccessReviewThresholdDays();
        int count = 0;
        for (OmniAuthAssignment a : ac.getAssignments()) {
            if (a.isReviewDue(threshold)) count++;
        }
        return count;
    }

    public List<PendingReviewItem> getPendingReviewItems() {
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (cfg == null || !cfg.isAccessReviewEnabled()) return Collections.emptyList();
        OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
        if (ac == null) return Collections.emptyList();
        int threshold = cfg.getAccessReviewThresholdDays();
        List<PendingReviewItem> items = new ArrayList<>();
        for (OmniAuthAssignment a : ac.getAssignments()) {
            if (!a.isReviewDue(threshold)) continue;
            String displayName = resolveDisplayName(a.getUserId(),
                    "GROUP".equalsIgnoreCase(a.getAuthType()) ? AuthorizationType.GROUP : AuthorizationType.USER);
            String baseline = (a.getReviewedAt() != null && !a.getReviewedAt().isBlank())
                    ? a.getReviewedAt()
                    : (a.getGrantedAt() != null && !a.getGrantedAt().isBlank() ? a.getGrantedAt() : null);
            long daysAgo = -1; // -1 = unknown grant date
            if (baseline != null) {
                try { daysAgo = java.time.temporal.ChronoUnit.DAYS.between(java.time.Instant.parse(baseline), java.time.Instant.now()); } catch (Exception ignored) {}
            }
            String scope = a.getScope();
            String displayScope = (scope == null || scope.isBlank()) ? "Global" : scope;
            items.add(new PendingReviewItem(a.getUserId(), displayName, a.getAuthType(), a.getRoleId(),
                    scope, displayScope, a.getScopeType(), (int) daysAgo,
                    a.getReviewedAt() != null && !a.getReviewedAt().isBlank()));
        }
        items.sort((x, y) -> Integer.compare(y.getDaysAgo(), x.getDaysAgo()));
        return items;
    }

    // ── JIT: getters ────────────────────────────────────────────────────────

    public int getPendingJitCount() {
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        return store == null ? 0 : store.getPendingCount();
    }

    public List<OmniAuthJitRequest> getPendingJitRequests() {
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        return store == null ? Collections.emptyList() : store.getPendingRequests();
    }

    public List<OmniAuthJitRequest> getRecentJitRequests() {
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        return store == null ? Collections.emptyList() : store.getRecentRequests(50);
    }

    // ── JIT: admin actions ───────────────────────────────────────────────────

    @POST
    public void doApproveJit(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String requestId = req.getParameter("requestId");
        if (requestId == null || requestId.isBlank()) { rsp.sendRedirect("jitRequests"); return; }
        String approver = Jenkins.getAuthentication2().getName();
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        OmniAuthJitRequest jitReq = store != null ? store.findById(requestId) : null;
        if (jitReq == null) { rsp.sendRedirect("jitRequests"); return; }

        boolean wentActive = store.approveAsApprover(requestId, approver);
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (wentActive) {
            if (audit != null) audit.logJitApproved(approver, jitReq.getRequesterId(),
                    jitReq.getScope(), jitReq.getRequestedDurationHours());
            NotificationService.sendJitApproved(cfg, jitReq);
            rsp.sendRedirect("jitRequests?approved=true");
        } else {
            rsp.sendRedirect("jitRequests?partialApproved=true");
        }
    }

    @POST
    public void doDenyJit(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String requestId = req.getParameter("requestId");
        String comment   = req.getParameter("comment");
        if (requestId == null || requestId.isBlank()) { rsp.sendRedirect("jitRequests"); return; }
        String approver = Jenkins.getAuthentication2().getName();
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        OmniAuthJitRequest jitReq = store != null ? store.findById(requestId) : null;
        if (jitReq == null) { rsp.sendRedirect("jitRequests"); return; }

        if (store.denyAsApprover(requestId, approver, comment)) {
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logJitDenied(approver, jitReq.getRequesterId(),
                    jitReq.getScope(), comment);
            OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
            NotificationService.sendJitDenied(cfg, jitReq);
        }
        rsp.sendRedirect("jitRequests?denied=true");
    }

    public String getCurrentUserId() {
        try { return Jenkins.getAuthentication2().getName(); } catch (Exception e) { return ""; }
    }

    @POST
    public void doRevokeActiveJit(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String requestId = req.getParameter("requestId");
        if (requestId == null || requestId.isBlank()) { rsp.sendRedirect("jitRequests"); return; }
        String revokedBy = Jenkins.getAuthentication2().getName();
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        OmniAuthJitRequest jitReq = store != null ? store.findById(requestId) : null;
        if (jitReq != null && store.revoke(requestId, revokedBy)) {
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logJitRevoked(revokedBy, jitReq.getRequesterId(), jitReq.getScope());
        }
        rsp.sendRedirect("jitRequests?revoked=true");
    }

    public int getPendingDeletionCount() {
        int count = 0;
        for (User user : User.getAll()) {
            OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
            if (prop != null && prop.isPendingDeletion()) count++;
        }
        return count;
    }

    // VIA_ENTRA_GROUP users whose group is no longer in Access Management (not yet flagged for deletion)
    public int getOrphanedGroupAccountCount() {
        int count = 0;
        for (User user : User.getAll()) {
            OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
            if (prop == null || !prop.isViaGroup() || prop.isPendingDeletion()) continue;
            if (prop.getActiveGroupOids().isEmpty()) count++;
        }
        return count;
    }

    // Names of notification channels that are enabled but whose last send failed
    public List<String> getFailingNotificationChannels() {
        NotificationLog log = NotificationLog.get();
        if (log == null) return java.util.Collections.emptyList();
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (cfg == null) return java.util.Collections.emptyList();
        List<String> failing = new ArrayList<>();
        if (cfg.isSmtpEnabled())  { var e = log.lastSmtpEntry();  if (e != null && !e.isSuccess()) failing.add("Email"); }
        if (cfg.isSlackEnabled()) { var e = log.lastSlackEntry(); if (e != null && !e.isSuccess()) failing.add("Slack"); }
        if (cfg.isTeamsEnabled()) { var e = log.lastTeamsEntry(); if (e != null && !e.isSuccess()) failing.add("Teams"); }
        return failing;
    }

    // Users with a global ADMIN role assignment but no TOTP enrolled
    public int getUnenrolledAdminCount() {
        OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
        if (ac == null) return 0;
        java.util.Set<String> adminUserIds = new java.util.HashSet<>();
        for (OmniAuthAssignment a : ac.getAssignments()) {
            if ("USER".equals(a.getAuthType())
                    && (a.getScope() == null || a.getScope().isEmpty())
                    && "ADMIN".equalsIgnoreCase(a.getRoleId())) {
                adminUserIds.add(a.getUserId());
            }
        }
        int count = 0;
        for (String uid : adminUserIds) {
            User user = User.getById(uid, false);
            if (user == null) continue;
            OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
            if (prop == null || !prop.isBreakGlassTotpEnrolled()) count++;
        }
        return count;
    }

    // Access grants expiring within the next N days
    public static final class ExpiringGrant {
        public final String userId;
        public final String roleId;
        public final String scope;
        public final String expiresAt;
        public final long daysLeft;
        public ExpiringGrant(String userId, String roleId, String scope, String expiresAt, long daysLeft) {
            this.userId = userId; this.roleId = roleId; this.scope = scope;
            this.expiresAt = expiresAt; this.daysLeft = daysLeft;
        }
        public String getUserId()   { return userId; }
        public String getRoleId()   { return roleId; }
        public String getScope()    { return scope == null || scope.isEmpty() ? "Global" : scope; }
        public String getExpiresAt(){ return expiresAt; }
        public long getDaysLeft()   { return daysLeft; }
    }

    public List<ExpiringGrant> getExpiringGrants(int withinDays) {
        OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
        if (ac == null) return java.util.Collections.emptyList();
        java.time.Instant now  = java.time.Instant.now();
        java.time.Instant cutoff = now.plus(withinDays, ChronoUnit.DAYS);
        List<ExpiringGrant> result = new ArrayList<>();
        for (OmniAuthAssignment a : ac.getAssignments()) {
            if (a.getExpiresAt() == null || a.getExpiresAt().isBlank()) continue;
            try {
                java.time.Instant exp = java.time.Instant.parse(a.getExpiresAt());
                if (exp.isAfter(now) && exp.isBefore(cutoff)) {
                    long days = ChronoUnit.DAYS.between(now, exp);
                    result.add(new ExpiringGrant(a.getUserId(), a.getRoleId(), a.getScope(), a.getExpiresAt(), days));
                }
            } catch (Exception ignored) {}
        }
        result.sort((a, b) -> Long.compare(a.daysLeft, b.daysLeft));
        return result;
    }

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

    /** Returns true if this user is VIA_ENTRA_GROUP and at least one of their groups is still active in Access Management. */
    public boolean isActiveGroupUser(String userId) {
        User user = User.getById(userId, false);
        if (user == null) return false;
        OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
        if (prop == null || !prop.isViaGroup()) return false;
        OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
        if (assignmentConfig == null) return false;
        for (String oid : prop.getActiveGroupOids()) {
            if (assignmentConfig.hasGroup(oid)) return true;
        }
        return false;
    }
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

            // Extended fields
            if (entraProp != null) {
                info.setProvisioningSource(entraProp.getProvisioningSource());
                info.setEntraUpn(entraProp.getEntraUpn());
                if (entraProp.isViaGroup()) {
                    OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
                    boolean foundActive = false;
                    if (assignmentConfig != null) {
                        for (String oid : entraProp.getActiveGroupOids()) {
                            if (assignmentConfig.hasGroup(oid)) {
                                info.setActiveGroupUser(true);
                                info.setGroupOid(oid);
                                OmniAuthGroupEntity groupEntity = assignmentConfig.findGroup(oid);
                                if (groupEntity != null) info.setGroupName(groupEntity.getEffectiveName());
                                foundActive = true;
                                break;
                            }
                        }
                    }
                    // Orphaned — fall back to last known group name/OID saved at orphan time
                    if (!foundActive) {
                        info.setGroupName(entraProp.getLastKnownGroupName());
                        info.setGroupOid(entraProp.getLastKnownGroupOid());
                    }
                }
            } else {
                info.setProvisioningSource("NATIVE");
            }

            // Stale warning — would this user be flagged by cleanup?
            Instant staleCutoff = Instant.now().minus(staleThresholdDays(), ChronoUnit.DAYS);
            boolean isStale = (lastLogin == null) || Instant.parse(lastLogin).isBefore(staleCutoff);
            info.setStaleWarning(isStale);

            // Pending deletion flag
            if (entraProp != null) info.setPendingDeletion(entraProp.isPendingDeletion());

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

            // Exclude pending deletion accounts — shown in their own section
            if (entraProp != null && entraProp.isPendingDeletion()) continue;

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

    public List<UserInfo> getPendingDeletionUsers() {
        List<UserInfo> result = new ArrayList<>();
        OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();

        for (User user : User.getAll()) {
            if (isInternalUser(user)) continue;
            OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
            if (entraProp == null || !entraProp.isPendingDeletion()) continue;

            LastLoginProperty loginProp = user.getProperty(LastLoginProperty.class);
            String lastLogin = resolveLastLogin(entraProp, loginProp);

            UserInfo info = new UserInfo(
                    user.getId(),
                    user.getFullName(),
                    (entraProp != null) ? "Entra" : "Legacy",
                    lastLogin,
                    entraProp.getEntraObjectId()
            );

            // Determine reason: orphaned group account vs manually marked
            boolean isOrphanedGroup = entraProp.isViaGroup() && entraProp.getActiveGroupOids().isEmpty();
            info.setPendingReason(isOrphanedGroup ? "Group access revoked" : "Manually marked");
            result.add(info);
        }

        result.sort((a, b) -> {
            if (a.getLastLoginAt() == null) return -1;
            if (b.getLastLoginAt() == null) return 1;
            return a.getLastLoginAt().compareTo(b.getLastLoginAt());
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

        AccessInfo accessInfo = new AccessInfo(
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

        // Provisioning source
        if (entraProp != null) accessInfo.setProvisioningSource(entraProp.getProvisioningSource());

        // Populate group info for VIA_ENTRA_GROUP users
        if (entraProp != null && entraProp.isViaGroup()) {
            String gName = null, gOid = null;
            OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
            for (String oid : entraProp.getActiveGroupOids()) {
                if (ac != null && ac.hasGroup(oid)) {
                    OmniAuthGroupEntity ge = ac.findGroup(oid);
                    gName = ge != null ? ge.getEffectiveName() : null;
                    gOid  = oid;
                    break;
                }
            }
            if (gOid == null) {
                gName = entraProp.getLastKnownGroupName();
                gOid  = entraProp.getLastKnownGroupOid();
            }
            accessInfo.setGroupName(gName);
            accessInfo.setGroupOid(gOid);
        }

        // OmniAuth grants — all assignments for this user (direct + via groups)
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        OmniAuthRoleConfig roleConfig   = OmniAuthRoleConfig.get();
        List<GrantDisplay> omniAuthGrants = new ArrayList<>();
        if (config != null) {
            for (OmniAuthAssignment a : config.getAssignmentsForUser(userId, "USER")) {
                omniAuthGrants.add(toGrantDisplay(a, "USER", userId, user.getFullName(), roleConfig));
            }
            if (entraProp != null) {
                for (String gOid : entraProp.getActiveGroupOids()) {
                    String gName = gOid;
                    OmniAuthGroupEntity ge = config.findGroup(gOid);
                    if (ge != null) gName = ge.getEffectiveName();
                    for (OmniAuthAssignment a : config.getAssignmentsForUser(gOid, "GROUP")) {
                        omniAuthGrants.add(toGrantDisplay(a, "GROUP", gOid, gName, roleConfig));
                    }
                }
            }
        }
        accessInfo.setOmniAuthGrants(omniAuthGrants);

        return accessInfo;
    }

    private static GrantDisplay toGrantDisplay(OmniAuthAssignment a, String principalType,
                                                String principalId, String principalName,
                                                OmniAuthRoleConfig roleConfig) {
        String roleId   = a.getRoleId();
        String roleName = roleId;
        if (!"CUSTOM".equalsIgnoreCase(roleId) && roleConfig != null) {
            OmniAuthRoleConfig.RoleDefinition role = roleConfig.findRole(roleId);
            if (role != null) roleName = role.getName();
        }
        String expiresDisplay = a.getExpiresAt() != null ? formatDate(a.getExpiresAt()) : null;
        return new GrantDisplay(principalType, principalId, principalName,
                                roleId, roleName, a.getScope(), a.getScopeType(),
                                expiresDisplay, a.isExpired());
    }

    // -------------------------------------------------------------------------
    // Access Management (writable permission management)
    // -------------------------------------------------------------------------

    public boolean isOmniAuthActive() {
        return Jenkins.get().getAuthorizationStrategy() instanceof OmniAuthAuthorizationStrategy;
    }

    public List<String> getAllJobNames() {
        List<String> names = new ArrayList<>();
        try {
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                names.add(job.getFullName());
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to list jobs", e);
        }
        names.sort(String.CASE_INSENSITIVE_ORDER);
        return names;
    }

    /** Returns folders + jobs as a JSON array of {path, type} objects for the scope picker. */
    public String getAllScopeNamesJson() {
        List<String[]> items = new ArrayList<>();
        try {
            for (AbstractFolder<?> folder : Jenkins.get().getAllItems(AbstractFolder.class)) {
                items.add(new String[]{folder.getFullName(), "folder"});
            }
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                items.add(new String[]{job.getFullName(), "job"});
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to list scope items", e);
        }
        items.sort((a, b) -> a[0].compareToIgnoreCase(b[0]));
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            String path = items.get(i)[0].replace("\\", "\\\\").replace("\"", "\\\"");
            sb.append("{\"path\":\"").append(path).append("\",\"type\":\"").append(items.get(i)[1]).append("\"}");
        }
        sb.append("]");
        return sb.toString();
    }

    public List<AccessManagementUserInfo> getAccessManagementUserList() {
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (!(strat instanceof GlobalMatrixAuthorizationStrategy)) return Collections.emptyList();
        GlobalMatrixAuthorizationStrategy matrix = (GlobalMatrixAuthorizationStrategy) strat;

        Map<String, Set<String>> permsByKey = new LinkedHashMap<>();
        Map<String, AuthorizationType> typeByKey = new LinkedHashMap<>();

        for (Map.Entry<Permission, Set<PermissionEntry>> e : matrix.getGrantedPermissionEntries().entrySet()) {
            for (PermissionEntry pe : e.getValue()) {
                String key = pe.getType().name() + ":" + pe.getSid();
                permsByKey.computeIfAbsent(key, k -> new HashSet<>()).add(e.getKey().getId());
                typeByKey.put(key, pe.getType());
            }
        }

        List<AccessManagementUserInfo> result = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : permsByKey.entrySet()) {
            String key = entry.getKey();
            AuthorizationType atype = typeByKey.get(key);
            String sid = key.substring(key.indexOf(':') + 1);
            String dn = resolveDisplayName(sid, atype);
            OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
            String roleName = roleConfig != null ? roleConfig.matchRole(entry.getValue()) : null;
            if (roleName == null) roleName = "Custom";
            String lastLogin = null;
            String provisioningSource = "NATIVE";
            if (atype == AuthorizationType.USER) {
                User u = User.getById(sid, false);
                if (u != null) {
                    OmniAuthUserProperty ep = u.getProperty(OmniAuthUserProperty.class);
                    LastLoginProperty lp = u.getProperty(LastLoginProperty.class);
                    lastLogin = resolveLastLogin(ep, lp);
                    if (ep != null) provisioningSource = ep.getProvisioningSource();
                }
            }
            AccessManagementUserInfo userInfo = new AccessManagementUserInfo(sid, dn, atype, roleName, entry.getValue(), lastLogin);
            userInfo.setProvisioningSource(provisioningSource);
            // Check if any scoped OmniAuth assignment for this principal is overdue for review
            OmniAuthGlobalConfig reviewCfg = OmniAuthGlobalConfig.get();
            if (reviewCfg != null && reviewCfg.isAccessReviewEnabled()) {
                OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
                if (ac != null) {
                    int threshold = reviewCfg.getAccessReviewThresholdDays();
                    String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";
                    boolean due = ac.getAssignmentsForUser(sid, authTypeStr).stream()
                            .anyMatch(a -> a.isReviewDue(threshold));
                    userInfo.setHasReviewDue(due);
                }
            }
            result.add(userInfo);
        }
        // Also include GROUP entities from OmniAuthAssignmentConfig that may not have matrix entries
        // (e.g. if grantGlobalRead failed during initial add, or strategy was not active yet)
        OmniAuthAssignmentConfig aConfig = OmniAuthAssignmentConfig.get();
        if (aConfig != null) {
            for (OmniAuthGroupEntity groupEntity : aConfig.getGroups()) {
                String gOid = groupEntity.getGroupOid();
                boolean alreadyPresent = result.stream()
                        .anyMatch(r -> r.getType() == AuthorizationType.GROUP && r.getSid().equals(gOid));
                if (!alreadyPresent) {
                    result.add(new AccessManagementUserInfo(gOid, groupEntity.getEffectiveName(),
                            AuthorizationType.GROUP, "—", Collections.emptySet(), null));
                }
            }
        }

        result.sort((a, b) -> a.getSid().compareToIgnoreCase(b.getSid()));
        return result;
    }

    public List<PermissionGroupInfo> getAvailablePermissions() {
        // Friendly label mapping: permission ID → display name
        Map<String, String> labels = new LinkedHashMap<>();
        // Job
        labels.put("hudson.model.Item.Read",       "Read Jobs");
        labels.put("hudson.model.Item.Discover",   "Discover Jobs");
        labels.put("hudson.model.Item.Create",     "Create Jobs");
        labels.put("hudson.model.Item.Configure",  "Configure Jobs");
        labels.put("hudson.model.Item.Move",       "Move Jobs");
        labels.put("hudson.model.Item.Delete",     "Delete Jobs");
        labels.put("hudson.model.Item.Workspace",  "Access Workspace");
        labels.put("hudson.model.Item.Build",      "Trigger Builds");
        labels.put("hudson.model.Item.Cancel",     "Cancel Builds");
        // Run
        labels.put("hudson.model.Run.Replay",      "Replay Pipeline");
        labels.put("hudson.model.Run.Delete",      "Delete Build History");
        labels.put("hudson.model.Run.Update",      "Update Build Description");
        // View
        labels.put("hudson.model.View.Read",       "Read Views");
        labels.put("hudson.model.View.Create",     "Create Views");
        labels.put("hudson.model.View.Configure",  "Configure Views");
        labels.put("hudson.model.View.Delete",     "Delete Views");
        // SCM
        labels.put("hudson.scm.SCM.Tag",           "Create SCM Tags");
        // Overall
        labels.put("hudson.model.Hudson.Administer",              "Full Admin");
        labels.put("hudson.model.Hudson.Read",                    "Overall Read (Login)");
        labels.put("hudson.model.Hudson.Manage",                  "Manage Jenkins");
        labels.put("hudson.model.Hudson.SystemRead",              "Read System Config");
        labels.put("hudson.model.Hudson.RunScripts",              "Run Groovy Scripts");
        labels.put("hudson.model.Hudson.ConfigureUpdateCenter",   "Configure Update Center");
        labels.put("hudson.model.Hudson.UploadPlugins",           "Upload Plugins");
        // Agent
        labels.put("hudson.model.Computer.Build",                 "Use Agent for Builds");
        labels.put("hudson.model.Computer.Configure",             "Configure Agents");
        labels.put("hudson.model.Computer.Connect",               "Connect Agents");
        labels.put("hudson.model.Computer.Create",                "Create Agents");
        labels.put("hudson.model.Computer.Delete",                "Delete Agents");
        labels.put("hudson.model.Computer.Disconnect",            "Disconnect Agents");
        labels.put("hudson.model.Computer.Provision",             "Provision Agents");
        // Credentials
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.Create",        "Add Credentials");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.Delete",        "Delete Credentials");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains", "Manage Credential Domains");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.Update",        "Update Credentials");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.View",          "View Credentials");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.UseItem",       "Use Credentials in Jobs");
        labels.put("com.cloudbees.plugins.credentials.CredentialsProvider.UseOwn",        "Use Own Credentials");
        // Metrics
        labels.put("jenkins.metrics.api.Metrics.HealthCheck", "Health Check");
        labels.put("jenkins.metrics.api.Metrics.ThreadDump",  "Thread Dump");
        labels.put("jenkins.metrics.api.Metrics.View",        "View Metrics");

        List<PermissionGroupInfo> result = new ArrayList<>();

        result.add(buildGroup("Overall", "System-wide access control", new String[]{
                "hudson.model.Hudson.Read",
                "hudson.model.Hudson.Administer",
                "hudson.model.Hudson.Manage",
                "hudson.model.Hudson.SystemRead",
                "hudson.model.Hudson.RunScripts",
                "hudson.model.Hudson.ConfigureUpdateCenter",
                "hudson.model.Hudson.UploadPlugins"
        }, labels));

        result.add(buildGroup("Credentials", "Stored passwords, API keys & certificates", new String[]{
                "com.cloudbees.plugins.credentials.CredentialsProvider.View",
                "com.cloudbees.plugins.credentials.CredentialsProvider.Create",
                "com.cloudbees.plugins.credentials.CredentialsProvider.Update",
                "com.cloudbees.plugins.credentials.CredentialsProvider.Delete",
                "com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains",
                "com.cloudbees.plugins.credentials.CredentialsProvider.UseItem",
                "com.cloudbees.plugins.credentials.CredentialsProvider.UseOwn"
        }, labels));

        result.add(buildGroup("Agent", "Build nodes & executors", new String[]{
                "hudson.model.Computer.Build",
                "hudson.model.Computer.Configure",
                "hudson.model.Computer.Connect",
                "hudson.model.Computer.Create",
                "hudson.model.Computer.Delete",
                "hudson.model.Computer.Disconnect",
                "hudson.model.Computer.Provision"
        }, labels));

        result.add(buildGroup("Job", "Pipelines, freestyle jobs & folders", new String[]{
                "hudson.model.Item.Read",
                "hudson.model.Item.Discover",
                "hudson.model.Item.Create",
                "hudson.model.Item.Configure",
                "hudson.model.Item.Move",
                "hudson.model.Item.Delete",
                "hudson.model.Item.Build",
                "hudson.model.Item.Cancel",
                "hudson.model.Item.Workspace"
        }, labels));

        result.add(buildGroup("Run", "Individual build instances", new String[]{
                "hudson.model.Run.Replay",
                "hudson.model.Run.Delete",
                "hudson.model.Run.Update"
        }, labels));

        result.add(buildGroup("View", "Dashboard views & layouts", new String[]{
                "hudson.model.View.Read",
                "hudson.model.View.Create",
                "hudson.model.View.Configure",
                "hudson.model.View.Delete"
        }, labels));

        result.add(buildGroup("SCM", "Source control management", new String[]{
                "hudson.scm.SCM.Tag"
        }, labels));

        result.add(buildGroup("Metrics", "Health & monitoring endpoints", new String[]{
                "jenkins.metrics.api.Metrics.View",
                "jenkins.metrics.api.Metrics.HealthCheck",
                "jenkins.metrics.api.Metrics.ThreadDump"
        }, labels));

        // Plugin Permissions — anything not already in a named group above.
        // Excludes hudson.security.Permission.* (internal abstract base permissions, not user-facing).
        Set<String> knownIds = new HashSet<>(labels.keySet());
        List<PermissionInfo> pluginPerms = new ArrayList<>();
        for (PermissionGroup group : PermissionGroup.getAll()) {
            if (group.owner == hudson.security.Permission.class) continue; // skip internal abstract perms
            for (Permission p : group.getPermissions()) {
                if (!p.enabled) continue;
                String pId = p.getId();
                if (knownIds.contains(pId)) continue;
                int last = pId.lastIndexOf('.');
                int prev = last > 0 ? pId.lastIndexOf('.', last - 1) : -1;
                String raw = prev >= 0 ? pId.substring(prev + 1) : (last >= 0 ? pId.substring(last + 1) : pId);
                pluginPerms.add(new PermissionInfo(pId, raw));
            }
        }
        if (!pluginPerms.isEmpty()) {
            result.add(new PermissionGroupInfo(
                    "Other Plugin Permissions",
                    "Permissions from installed plugins not covered above",
                    pluginPerms));
        }

        // Remove empty groups (plugin absent or all permissions disabled)
        result.removeIf(g -> g.getPermissions().isEmpty());
        return result;
    }

    /** Returns only permissions that exist in this Jenkins and are enabled. */
    private PermissionGroupInfo buildGroup(String name, String subtitle, String[] ids, Map<String, String> labels) {
        List<PermissionInfo> perms = new ArrayList<>();
        for (String id : ids) {
            Permission p = Permission.fromId(id);
            if (p != null && p.enabled) {
                perms.add(new PermissionInfo(id, labels.getOrDefault(id, id)));
            }
        }
        return new PermissionGroupInfo(name, subtitle, perms);
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
            if (isActiveGroupUser(userId)) {
                LOGGER.warning("Deletion blocked — user is managed via active Entra group: " + userId);
                rsp.sendRedirect(back + "?error=activeGroup");
                return;
            }
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
                OmniAuthAuditLog audit = OmniAuthAuditLog.get();
                if (audit != null) audit.logUserDeleted(deletedBy, userId);
            }
            // Always wipe matrix entries — user object may already be gone but entries linger
            purgeMatrixEntries(userId);
        }
        rsp.sendRedirect(back + "?deleted=true");
    }

    public void doMarkForDeletion(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String userId = req.getParameter("userId");
        String from   = req.getParameter("from");
        if (userId != null && !userId.isEmpty()) {
            User user = User.getById(userId, false);
            if (user != null) {
                OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
                if (prop != null) {
                    prop.setPendingDeletion(true);
                    user.addProperty(prop);
                    user.save();
                    LOGGER.info("User marked for deletion by " + currentUserId() + ": " + userId);
                }
            }
        }
        String back = ("userStatus".equals(from)) ? "userStatus" : "staleUsers";
        rsp.sendRedirect(back + "?marked=true");
    }

    public void doUnmarkForDeletion(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String userId = req.getParameter("userId");
        String from   = req.getParameter("from");
        if (userId != null && !userId.isEmpty()) {
            User user = User.getById(userId, false);
            if (user != null) {
                OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
                if (prop != null) {
                    prop.setPendingDeletion(false);
                    user.addProperty(prop);
                    user.save();
                    LOGGER.info("Pending deletion cleared by " + currentUserId() + ": " + userId);
                }
            }
        }
        String back = ("userStatus".equals(from)) ? "userStatus" : "staleUsers";
        rsp.sendRedirect(back + "?unmarked=true");
    }

    private void purgeMatrixEntries(String userId) {
        // 1. Global matrix — remove both USER and GROUP entries (belt-and-suspenders)
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (strat instanceof OmniAuthAuthorizationStrategy) {
            OmniAuthAuthorizationStrategy current = (OmniAuthAuthorizationStrategy) strat;
            OmniAuthAuthorizationStrategy rebuilt = new OmniAuthAuthorizationStrategy();
            for (Map.Entry<Permission, Set<PermissionEntry>> e : current.getGrantedPermissionEntries().entrySet()) {
                for (PermissionEntry pe : e.getValue()) {
                    if (!pe.getSid().equals(userId)) {
                        rebuilt.add(e.getKey(), pe);
                    }
                }
            }
            Jenkins.get().setAuthorizationStrategy(rebuilt);
            try { Jenkins.get().save(); } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "Failed to save Jenkins config after purging global matrix for " + userId, ex);
            }
        }

        // 2. Job-level matrices
        try {
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                hudson.security.AuthorizationMatrixProperty prop =
                        job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
                if (prop == null) continue;
                boolean affected = prop.getGrantedPermissionEntries().values().stream()
                        .anyMatch(set -> set.stream().anyMatch(pe -> pe.getSid().equals(userId)));
                if (!affected) continue;
                mutateGrantedPermissions(prop, userId, null, null, Collections.emptySet());
                job.save();
            }
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "Failed to purge job-level matrix entries for " + userId, ex);
        }

        // 3. Folder-level matrices
        try {
            for (AbstractFolder<?> folder : Jenkins.get().getAllItems(AbstractFolder.class)) {
                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                        folder.getProperties().get(
                                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
                if (fp == null) continue;
                boolean affected = fp.getGrantedPermissionEntries().values().stream()
                        .anyMatch(set -> set.stream().anyMatch(pe -> pe.getSid().equals(userId)));
                if (!affected) continue;
                mutateGrantedPermissions(fp, userId, null, null, Collections.emptySet());
                folder.save();
            }
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "Failed to purge folder-level matrix entries for " + userId, ex);
        }
    }

    @POST
    public void doSetUserRole(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid      = req.getParameter("sid");
        String type     = req.getParameter("type");
        String roleName = req.getParameter("role");

        if (sid == null || sid.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missingSid"); return;
        }

        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (!(strat instanceof OmniAuthAuthorizationStrategy)) {
            rsp.sendRedirect("accessManagement?error=notOmniAuth"); return;
        }
        OmniAuthAuthorizationStrategy current = (OmniAuthAuthorizationStrategy) strat;

        Set<String> newPermIds;
        OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
        OmniAuthRoleConfig.RoleDefinition roleDef = roleConfig != null ? roleConfig.findRole(roleName) : null;
        if (roleDef != null) {
            newPermIds = new HashSet<>(roleDef.getPermissionIds());
        } else if ("CUSTOM".equalsIgnoreCase(roleName)) {
            String[] custom = req.getParameterValues("customPermissions");
            newPermIds = custom != null ? new HashSet<>(Arrays.asList(custom)) : Collections.emptySet();
        } else {
            rsp.sendRedirect("accessManagement?error=invalidRole"); return;
        }

        if (newPermIds.isEmpty()) {
            rsp.sendRedirect("accessManagement?error=noPermissions"); return;
        }

        AuthorizationType targetType = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;
        sid = sid.trim();

        // Rebuild: keep all other entries, replace this user's entries.
        // Preserve Hudson.Read for this user — login access comes from account creation, not role.
        Permission hudsonRead = Permission.fromId("hudson.model.Hudson.Read");
        OmniAuthAuthorizationStrategy rebuilt = new OmniAuthAuthorizationStrategy();
        for (Map.Entry<Permission, Set<PermissionEntry>> e : current.getGrantedPermissionEntries().entrySet()) {
            for (PermissionEntry pe : e.getValue()) {
                boolean isThisUser = pe.getSid().equals(sid) && pe.getType() == targetType;
                boolean isHudsonRead = e.getKey().equals(hudsonRead);
                if (!isThisUser || isHudsonRead) {
                    rebuilt.add(e.getKey(), pe);
                }
            }
        }
        PermissionEntry entry = targetType == AuthorizationType.GROUP
                ? PermissionEntry.group(sid) : PermissionEntry.user(sid);
        for (String permId : newPermIds) {
            Permission p = Permission.fromId(permId);
            if (p != null) rebuilt.add(p, entry);
        }

        Set<PermissionEntry> adminSet = rebuilt.getGrantedPermissionEntries().get(Jenkins.ADMINISTER);
        if (adminSet == null || adminSet.isEmpty()) {
            rsp.sendRedirect("accessManagement?error=lastAdmin"); return;
        }

        Jenkins.get().setAuthorizationStrategy(rebuilt);
        Jenkins.get().save();
        rsp.sendRedirect("accessManagement?saved=true&sid=" + java.net.URLEncoder.encode(sid, "UTF-8"));
    }

    @POST
    public void doRemoveUserAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid  = req.getParameter("sid");
        String type = req.getParameter("type");

        if (sid == null) { rsp.sendRedirect("accessManagement?error=missing"); return; }

        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (!(strat instanceof OmniAuthAuthorizationStrategy)) {
            rsp.sendRedirect("accessManagement?error=notOmniAuth"); return;
        }
        OmniAuthAuthorizationStrategy current = (OmniAuthAuthorizationStrategy) strat;
        AuthorizationType targetType = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        OmniAuthAuthorizationStrategy rebuilt = new OmniAuthAuthorizationStrategy();
        for (Map.Entry<Permission, Set<PermissionEntry>> e : current.getGrantedPermissionEntries().entrySet()) {
            for (PermissionEntry pe : e.getValue()) {
                if (!(pe.getSid().equals(sid) && pe.getType() == targetType)) {
                    rebuilt.add(e.getKey(), pe);
                }
            }
        }

        Set<PermissionEntry> adminSet = rebuilt.getGrantedPermissionEntries().get(Jenkins.ADMINISTER);
        if (adminSet == null || adminSet.isEmpty()) {
            rsp.sendRedirect("accessManagement?error=lastAdmin"); return;
        }

        Jenkins.get().setAuthorizationStrategy(rebuilt);
        Jenkins.get().save();
        rsp.sendRedirect("accessManagement?removed=true");
    }

    /** Returns JSON array of scoped permissions for a user across all jobs. */
    public void doScopedAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid  = req.getParameter("sid");
        String type = req.getParameter("type");
        if (sid == null) { writeJson(rsp, "[]"); return; }

        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        try {
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                hudson.security.AuthorizationMatrixProperty prop =
                        job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
                if (prop == null) continue;
                List<String> granted = new ArrayList<>();
                for (Map.Entry<Permission, Set<PermissionEntry>> e : prop.getGrantedPermissionEntries().entrySet()) {
                    for (PermissionEntry pe : e.getValue()) {
                        if (pe.getSid().equals(sid) && pe.getType() == atype) {
                            String pId = e.getKey().getId();
                            int dot = pId.lastIndexOf('.');
                            granted.add(dot >= 0 ? pId.substring(dot + 1) : pId);
                        }
                    }
                }
                if (!granted.isEmpty()) {
                    if (!first) json.append(",");
                    json.append("{\"jobName\":\"").append(escapeJson(job.getFullName())).append("\"")
                        .append(",\"permissions\":[");
                    for (int i = 0; i < granted.size(); i++) {
                        if (i > 0) json.append(",");
                        json.append("\"").append(escapeJson(granted.get(i))).append("\"");
                    }
                    json.append("]}");
                    first = false;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning scoped permissions", e);
        }
        writeJson(rsp, json.append("]").toString());
    }

    public void doAllScopedAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        try {
            for (Job<?, ?> job : Jenkins.get().getAllItems(Job.class)) {
                hudson.security.AuthorizationMatrixProperty prop =
                        job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
                if (prop == null) continue;
                Map<String, List<String>> bySid = new LinkedHashMap<>();
                Map<String, String> sidType = new java.util.LinkedHashMap<>();
                for (Map.Entry<Permission, Set<PermissionEntry>> e : prop.getGrantedPermissionEntries().entrySet()) {
                    String pShort = e.getKey().getId();
                    int dot = pShort.lastIndexOf('.');
                    if (dot >= 0) pShort = pShort.substring(dot + 1);
                    for (PermissionEntry pe : e.getValue()) {
                        String key = pe.getType().name() + "\0" + pe.getSid();
                        bySid.computeIfAbsent(key, k -> new ArrayList<>()).add(pShort);
                        sidType.put(key, pe.getType().name());
                    }
                }
                for (Map.Entry<String, List<String>> entry : bySid.entrySet()) {
                    String[] parts = entry.getKey().split("\0", 2);
                    if (!first) json.append(",");
                    json.append("{\"sid\":\"").append(escapeJson(parts.length > 1 ? parts[1] : parts[0])).append("\"")
                        .append(",\"type\":\"").append(parts[0]).append("\"")
                        .append(",\"jobName\":\"").append(escapeJson(job.getFullName())).append("\"")
                        .append(",\"permissions\":[");
                    List<String> perms = entry.getValue();
                    for (int i = 0; i < perms.size(); i++) {
                        if (i > 0) json.append(",");
                        json.append("\"").append(escapeJson(perms.get(i))).append("\"");
                    }
                    json.append("]}");
                    first = false;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning all scoped permissions", e);
        }
        writeJson(rsp, json.append("]").toString());
    }

    @POST
    public void doGrantScopedAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid       = req.getParameter("sid");
        String type      = req.getParameter("type");
        String jobName   = req.getParameter("jobName");
        String scopedRole = req.getParameter("scopedRole");

        if (sid == null || jobName == null) {
            rsp.sendRedirect("accessManagement?error=missing"); return;
        }

        Job<?, ?> job = Jenkins.get().getItemByFullName(jobName, Job.class);
        if (job == null) {
            rsp.sendRedirect("accessManagement?error=jobNotFound&sid=" +
                    java.net.URLEncoder.encode(sid, "UTF-8")); return;
        }

        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;
        PermissionEntry entry = atype == AuthorizationType.GROUP
                ? PermissionEntry.group(sid) : PermissionEntry.user(sid);

        // Determine permissions from config-based role, then legacy scoped role names
        List<String> permIds;
        OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
        OmniAuthRoleConfig.RoleDefinition roleDef = roleConfig != null ? roleConfig.findRole(scopedRole) : null;
        if (roleDef != null) {
            permIds = new ArrayList<>(roleDef.getPermissionIds());
        } else {
            permIds = new ArrayList<>();
            permIds.add("hudson.model.Item.Read");
            if ("BUILD".equals(scopedRole) || "CONFIGURE".equals(scopedRole)) {
                permIds.add("hudson.model.Item.Build");
                permIds.add("hudson.model.Item.Cancel");
            }
            if ("CONFIGURE".equals(scopedRole)) {
                permIds.add("hudson.model.Item.Configure");
                permIds.add("hudson.model.Item.Delete");
            }
        }

        // Grant on the target job
        hudson.security.AuthorizationMatrixProperty prop =
                job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
        if (prop == null) {
            prop = new hudson.security.AuthorizationMatrixProperty(new java.util.HashMap<>());
        }
        for (String permId : permIds) {
            Permission p = Permission.fromId(permId);
            if (p != null) prop.add(p, entry);
        }
        job.addProperty(prop);
        job.save();

        // Auto-grant Item.Read on all parent jobs/folders (best-effort)
        hudson.model.ItemGroup<?> parent = job.getParent();
        while (parent instanceof Job) {
            Job<?, ?> parentJob = (Job<?, ?>) parent;
            try {
                hudson.security.AuthorizationMatrixProperty fp =
                        parentJob.getProperty(hudson.security.AuthorizationMatrixProperty.class);
                if (fp == null) fp = new hudson.security.AuthorizationMatrixProperty(new java.util.HashMap<>());
                Permission readPerm = Permission.fromId("hudson.model.Item.Read");
                if (readPerm != null) fp.add(readPerm, entry);
                parentJob.addProperty(fp);
                parentJob.save();
            } catch (Exception ignored) {}
            parent = ((hudson.model.AbstractItem) parentJob).getParent();
        }

        rsp.sendRedirect("accessManagement?saved=true&sid=" +
                java.net.URLEncoder.encode(sid, "UTF-8"));
    }

    @POST
    public void doRevokeScopedAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid     = req.getParameter("sid");
        String type    = req.getParameter("type");
        String jobName = req.getParameter("jobName");

        if (sid == null || jobName == null) {
            rsp.sendRedirect("accessManagement?error=missing"); return;
        }

        Job<?, ?> job = Jenkins.get().getItemByFullName(jobName, Job.class);
        if (job == null) {
            rsp.sendRedirect("accessManagement?saved=true&sid=" +
                    java.net.URLEncoder.encode(sid, "UTF-8")); return;
        }

        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        hudson.security.AuthorizationMatrixProperty prop =
                job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
        if (prop != null) {
            // Build filtered map excluding this user's entries
            java.util.Map<Permission, Set<PermissionEntry>> filteredMap = new java.util.HashMap<>();
            for (Map.Entry<Permission, Set<PermissionEntry>> e : prop.getGrantedPermissionEntries().entrySet()) {
                for (PermissionEntry pe : e.getValue()) {
                    if (!(pe.getSid().equals(sid) && pe.getType() == atype)) {
                        filteredMap.computeIfAbsent(e.getKey(), k -> new java.util.HashSet<>()).add(pe);
                    }
                }
            }
            hudson.security.AuthorizationMatrixProperty rebuilt =
                    new hudson.security.AuthorizationMatrixProperty(filteredMap, prop.getInheritanceStrategy());
            job.addProperty(rebuilt);
            job.save();
        }

        rsp.sendRedirect("accessManagement?saved=true&sid=" +
                java.net.URLEncoder.encode(sid, "UTF-8"));
    }

    // -------------------------------------------------------------------------
    // Role management (CRUD for OmniAuthRoleConfig)
    // -------------------------------------------------------------------------

    public List<OmniAuthRoleConfig.RoleDefinition> getRoles() {
        OmniAuthRoleConfig cfg = OmniAuthRoleConfig.get();
        return cfg != null ? cfg.getRoles() : Collections.emptyList();
    }

    @POST
    public void doSaveRole(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String name        = req.getParameter("roleName");
        String description = req.getParameter("roleDescription");
        String[] permIds   = req.getParameterValues("rolePermissions");
        if (name == null || name.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missingRoleName"); return;
        }
        OmniAuthRoleConfig cfg = OmniAuthRoleConfig.get();
        if (cfg != null) {
            List<String> perms = permIds != null ? Arrays.asList(permIds) : Collections.emptyList();
            boolean isNew = cfg.findRole(name.trim()) == null;
            cfg.upsertRole(name.trim(), description != null ? description.trim() : "", perms);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) {
                if (isNew) audit.logRoleCreated(Jenkins.getAuthentication2().getName(), name.trim());
                else audit.logRoleEdited(Jenkins.getAuthentication2().getName(), name.trim());
            }
        }
        rsp.sendRedirect("accessManagement?roleSaved=true");
    }

    @POST
    public void doDeleteRole(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String name = req.getParameter("roleName");
        if (name != null) {
            OmniAuthRoleConfig cfg = OmniAuthRoleConfig.get();
            if (cfg != null) cfg.deleteRole(name);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logRoleDeleted(Jenkins.getAuthentication2().getName(), name);
        }
        rsp.sendRedirect("accessManagement?roleDeleted=true");
    }

    // -------------------------------------------------------------------------
    // User-centric assignment view (used by userDetail.jelly)
    // -------------------------------------------------------------------------

    public List<UserAssignmentInfo> getUserAssignments() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return Collections.emptyList();
        String sid  = req.getParameter("sid");
        String type = req.getParameter("type");
        if (sid == null) return Collections.emptyList();

        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;
        OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
        List<UserAssignmentInfo> result = new ArrayList<>();

        // Global assignment
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (strat instanceof GlobalMatrixAuthorizationStrategy) {
            Set<String> perms = collectDirectPermsForUser(
                    ((GlobalMatrixAuthorizationStrategy) strat).getGrantedPermissionEntries(), sid, atype);
            if (!perms.isEmpty()) {
                String roleName = roleConfig != null ? roleConfig.matchRole(perms) : null;
                result.add(new UserAssignmentInfo("", "Jenkins (Global)", "global",
                        roleName != null ? roleName : "Custom", new ArrayList<>(perms),
                        null, null));
            }
        }

        // Item-level assignments from assignment store
        OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
        if (assignmentConfig != null) {
            String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";
            OmniAuthGlobalConfig reviewCfg = OmniAuthGlobalConfig.get();
            int reviewThreshold = (reviewCfg != null && reviewCfg.isAccessReviewEnabled())
                    ? reviewCfg.getAccessReviewThresholdDays() : -1;
            for (OmniAuthAssignment a : assignmentConfig.getAssignmentsForUser(sid, authTypeStr)) {
                if (a.getScope().isEmpty()) continue; // global handled above
                String itemType = "FOLDER".equals(a.getScopeType()) ? "folder" : "job";
                List<String> perms = "CUSTOM".equalsIgnoreCase(a.getRoleId())
                        ? a.getCustomPermissions()
                        : (roleConfig != null && roleConfig.findRole(a.getRoleId()) != null
                                ? roleConfig.findRole(a.getRoleId()).getPermissionIds()
                                : Collections.emptyList());
                List<String> customPerms = "CUSTOM".equalsIgnoreCase(a.getRoleId())
                        ? a.getCustomPermissions() : Collections.emptyList();
                UserAssignmentInfo info = new UserAssignmentInfo(a.getScope(), a.getScope(), itemType,
                        a.getRoleId(), new ArrayList<>(perms),
                        a.getExpiresAt(), new ArrayList<>(customPerms));
                if (reviewThreshold > 0) info.setReviewDue(a.isReviewDue(reviewThreshold));
                info.setAccessType(a.getAccessType());
                info.setApproverGroup(a.getApproverGroup());
                info.setMaxDurationHours(a.getMaxDurationHours());
                info.setApprovalTimeoutHours(a.getApprovalTimeoutHours());
                result.add(info);
            }
        }

        return result;
    }

    /** Grant a config-defined role to a user at a given scope (global or specific item path). */
    @POST
    public void doGrantAssignment(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid      = req.getParameter("sid");
        String type     = req.getParameter("type");
        String roleName = req.getParameter("role");
        String scope    = req.getParameter("scope"); // "" = global, "item/path" = scoped

        if (sid == null || sid.trim().isEmpty()) {
            rsp.sendRedirect("userDetail?sid=&type=&error=missingSid"); return;
        }
        sid = sid.trim();
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        Set<String> permIds;
        if ("CUSTOM".equalsIgnoreCase(roleName)) {
            String[] custom = req.getParameterValues("customPermissions");
            permIds = custom != null && custom.length > 0
                    ? new HashSet<>(Arrays.asList(custom)) : Collections.emptySet();
        } else {
            OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
            OmniAuthRoleConfig.RoleDefinition roleDef = roleConfig != null ? roleConfig.findRole(roleName) : null;
            if (roleDef == null) {
                rsp.sendRedirect(detailUrl(sid, atype, "error=invalidRole")); return;
            }
            permIds = new HashSet<>(roleDef.getPermissionIds());
        }
        if (permIds.isEmpty()) {
            rsp.sendRedirect(detailUrl(sid, atype, "error=noPermissions")); return;
        }

        String expiresAt = toInstantString(req.getParameter("expiresAt"));

        if (scope == null || scope.isEmpty()) {
            applyRootPermissions(sid, atype, permIds, rsp, false);
        } else {
            Item item = Jenkins.get().getItemByFullName(scope);
            if (item == null) {
                rsp.sendRedirect(detailUrl(sid, atype, "error=notFound")); return;
            }
            String scopeType = (item instanceof com.cloudbees.hudson.plugins.folder.AbstractFolder) ? "FOLDER" : "JOB";
            String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";
            String grantedAt = java.time.Instant.now().toString();
            String grantedBy = Jenkins.getAuthentication2().getName();
            List<String> customPerms = "CUSTOM".equalsIgnoreCase(roleName)
                    ? new java.util.ArrayList<>(permIds) : null;
            OmniAuthAssignment assignment = new OmniAuthAssignment(
                    sid, authTypeStr, roleName, scope, scopeType, customPerms, grantedAt, grantedBy);
            assignment.setExpiresAt(expiresAt);
            applyJitFieldsFromRequest(req, assignment);
            if (assignment.isJit() && assignment.getApprovers().size() < 2) {
                rsp.sendRedirect(detailUrl(sid, atype, "error=jitMinApprovers")); return;
            }
            OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
            if (config != null) config.addAssignment(assignment);
            // Ensure user can log in — Hudson.Read at global is required for any access
            grantGlobalRead(sid, atype);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logGrant(Jenkins.getAuthentication2().getName(), sid, roleName, scope, expiresAt);
            rsp.sendRedirect(detailUrl(sid, atype, "saved=true"));
        }
    }

    /** Typeahead endpoint — returns up to 10 users + groups whose id/name contains the query. */
    public void doSuggestApprovers(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String q = req.getParameter("q");
        if (q == null) q = "";
        String lq = q.toLowerCase().trim();

        java.util.List<String> results = new java.util.ArrayList<>();

        // Groups first — from OmniAuth group assignments (unique group IDs)
        OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
        if (assignmentConfig != null) {
            java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
            for (OmniAuthAssignment a : assignmentConfig.getAssignments()) {
                if (!"GROUP".equalsIgnoreCase(a.getAuthType())) continue;
                String gid = a.getUserId();
                if (gid == null || gid.isBlank() || seen.contains(gid)) continue;
                seen.add(gid);
                if (!lq.isEmpty() && !gid.toLowerCase().contains(lq)) continue;
                results.add("{\"id\":\"" + jsonEsc(gid) + "\",\"type\":\"group\"}");
                if (results.size() >= 5) break;
            }
        }

        // Users — remaining slots up to 10 total
        int remaining = 10 - results.size();
        for (User user : User.getAll()) {
            if (remaining <= 0) break;
            if (isInternalUser(user)) continue;
            String id      = user.getId();
            String full    = user.getFullName();
            String display = (full != null && !full.equals(id)) ? full : null;
            String combined = (id + " " + (display != null ? display : "")).toLowerCase();
            if (!lq.isEmpty() && !combined.contains(lq)) continue;
            StringBuilder entry = new StringBuilder("{\"id\":\"").append(jsonEsc(id)).append("\",\"type\":\"user\"");
            if (display != null) entry.append(",\"displayName\":\"").append(jsonEsc(display)).append("\"");
            entry.append("}");
            results.add(entry.toString());
            remaining--;
        }

        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write("[" + String.join(",", results) + "]");
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static void applyJitFieldsFromRequest(StaplerRequest req, OmniAuthAssignment assignment) {
        String accessType = req.getParameter("accessType");
        if ("JIT".equalsIgnoreCase(accessType)) {
            assignment.setAccessType("JIT");
            String approversParam = req.getParameter("approvers");
            if (approversParam != null && !approversParam.isBlank()) {
                java.util.List<String> approvers = java.util.Arrays.stream(approversParam.split(","))
                        .map(String::trim).filter(s -> !s.isEmpty())
                        .collect(java.util.stream.Collectors.toList());
                assignment.setApprovers(approvers);
            }
            try { assignment.setMaxDurationHours(Integer.parseInt(req.getParameter("maxDurationHours"))); } catch (Exception ignore) {}
            try { assignment.setApprovalTimeoutHours(Integer.parseInt(req.getParameter("approvalTimeoutHours"))); } catch (Exception ignore) {}
        } else {
            assignment.setAccessType("STANDING");
        }
    }

    /** Edit (replace) an existing assignment — scope stays the same, role/permissions/expiry may change. */
    @POST
    public void doEditAssignment(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid      = req.getParameter("sid");
        String type     = req.getParameter("type");
        String scope    = req.getParameter("scope");
        String roleName = req.getParameter("role");
        String expiresAt = toInstantString(req.getParameter("expiresAt"));

        if (sid == null || sid.trim().isEmpty()) {
            rsp.sendRedirect("userDetail?sid=&type=&error=missingSid"); return;
        }
        sid = sid.trim();
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;
        String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";

        Set<String> permIds;
        if ("CUSTOM".equalsIgnoreCase(roleName)) {
            String[] custom = req.getParameterValues("customPermissions");
            permIds = custom != null && custom.length > 0
                    ? new HashSet<>(Arrays.asList(custom)) : Collections.emptySet();
        } else {
            OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
            OmniAuthRoleConfig.RoleDefinition roleDef = roleConfig != null ? roleConfig.findRole(roleName) : null;
            if (roleDef == null) {
                rsp.sendRedirect(detailUrl(sid, atype, "error=invalidRole")); return;
            }
            permIds = new HashSet<>(roleDef.getPermissionIds());
        }
        if (permIds.isEmpty()) {
            rsp.sendRedirect(detailUrl(sid, atype, "error=noPermissions")); return;
        }

        String scopeType;
        if (scope == null || scope.isEmpty()) {
            scopeType = "GLOBAL";
        } else {
            Item item = Jenkins.get().getItemByFullName(scope);
            scopeType = (item instanceof com.cloudbees.hudson.plugins.folder.AbstractFolder) ? "FOLDER" : "JOB";
        }

        List<String> customPerms = "CUSTOM".equalsIgnoreCase(roleName)
                ? new ArrayList<>(permIds) : null;

        OmniAuthAssignment updated = new OmniAuthAssignment(
                sid, authTypeStr, roleName,
                scope != null ? scope : "", scopeType,
                customPerms,
                java.time.Instant.now().toString(),
                Jenkins.getAuthentication2().getName());
        updated.setExpiresAt(expiresAt);
        applyJitFieldsFromRequest(req, updated);
        if (updated.isJit() && updated.getApprovers().size() < 2) {
            rsp.sendRedirect(detailUrl(sid, atype, "error=jitMinApprovers")); return;
        }

        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        String oldRole = null;
        if (config != null) {
            OmniAuthAssignment existing = config.getAssignmentsForUser(sid, authTypeStr).stream()
                    .filter(a -> a.getScope().equals(scope != null ? scope : ""))
                    .findFirst().orElse(null);
            oldRole = existing != null ? existing.getRoleId() : null;
            config.updateAssignment(sid, authTypeStr, scope != null ? scope : "", updated);
        }
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logEdit(Jenkins.getAuthentication2().getName(), sid, scope, oldRole != null ? oldRole : "?", roleName, expiresAt);
        rsp.sendRedirect(detailUrl(sid, atype, "saved=true"));
    }

    /** Revoke a specific access assignment (global or scoped to an item path). */
    @POST
    public void doRevokeAssignment(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid   = req.getParameter("sid");
        String type  = req.getParameter("type");
        String scope = req.getParameter("scope");

        if (sid == null) {
            rsp.sendRedirect("userDetail?sid=&type=&error=missing"); return;
        }
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        if (scope == null || scope.isEmpty()) {
            applyRootPermissions(sid, atype, Collections.emptySet(), rsp, true);
        } else {
            String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";
            OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
            String revokedRole = null;
            if (config != null) {
                String normalizedScope = scope == null ? "" : scope;
                revokedRole = config.getAssignmentsForUser(sid, authTypeStr).stream()
                        .filter(a -> a.getScope().equals(normalizedScope))
                        .findFirst().map(OmniAuthAssignment::getRoleId).orElse(null);
                config.removeAssignment(sid, authTypeStr, scope);
            }
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logRevoke(Jenkins.getAuthentication2().getName(), sid, scope, revokedRole);
            rsp.sendRedirect(detailUrl(sid, atype, "saved=true"));
        }
    }

    public void doConfirmAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid      = req.getParameter("sid");
        String type     = req.getParameter("type");
        String scope    = req.getParameter("scope");
        String returnTo = req.getParameter("returnTo");
        if (sid == null || sid.isBlank()) {
            rsp.sendRedirect("accessManagement"); return;
        }
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;
        String authTypeStr = atype == AuthorizationType.GROUP ? "GROUP" : "USER";

        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        String confirmedRole = null;
        if (config != null) {
            String normalizedScope = scope != null ? scope : "";
            confirmedRole = config.getAssignmentsForUser(sid, authTypeStr).stream()
                    .filter(a -> a.getScope().equals(normalizedScope))
                    .findFirst().map(OmniAuthAssignment::getRoleId).orElse(null);
            config.confirmReview(sid, authTypeStr, normalizedScope);
        }
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logReviewConfirmed(Jenkins.getAuthentication2().getName(), sid, confirmedRole, scope);
        if ("accessReview".equals(returnTo)) {
            rsp.sendRedirect("accessReview?confirmed=true");
        } else {
            rsp.sendRedirect(detailUrl(sid, atype, "reviewed=true"));
        }
    }

    @POST
    public void doConfirmAllAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (cfg == null || !cfg.isAccessReviewEnabled()) { rsp.sendRedirect("accessReview"); return; }
        OmniAuthAssignmentConfig ac = OmniAuthAssignmentConfig.get();
        if (ac == null) { rsp.sendRedirect("accessReview"); return; }
        int threshold = cfg.getAccessReviewThresholdDays();
        String by = Jenkins.getAuthentication2().getName();
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        for (OmniAuthAssignment a : ac.getAssignments()) {
            if (!a.isReviewDue(threshold)) continue;
            ac.confirmReview(a.getUserId(), a.getAuthType(), a.getScope());
            if (audit != null) audit.logReviewConfirmed(by, a.getUserId(), a.getRoleId(), a.getScope());
        }
        rsp.sendRedirect("accessReview?confirmedAll=true");
    }

    @POST
    public void doRevokeFromReview(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid   = req.getParameter("sid");
        String type  = req.getParameter("type");
        String scope = req.getParameter("scope");
        if (sid == null || sid.isBlank()) {
            rsp.sendRedirect("accessReview"); return;
        }
        String authTypeStr = "GROUP".equalsIgnoreCase(type) ? "GROUP" : "USER";
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        String revokedRole = null;
        if (config != null) {
            String normalizedScope = scope != null ? scope : "";
            revokedRole = config.getAssignmentsForUser(sid, authTypeStr).stream()
                    .filter(a -> a.getScope().equals(normalizedScope))
                    .findFirst().map(OmniAuthAssignment::getRoleId).orElse(null);
            config.removeAssignment(sid, authTypeStr, normalizedScope);
        }
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logRevoke(Jenkins.getAuthentication2().getName(), sid,
                scope != null ? scope : "", revokedRole);
        rsp.sendRedirect("accessReview?revoked=true");
    }

    // -------------------------------------------------------------------------
    // Group assignment helpers
    // -------------------------------------------------------------------------

    public List<OmniAuthAssignment> getGroupAssignmentsForOid(String groupOid) {
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null) return Collections.emptyList();
        return config.getAssignmentsForUser(groupOid, "GROUP");
    }

    /** Returns group assignments as the same rich view model used by userDetail.jelly. */
    public List<UserAssignmentInfo> getGroupDetailAssignments() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return Collections.emptyList();
        String oid = req.getParameter("oid");
        if (oid == null) return Collections.emptyList();

        OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
        List<UserAssignmentInfo> result = new ArrayList<>();

        // Global assignment from matrix
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (strat instanceof GlobalMatrixAuthorizationStrategy) {
            Set<String> perms = collectDirectPermsForUser(
                    ((GlobalMatrixAuthorizationStrategy) strat).getGrantedPermissionEntries(),
                    oid, AuthorizationType.GROUP);
            if (!perms.isEmpty()) {
                String roleName = roleConfig != null ? roleConfig.matchRole(perms) : null;
                result.add(new UserAssignmentInfo("", "Jenkins (Global)", "global",
                        roleName != null ? roleName : "Custom", new ArrayList<>(perms), null, null));
            }
        }

        // Item-level assignments
        OmniAuthAssignmentConfig aConfig = OmniAuthAssignmentConfig.get();
        if (aConfig != null) {
            OmniAuthGlobalConfig reviewCfg = OmniAuthGlobalConfig.get();
            int reviewThreshold = (reviewCfg != null && reviewCfg.isAccessReviewEnabled())
                    ? reviewCfg.getAccessReviewThresholdDays() : -1;
            for (OmniAuthAssignment a : aConfig.getAssignmentsForUser(oid, "GROUP")) {
                if (a.getScope().isEmpty()) continue;
                String itemType = "FOLDER".equals(a.getScopeType()) ? "folder" : "job";
                List<String> perms = "CUSTOM".equalsIgnoreCase(a.getRoleId())
                        ? a.getCustomPermissions()
                        : (roleConfig != null && roleConfig.findRole(a.getRoleId()) != null
                                ? roleConfig.findRole(a.getRoleId()).getPermissionIds()
                                : Collections.emptyList());
                List<String> customPerms = "CUSTOM".equalsIgnoreCase(a.getRoleId())
                        ? a.getCustomPermissions() : Collections.emptyList();
                UserAssignmentInfo info = new UserAssignmentInfo(a.getScope(), a.getScope(), itemType,
                        a.getRoleId(), new ArrayList<>(perms), a.getExpiresAt(), new ArrayList<>(customPerms));
                if (reviewThreshold > 0) info.setReviewDue(a.isReviewDue(reviewThreshold));
                result.add(info);
            }
        }
        return result;
    }

    public void doGrantGroupAssignment(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String groupOid   = req.getParameter("sid");
        String roleId     = req.getParameter("roleId");
        String scopeType  = req.getParameter("scopeType");
        String scope      = req.getParameter("scope");
        if (scope == null) scope = "";
        scope = scope.trim();
        if ("GLOBAL".equalsIgnoreCase(scopeType)) scope = "";

        if (groupOid == null || groupOid.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missing"); return;
        }
        if (roleId == null || roleId.trim().isEmpty()) {
            rsp.sendRedirect("groupDetail?oid=" + enc(groupOid) + "&error=invalidRole"); return;
        }
        String now = java.time.Instant.now().toString();
        String by  = Jenkins.getAuthentication2().getName();
        OmniAuthAssignment assignment = new OmniAuthAssignment(
                groupOid, "GROUP", roleId, scope, scopeType != null ? scopeType : "GLOBAL",
                Collections.emptyList(), now, by);
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config != null) config.addAssignment(assignment);
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logGrant(by, groupOid, roleId, scope, null);
        rsp.sendRedirect("groupDetail?oid=" + enc(groupOid) + "&saved=true");
    }

    public void doRevokeGroupAssignment(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String groupOid = req.getParameter("sid");
        String scope    = req.getParameter("scope");
        if (scope == null) scope = "";
        if (groupOid == null || groupOid.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missing"); return;
        }
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config != null) config.removeAssignment(groupOid, "GROUP", scope);
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logRevoke(Jenkins.getAuthentication2().getName(), groupOid, scope, null);
        rsp.sendRedirect("groupDetail?oid=" + enc(groupOid) + "&saved=true");
    }

    // -------------------------------------------------------------------------
    // Add User flow
    // -------------------------------------------------------------------------

    /** AJAX: check whether a native Jenkins account exists for the given username. */
    public void doCheckNativeUser(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String username = req.getParameter("username");
        rsp.setContentType("application/json;charset=UTF-8");
        rsp.addHeader("Cache-Control", "no-cache");
        java.io.PrintWriter w = rsp.getWriter();
        if (username == null || username.trim().isEmpty()) {
            w.write("{\"exists\":false}"); return;
        }
        User user = User.getById(username.trim(), false);
        if (user != null) {
            String dn = user.getDisplayName() != null ? user.getDisplayName() : username.trim();
            w.write("{\"exists\":true,\"displayName\":\""
                    + dn.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
        } else {
            w.write("{\"exists\":false}");
        }
    }

    /** POST: add a user (native create or Entra pre-provision) then redirect to their detail page. */
    @POST
    public void doAddUser(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String userType           = req.getParameter("userType"); // NATIVE, ENTRA, or GROUP
        String sid                = req.getParameter("sid");
        String action             = req.getParameter("action");   // "existing" or "create"
        String fullName           = req.getParameter("fullName");
        String email              = req.getParameter("email");
        boolean forcePasswordChange = "true".equals(req.getParameter("forcePasswordChange"));

        // For GROUP type the OID comes from a dedicated field to avoid conflicts with the sid field
        if ("GROUP".equalsIgnoreCase(userType)) {
            String groupOidParam = req.getParameter("groupOid");
            if (groupOidParam != null && !groupOidParam.trim().isEmpty()) {
                sid = groupOidParam.trim();
            }
        }

        if (sid == null || sid.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missingSid"); return;
        }
        sid = sid.trim();

        if ("NATIVE".equalsIgnoreCase(userType) && "create".equalsIgnoreCase(action)) {
            if (!(Jenkins.get().getSecurityRealm() instanceof hudson.security.HudsonPrivateSecurityRealm)) {
                rsp.sendRedirect("accessManagement?error=notNativeRealm"); return;
            }
            hudson.security.HudsonPrivateSecurityRealm realm =
                    (hudson.security.HudsonPrivateSecurityRealm) Jenkins.get().getSecurityRealm();
            String tmpPwd = generateTempPassword();
            realm.createAccount(sid, tmpPwd);
            User user = User.getById(sid, false);
            if (user != null) {
                if (fullName != null && !fullName.trim().isEmpty()) {
                    user.setFullName(fullName.trim());
                }
                if (email != null && !email.trim().isEmpty()) {
                    try {
                        ClassLoader uberCl = Jenkins.get().getPluginManager().uberClassLoader;
                        Class<?> mailerPropClass = Class.forName("hudson.tasks.Mailer$UserProperty", true, uberCl);
                        java.lang.reflect.Constructor<?> ctor = mailerPropClass.getConstructor(String.class);
                        hudson.model.UserProperty prop = (hudson.model.UserProperty) ctor.newInstance(email.trim());
                        user.addProperty(prop);
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Could not set email for user " + sid, e);
                    }
                }
                user.save();
            }
            // Auto-grant Hudson.Read so user can log in and change their password
            grantGlobalRead(sid, AuthorizationType.USER);
            // Set force-password-change flag if requested
            if (forcePasswordChange && user != null) {
                user.addProperty(new OmniAuthForcePasswordProperty(true));
                user.save();
            }
            // Store temp password in session — read once by userDetail, then cleared
            req.getSession().setAttribute("omniauth.tmpPwd", tmpPwd);
            req.getSession().setAttribute("omniauth.tmpPwdSid", sid);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logUserCreated(Jenkins.getAuthentication2().getName(), sid);
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=USER&newUser=true&mustChange=" + forcePasswordChange);
        } else if ("ENTRA".equalsIgnoreCase(userType)) {
            // Pre-provision Entra user: create the Jenkins User object + placeholder property + Hudson.Read,
            // mirroring the native flow so the SSO gate can confirm they were admin-added.
            User entraUser = User.getOrCreateByIdOrFullName(sid);
            entraUser.setFullName(sid);
            OmniAuthUserProperty placeholder = new OmniAuthUserProperty(null, sid);
            placeholder.setProvisioningSource("INDIVIDUAL");
            try {
                entraUser.addProperty(placeholder);
                entraUser.save();
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Could not save OmniAuthUserProperty for Entra pre-provision: " + sid, e);
            }
            grantGlobalRead(sid, AuthorizationType.USER);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logUserCreated(Jenkins.getAuthentication2().getName(), sid);
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=USER&preProvisioned=true");
        } else if ("GROUP".equalsIgnoreCase(userType)) {
            // sid is the group OID here
            String groupOid   = sid;
            String groupLabel = req.getParameter("groupLabel");
            if (groupLabel != null) groupLabel = groupLabel.trim();
            OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
            if (assignmentConfig == null) {
                rsp.sendRedirect("accessManagement?error=configError"); return;
            }
            if (assignmentConfig.hasGroup(groupOid)) {
                rsp.sendRedirect("accessManagement?error=groupAlreadyExists"); return;
            }
            String now = java.time.Instant.now().toString();
            String addedBy = Jenkins.getAuthentication2().getName();
            OmniAuthGroupEntity groupEntity = new OmniAuthGroupEntity(groupOid, groupLabel, now, addedBy);
            assignmentConfig.addGroup(groupEntity);
            // Grant Hudson.Read at GROUP level so members can log in
            grantGlobalRead(groupOid, AuthorizationType.GROUP);
            OmniAuthAuditLog audit = OmniAuthAuditLog.get();
            if (audit != null) audit.logUserCreated(addedBy, "[GROUP] " + groupOid);
            rsp.sendRedirect("groupDetail?oid=" + enc(groupOid) + "&added=true");
        } else {
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=USER");
        }
    }

    /** Removes a GROUP entity from Access Management and revokes sessions for affected members. */
    public void doRemoveGroup(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String groupOid = req.getParameter("oid");
        if (groupOid == null || groupOid.trim().isEmpty()) {
            rsp.sendRedirect("accessManagement?error=missing"); return;
        }
        groupOid = groupOid.trim();
        OmniAuthAssignmentConfig assignmentConfig = OmniAuthAssignmentConfig.get();
        if (assignmentConfig == null) {
            rsp.sendRedirect("accessManagement?error=configError"); return;
        }

        // Find all VIA_ENTRA_GROUP users whose activeGroupOids contains this OID
        // Revoke sessions for those who have no remaining active groups after removal
        try (hudson.security.ACLContext ignored = hudson.security.ACL.as2(hudson.security.ACL.SYSTEM2)) {
            for (hudson.model.User user : hudson.model.User.getAll()) {
                OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
                if (prop == null || !prop.isViaGroup()) continue;
                if (!prop.getActiveGroupOids().contains(groupOid)) continue;

                List<String> remaining = new ArrayList<>(prop.getActiveGroupOids());
                remaining.remove(groupOid);

                if (remaining.isEmpty()) {
                    // No other groups — revoke all active sessions for this user immediately
                    String uid = user.getId();
                    ActiveSessionManager.getAll().stream()
                            .filter(s -> uid.equals(s.getUserId()))
                            .forEach(s -> ActiveSessionManager.revoke(s.getSessionId()));
                    LOGGER.log(Level.INFO, "Session revoked for {0} — group {1} removed",
                            new Object[]{uid, groupOid});
                }

                // Update activeGroupOids
                try {
                    OmniAuthUserProperty updated = new OmniAuthUserProperty(
                            prop.getEntraObjectId(), prop.getEntraUpn());
                    updated.setProvisioningSource("VIA_ENTRA_GROUP");
                    updated.setActiveGroupOids(remaining);
                    updated.setLastLoginAt(prop.getLastLoginAt());
                    updated.setGroupsLastSynced(prop.getGroupsLastSynced());
                    updated.setCachedGroups(new ArrayList<>(prop.getCachedGroups()));
                    user.addProperty(updated);
                    user.save();
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Could not update activeGroupOids for " + user.getId(), e);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error processing group removal sessions", e);
        }

        // Remove all GROUP assignments for this OID
        final String finalGroupOid = groupOid;
        List<OmniAuthAssignment> toRemove = assignmentConfig.getAssignments().stream()
                .filter(a -> "GROUP".equalsIgnoreCase(a.getAuthType()) && finalGroupOid.equals(a.getUserId()))
                .toList();
        for (OmniAuthAssignment a : toRemove) {
            assignmentConfig.removeAssignment(finalGroupOid, "GROUP", a.getScope());
        }

        // Remove Hudson.Read grant for this group from global matrix by rebuilding without that entry
        try {
            hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
            if (strat instanceof OmniAuthAuthorizationStrategy) {
                OmniAuthAuthorizationStrategy current = (OmniAuthAuthorizationStrategy) strat;
                OmniAuthAuthorizationStrategy rebuilt = new OmniAuthAuthorizationStrategy();
                for (Map.Entry<Permission, Set<PermissionEntry>> e : current.getGrantedPermissionEntries().entrySet()) {
                    for (PermissionEntry pe : e.getValue()) {
                        if (!pe.getSid().equals(groupOid)) {
                            rebuilt.add(e.getKey(), pe);
                        }
                    }
                }
                Jenkins.get().setAuthorizationStrategy(rebuilt);
                Jenkins.get().save();
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not remove Hudson.Read for group " + groupOid, e);
        }

        // Remove the group entity
        assignmentConfig.removeGroup(groupOid);

        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) audit.logUserCreated(Jenkins.getAuthentication2().getName(), "[GROUP REMOVED] " + groupOid);

        rsp.sendRedirect("accessManagement?groupRemoved=true");
    }

    private void grantGlobalRead(String sid, AuthorizationType atype) {
        try {
            hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
            if (!(strat instanceof OmniAuthAuthorizationStrategy)) return;
            OmniAuthAuthorizationStrategy omniStrat = (OmniAuthAuthorizationStrategy) strat;
            Permission readPerm = Permission.fromId("hudson.model.Hudson.Read");
            if (readPerm == null) return;
            PermissionEntry entry = new PermissionEntry(atype, sid);
            omniStrat.add(readPerm, entry);
            Jenkins.get().save();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not auto-grant Hudson.Read to " + sid, e);
        }
    }

    /** Called from userDetail.jelly — reads the one-time temp password from session. */
    public String getTempPassword() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return null;
        Object pwd = req.getSession().getAttribute("omniauth.tmpPwd");
        Object psid = req.getSession().getAttribute("omniauth.tmpPwdSid");
        String currentSid = req.getParameter("sid");
        if (pwd != null && psid != null && psid.toString().equals(currentSid)) {
            req.getSession().removeAttribute("omniauth.tmpPwd");
            req.getSession().removeAttribute("omniauth.tmpPwdSid");
            return pwd.toString();
        }
        return null;
    }

    private static String generateTempPassword() {
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%";
        java.security.SecureRandom rng = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder(14);
        for (int i = 0; i < 14; i++) sb.append(chars.charAt(rng.nextInt(chars.length())));
        return sb.toString();
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

    private static String resolveDisplayName(String sid, AuthorizationType type) {
        if (type == AuthorizationType.USER) {
            User u = User.getById(sid, false);
            if (u != null && u.getFullName() != null && !u.getFullName().equals(sid)) {
                return u.getFullName();
            }
        } else if (type == AuthorizationType.GROUP) {
            OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
            if (config != null) {
                OmniAuthGroupEntity group = config.findGroup(sid);
                if (group != null) return group.getEffectiveName();
            }
        }
        return sid;
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

        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        Set<String> userGroupOids = new HashSet<>();
        OmniAuthUserProperty ep = user.getProperty(OmniAuthUserProperty.class);
        if (ep != null) userGroupOids.addAll(ep.getActiveGroupOids());

        List<Job> allJobs = Jenkins.get().getAllItems(Job.class);

        try (ACLContext ignored = ACL.as2(auth)) {
            for (Job job : allJobs) {
                if (result.size() >= JOB_ACCESS_CAP) break;
                boolean read      = job.hasPermission(Item.READ);
                boolean build     = job.hasPermission(Item.BUILD);
                boolean configure = job.hasPermission(Item.CONFIGURE);
                boolean delete    = job.hasPermission(Item.DELETE);
                boolean workspace = job.hasPermission(Item.WORKSPACE);
                if (read || build || configure) {
                    String source = detectSource(job, userId, userGroupOids, auth, config);
                    result.add(new JobAccessInfo(job.getFullName(), read, build, configure, delete, workspace, source));
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning job access for user: " + userId, e);
        }

        result.sort((a, b) -> a.getJobName().compareToIgnoreCase(b.getJobName()));
        return result;
    }

    @SuppressWarnings("rawtypes")
    private static String detectSource(Job job, String userId,
                                        Set<String> userGroupOids,
                                        Authentication auth,
                                        OmniAuthAssignmentConfig config) {
        String jobFullName = job.getFullName();
        if (config != null) {
            for (OmniAuthAssignment a : config.getAssignmentsForUser(userId, "USER")) {
                if (!a.isExpired() && omniAuthCovers(a, jobFullName)) return "OmniAuth";
            }
            for (String gOid : userGroupOids) {
                for (OmniAuthAssignment a : config.getAssignmentsForUser(gOid, "GROUP")) {
                    if (!a.isExpired() && omniAuthCovers(a, jobFullName)) return "OmniAuth";
                }
            }
        }
        // Check job itself (already have the object — no lookup needed)
        if (hasMatrixGrant(job, auth)) return "Direct";
        // Check folder ancestors — use SYSTEM context to avoid recursive hasPermission2
        try {
            Jenkins j = Jenkins.getInstanceOrNull();
            if (j != null) {
                String path = jobFullName;
                int sep = path.lastIndexOf('/');
                while (sep > 0) {
                    path = path.substring(0, sep);
                    final String p = path;
                    hudson.model.AbstractItem folder;
                    try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
                        folder = j.getItemByFullName(p, hudson.model.AbstractItem.class);
                    }
                    if (folder != null && hasMatrixGrant(folder, auth)) return "Direct";
                    sep = path.lastIndexOf('/');
                }
            }
        } catch (Exception ignored) {}
        return "Global";
    }

    private static boolean omniAuthCovers(OmniAuthAssignment a, String jobFullName) {
        String scope = a.getScope();
        if (scope.isEmpty()) return true;
        if ("FOLDER".equals(a.getScopeType())) {
            return jobFullName.equals(scope) || jobFullName.startsWith(scope + "/");
        }
        return jobFullName.equals(scope);
    }

    private static boolean hasMatrixGrant(hudson.model.AbstractItem item, Authentication auth) {
        if (!(item instanceof hudson.model.Job)) return false;
        hudson.model.Job<?,?> job = (hudson.model.Job<?,?>) item;
        for (hudson.model.JobProperty<?> prop : job.getAllProperties()) {
            if (prop instanceof hudson.security.AuthorizationMatrixProperty) {
                hudson.security.SidACL sidAcl =
                        ((hudson.security.AuthorizationMatrixProperty) prop).getACL();
                return sidAcl != null && sidAcl.hasPermission2(auth, Item.READ);
            }
        }
        return false;
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

        // Extended fields
        private String provisioningSource; // NATIVE, INDIVIDUAL, VIA_ENTRA_GROUP
        private String entraUpn;
        private String groupName;          // effective group name if VIA_ENTRA_GROUP
        private String groupOid;           // OID of the group
        private boolean activeGroupUser;
        private boolean staleWarning;

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

        public String getProvisioningSource()        { return provisioningSource != null ? provisioningSource : "NATIVE"; }
        public void setProvisioningSource(String s)  { this.provisioningSource = s; }
        public String getEntraUpn()                  { return entraUpn; }
        public void setEntraUpn(String s)            { this.entraUpn = s; }
        public String getGroupName()                 { return groupName; }
        public void setGroupName(String s)           { this.groupName = s; }
        public String getGroupOid()                  { return groupOid; }
        public void setGroupOid(String s)            { this.groupOid = s; }
        public boolean isActiveGroupUser()           { return activeGroupUser; }
        public void setActiveGroupUser(boolean b)    { this.activeGroupUser = b; }
        public boolean isStaleWarning()              { return staleWarning; }
        public void setStaleWarning(boolean b)       { this.staleWarning = b; }

        private boolean pendingDeletion;
        public boolean isPendingDeletion()           { return pendingDeletion; }
        public void setPendingDeletion(boolean b)    { this.pendingDeletion = b; }

        private LoginEvent latestEvent;
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
        private String pendingReason; // null = not pending; "Group access revoked" or "Manually marked"

        public UserInfo(String userId, String fullName, String userType,
                        String lastLoginAt, String entraOid) {
            this.userId      = userId;
            this.fullName    = fullName;
            this.userType    = userType;
            this.lastLoginAt = lastLoginAt;
            this.entraOid    = entraOid;
        }

        public String getUserId()        { return userId; }
        public String getFullName()      { return fullName; }
        public String getUserType()      { return userType; }
        public String getLastLoginAt()   { return lastLoginAt; }
        public String getEntraOid()      { return entraOid; }
        public boolean isNeverLoggedIn() { return lastLoginAt == null; }
        public String getPendingReason() { return pendingReason; }
        public void setPendingReason(String r) { this.pendingReason = r; }
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
        private String groupName;
        private String groupOid;
        private String provisioningSource;
        private List<GrantDisplay> omniAuthGrants;

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
        public String getGroupName()               { return groupName; }
        public void setGroupName(String s)         { this.groupName = s; }
        public String getGroupOid()                { return groupOid; }
        public void setGroupOid(String s)          { this.groupOid = s; }
        public String getProvisioningSource()      { return provisioningSource != null ? provisioningSource : "NATIVE"; }
        public void setProvisioningSource(String s){ this.provisioningSource = s; }
        public boolean isViaGroup()                { return "VIA_ENTRA_GROUP".equals(provisioningSource); }
        public List<GrantDisplay> getOmniAuthGrants() { return omniAuthGrants != null ? omniAuthGrants : Collections.emptyList(); }
        public void setOmniAuthGrants(List<GrantDisplay> grants) { this.omniAuthGrants = grants; }
        public boolean isPerJobSupported() {
            return authStrategy != null &&
                   (authStrategy.toLowerCase().contains("projectmatrix") ||
                    authStrategy.toLowerCase().contains("omniauth"));
        }
    }

    public static final class JobAccessInfo {
        private final String jobName;
        private final boolean canRead;
        private final boolean canBuild;
        private final boolean canConfigure;
        private final boolean canDelete;
        private final boolean canWorkspace;
        private final String source;

        public JobAccessInfo(String jobName, boolean canRead, boolean canBuild, boolean canConfigure,
                             boolean canDelete, boolean canWorkspace, String source) {
            this.jobName      = jobName;
            this.canRead      = canRead;
            this.canBuild     = canBuild;
            this.canConfigure = canConfigure;
            this.canDelete    = canDelete;
            this.canWorkspace = canWorkspace;
            this.source       = source != null ? source : "Global";
        }

        public String getJobName()       { return jobName; }
        public boolean isCanRead()       { return canRead; }
        public boolean isCanBuild()      { return canBuild; }
        public boolean isCanConfigure()  { return canConfigure; }
        public boolean isCanDelete()     { return canDelete; }
        public boolean isCanWorkspace()  { return canWorkspace; }
        public String getSource()        { return source; }
    }

    public static final class GrantDisplay {
        private final String principalType;
        private final String principalId;
        private final String principalName;
        private final String roleId;
        private final String roleName;
        private final String scope;
        private final String scopeType;
        private final String expiresAt;
        private final boolean expired;

        public GrantDisplay(String principalType, String principalId, String principalName,
                            String roleId, String roleName, String scope, String scopeType,
                            String expiresAt, boolean expired) {
            this.principalType = principalType;
            this.principalId   = principalId;
            this.principalName = principalName;
            this.roleId        = roleId;
            this.roleName      = roleName;
            this.scope         = scope;
            this.scopeType     = scopeType;
            this.expiresAt     = expiresAt;
            this.expired       = expired;
        }

        public String getPrincipalType() { return principalType; }
        public String getPrincipalId()   { return principalId; }
        public String getPrincipalName() { return principalName; }
        public String getRoleId()        { return roleId; }
        public String getRoleName()      { return roleName; }
        public String getScope()         { return scope; }
        public String getScopeType()     { return scopeType; }
        public String getExpiresAt()     { return expiresAt; }
        public boolean isExpired()       { return expired; }
        public boolean isGlobal()        { return scope == null || scope.isEmpty(); }
        public String getScopeDisplay()  {
            if (scope == null || scope.isEmpty()) return "Global";
            return scope;
        }
        public String getScopeTypeDisplay() {
            if (scope == null || scope.isEmpty()) return "Global";
            if ("FOLDER".equals(scopeType)) return "Folder";
            if ("JOB".equals(scopeType)) return "Job";
            return scopeType;
        }
    }

    private static final class LastJobInfo {
        final String jobName;
        final String triggeredAt;
        LastJobInfo(String jobName, String triggeredAt) {
            this.jobName     = jobName;
            this.triggeredAt = triggeredAt;
        }
    }

    public enum AccessRole {
        ADMIN(
            "hudson.model.Hudson.Administer"
        ),
        DEVELOPER(
            "hudson.model.Hudson.Read",
            "hudson.model.Item.Build",
            "hudson.model.Item.Cancel",
            "hudson.model.Item.Configure",
            "hudson.model.Item.Create",
            "hudson.model.Item.Delete",
            "hudson.model.Item.Move",
            "hudson.model.Item.Read",
            "hudson.model.Item.WipeOut",
            "hudson.model.View.Configure",
            "hudson.model.View.Create",
            "hudson.model.View.Delete",
            "hudson.model.View.Read",
            "hudson.model.Run.Delete",
            "hudson.model.Run.Update"
        ),
        VIEWER(
            "hudson.model.Hudson.Read",
            "hudson.model.Item.Read",
            "hudson.model.View.Read"
        ),
        CUSTOM();

        public final Set<String> permissionIds;

        AccessRole(String... ids) {
            this.permissionIds = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(ids)));
        }

        public static AccessRole infer(Set<String> userPerms) {
            Set<String> s = new HashSet<>(userPerms);
            if (s.equals(ADMIN.permissionIds))     return ADMIN;
            if (s.equals(DEVELOPER.permissionIds)) return DEVELOPER;
            if (s.equals(VIEWER.permissionIds))    return VIEWER;
            return CUSTOM;
        }
    }

    public static final class AccessManagementUserInfo {
        private final String sid;
        private final String displayName;
        private final AuthorizationType type;
        private final String roleName;
        private final Set<String> permissionIds;
        private final String lastLoginAt;
        private String provisioningSource = "NATIVE";
        private boolean hasReviewDue = false;

        public AccessManagementUserInfo(String sid, String displayName, AuthorizationType type,
                                        String roleName, Set<String> permissionIds, String lastLoginAt) {
            this.sid           = sid;
            this.displayName   = displayName;
            this.type          = type;
            this.roleName      = roleName;
            this.permissionIds = permissionIds;
            this.lastLoginAt   = lastLoginAt;
        }

        public String getSid()             { return sid; }
        public String getDisplayName()     { return displayName; }
        public AuthorizationType getType() { return type; }
        public String getRoleName()        { return roleName; }
        public Set<String> getPermissionIds() { return permissionIds; }
        public String getLastLoginAt()     { return lastLoginAt; }
        public boolean isUserEntry()       { return type == AuthorizationType.USER; }
        public String getProvisioningSource()       { return provisioningSource; }
        public void setProvisioningSource(String s) { this.provisioningSource = s != null ? s : "NATIVE"; }
        public boolean isGroupManaged()             { return "VIA_ENTRA_GROUP".equals(provisioningSource); }
        public boolean isHasReviewDue()             { return hasReviewDue; }
        public void setHasReviewDue(boolean v)      { this.hasReviewDue = v; }

        public String getAvatarLetter() {
            String src = (displayName != null && !displayName.equals(sid)) ? displayName : sid;
            return src != null && !src.isEmpty() ? src.substring(0, 1).toUpperCase() : "?";
        }

        public String getRelativeLastLogin() {
            return lastLoginAt != null ? OmniAuthManagementLink.relativeTime(lastLoginAt) : null;
        }

        public String getPermissionsJson() {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String id : permissionIds) {
                if (!first) sb.append(",");
                sb.append("\"").append(id.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
                first = false;
            }
            return sb.append("]").toString();
        }
    }

    public static final class PermissionGroupInfo {
        private final String groupName;
        private final String subtitle;
        private final List<PermissionInfo> permissions;
        public PermissionGroupInfo(String groupName, String subtitle, List<PermissionInfo> permissions) {
            this.groupName = groupName;
            this.subtitle = subtitle != null ? subtitle : "";
            this.permissions = permissions;
        }
        public String getGroupName()                { return groupName; }
        public String getSubtitle()                 { return subtitle; }
        public List<PermissionInfo> getPermissions() { return permissions; }
    }

    public static final class PermissionInfo {
        private final String id;
        private final String name;
        private final String shortId;
        public PermissionInfo(String id, String name) {
            this.id = id;
            this.name = name;
            // e.g. "hudson.model.Item.Build" → "Item.Build"
            int last = id.lastIndexOf('.');
            int prev = last > 0 ? id.lastIndexOf('.', last - 1) : -1;
            this.shortId = prev >= 0 ? id.substring(prev + 1) : id;
        }
        public String getId()      { return id; }
        public String getName()    { return name; }
        public String getShortId() { return shortId; }
    }

    // =========================================================================
    // User-centric hierarchy view
    // =========================================================================

    public void doCheckAccess(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid = req.getParameter("sid");
        if (sid != null) {
            User u = User.getById(sid, false);
            if (u != null) {
                OmniAuthUserProperty ep = u.getProperty(OmniAuthUserProperty.class);
                if (ep != null && ep.isPendingDeletion()) {
                    rsp.sendRedirect(req.getContextPath() + "/manage/omniauth-management/userStatus?info=pendingDeletion");
                    return;
                }
            }
        }
        req.getView(this, "userDetail.jelly").forward(req, rsp);
    }

    public void doGroupDetail(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "groupDetail.jelly").forward(req, rsp);
    }

    /** Returns all GROUP entities for display in Access Management. */
    public List<OmniAuthGroupEntity> getGroupList() {
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null) return Collections.emptyList();
        return config.getGroups();
    }

    /** Returns users provisioned via a specific group OID. */
    public List<UserStatusInfo> getGroupMembers(String groupOid) {
        List<UserStatusInfo> members = new ArrayList<>();
        try (hudson.security.ACLContext ignored = hudson.security.ACL.as2(hudson.security.ACL.SYSTEM2)) {
            for (hudson.model.User user : hudson.model.User.getAll()) {
                OmniAuthUserProperty prop = user.getProperty(OmniAuthUserProperty.class);
                if (prop != null && prop.isViaGroup() && prop.getActiveGroupOids().contains(groupOid)) {
                    String lastLogin = prop.getLastLoginAt();
                    members.add(new UserStatusInfo(user.getId(), user.getFullName(), "Entra", lastLogin, null, null, "active"));
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error fetching group members for " + groupOid, e);
        }
        return members;
    }

    /** Returns the OmniAuthGroupEntity for a given OID — used by groupDetail.jelly. */
    public OmniAuthGroupEntity getGroupEntity() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return null;
        String oid = req.getParameter("oid");
        if (oid == null) return null;
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        return config != null ? config.findGroup(oid) : null;
    }

    /** Returns the user hierarchy as a flat list of TreeRow objects (with depth + inherited info). */
    public List<TreeRow> getUserHierarchyFlat() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return Collections.emptyList();
        String sid = req.getParameter("sid");
        String type = req.getParameter("type");
        if (sid == null) return Collections.emptyList();
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        TreeNode root = buildHierarchy(sid, atype);
        List<TreeRow> rows = new ArrayList<>();
        flattenTree(root, 0, null, null, rows);
        return rows;
    }

    /** Returns minimal info about the user being inspected (for the userDetail header). */
    public AccessManagementUserInfo getUserDetailHeader() {
        org.kohsuke.stapler.StaplerRequest2 req = org.kohsuke.stapler.Stapler.getCurrentRequest2();
        if (req == null) return null;
        String sid = req.getParameter("sid");
        String type = req.getParameter("type");
        if (sid == null) return null;
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        // Reuse the access-management list and filter
        for (AccessManagementUserInfo info : getAccessManagementUserList()) {
            if (info.getSid().equals(sid) && info.getType() == atype) return info;
        }
        // Build a minimal placeholder if not found in the list (e.g. user being added)
        String display = resolveDisplayName(sid, atype);
        String ps = "NATIVE";
        if (atype == AuthorizationType.USER) {
            User u2 = User.getById(sid, false);
            if (u2 != null) {
                OmniAuthUserProperty ep2 = u2.getProperty(OmniAuthUserProperty.class);
                if (ep2 != null) ps = ep2.getProvisioningSource();
            }
        }
        AccessManagementUserInfo placeholder = new AccessManagementUserInfo(sid, display, atype, "NONE",
                Collections.emptySet(), null);
        placeholder.setProvisioningSource(ps);
        return placeholder;
    }

    private TreeNode buildHierarchy(String sid, AuthorizationType atype) {
        TreeNode root = new TreeNode("", "Jenkins (root)", "root");

        // Direct grants at root come from the OmniAuthAuthorizationStrategy (global)
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (strat instanceof GlobalMatrixAuthorizationStrategy) {
            Set<String> rootPerms = collectDirectPermsForUser(
                    ((GlobalMatrixAuthorizationStrategy) strat).getGrantedPermissionEntries(), sid, atype);
            root.directPerms = new ArrayList<>(rootPerms);
            root.directRole = inferRoleAtRoot(rootPerms);
        }

        // Recurse top-level items
        for (Item item : Jenkins.get().getItems()) {
            TreeNode child = buildItemNode(item, sid, atype);
            if (child != null) root.children.add(child);
        }

        // Compute effective role with simple inheritance: directRole or parent.effectiveRole
        computeEffectiveRoles(root, null);
        return root;
    }

    private TreeNode buildItemNode(Item item, String sid, AuthorizationType atype) {
        boolean isGroup = item instanceof ItemGroup;
        boolean isJob   = item instanceof Job;
        String type = isGroup ? "folder" : (isJob ? "job" : "other");
        TreeNode node = new TreeNode(item.getFullName(), item.getName(), type);

        Set<String> direct = new HashSet<>();
        if (isJob) {
            hudson.security.AuthorizationMatrixProperty prop =
                    ((Job<?, ?>) item).getProperty(hudson.security.AuthorizationMatrixProperty.class);
            if (prop != null) {
                direct.addAll(collectDirectPermsForUser(prop.getGrantedPermissionEntries(), sid, atype));
            }
        }
        if (item instanceof AbstractFolder) {
            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                    ((AbstractFolder<?>) item).getProperties().get(
                            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
            if (fp != null) {
                direct.addAll(collectDirectPermsForUser(fp.getGrantedPermissionEntries(), sid, atype));
            }
        }
        node.directPerms = new ArrayList<>(direct);
        node.directRole = inferRoleAtItem(direct);

        if (isGroup) {
            for (Object child : ((ItemGroup<?>) item).getItems()) {
                TreeNode cn = buildItemNode((Item) child, sid, atype);
                if (cn != null) node.children.add(cn);
            }
        }
        return node;
    }

    private static Set<String> collectDirectPermsForUser(
            Map<Permission, Set<PermissionEntry>> entries, String sid, AuthorizationType atype) {
        Set<String> out = new HashSet<>();
        for (Map.Entry<Permission, Set<PermissionEntry>> e : entries.entrySet()) {
            for (PermissionEntry pe : e.getValue()) {
                if (pe.getSid().equals(sid) && pe.getType() == atype) {
                    out.add(e.getKey().getId());
                }
            }
        }
        return out;
    }

    private static String inferRoleAtRoot(Set<String> perms) {
        if (perms == null || perms.isEmpty()) return null;
        AccessRole r = AccessRole.infer(perms);
        return r.name();
    }

    private static String inferRoleAtItem(Set<String> perms) {
        if (perms == null || perms.isEmpty()) return null;
        if (perms.equals(ScopedRole.CONFIGURE.permissionIds)) return "CONFIGURE";
        if (perms.equals(ScopedRole.BUILD.permissionIds))     return "BUILD";
        if (perms.equals(ScopedRole.READ.permissionIds))      return "READ";
        return "CUSTOM";
    }

    private void computeEffectiveRoles(TreeNode node, String parentEffective) {
        node.effectiveRole = node.directRole != null ? node.directRole : parentEffective;
        for (TreeNode child : node.children) {
            computeEffectiveRoles(child, node.effectiveRole);
        }
    }

    private void flattenTree(TreeNode node, int depth, String parentEffective,
                             String parentEffectivePath, List<TreeRow> out) {
        TreeRow row = new TreeRow();
        row.node = node;
        row.depth = depth;
        row.inheritedRole = (node.directRole == null) ? parentEffective : null;
        row.inheritedFromPath = (node.directRole == null) ? parentEffectivePath : null;
        out.add(row);
        String childInheritRole = node.directRole != null ? node.directRole : parentEffective;
        String childInheritPath = node.directRole != null ? node.path : parentEffectivePath;
        for (TreeNode child : node.children) {
            flattenTree(child, depth + 1, childInheritRole, childInheritPath, out);
        }
    }

    // ─── POST: Set role at any node (root, folder, job) ─────────────────────

    @POST
    public void doSetNodePermission(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid  = req.getParameter("sid");
        String type = req.getParameter("type");
        String path = req.getParameter("path");      // "" for root
        String role = req.getParameter("role");      // ADMIN/DEVELOPER/VIEWER/CUSTOM at root, or CONFIGURE/BUILD/READ at items

        if (sid == null || sid.trim().isEmpty() || role == null) {
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=missing");
            return;
        }
        sid = sid.trim();
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        // Resolve target permission set
        Set<String> permIds;
        if (path == null || path.isEmpty()) {
            // Root: AccessRole bucket
            try {
                permIds = AccessRole.valueOf(role.toUpperCase()).permissionIds;
            } catch (IllegalArgumentException ex) {
                rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=invalidRole");
                return;
            }
            if (permIds.isEmpty()) {
                rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=noPermissions");
                return;
            }
            applyRootPermissions(sid, atype, permIds, rsp, false);
        } else {
            // Item: ScopedRole bucket
            try {
                permIds = ScopedRole.valueOf(role.toUpperCase()).permissionIds;
            } catch (IllegalArgumentException ex) {
                rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=invalidRole");
                return;
            }
            Item item = Jenkins.get().getItemByFullName(path);
            if (item == null) {
                rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=notFound");
                return;
            }
            applyItemPermissions(item, sid, atype, permIds);
            autoGrantParentRead(item, sid, atype);
        }
        rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&saved=true");
    }

    @POST
    public void doRemoveNodePermission(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String sid  = req.getParameter("sid");
        String type = req.getParameter("type");
        String path = req.getParameter("path");

        if (sid == null) {
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&error=missing");
            return;
        }
        AuthorizationType atype = "GROUP".equalsIgnoreCase(type)
                ? AuthorizationType.GROUP : AuthorizationType.USER;

        if (path == null || path.isEmpty()) {
            // Remove all global (root) grants
            applyRootPermissions(sid, atype, Collections.emptySet(), rsp, true);
        } else {
            Item item = Jenkins.get().getItemByFullName(path);
            if (item != null) {
                applyItemPermissions(item, sid, atype, Collections.emptySet());
                cleanupParentRead(item, sid, atype);
            }
            rsp.sendRedirect("userDetail?sid=" + enc(sid) + "&type=" + enc(type) + "&saved=true");
        }
    }

    /** Rebuild the global OmniAuthAuthorizationStrategy with this user's permissions replaced. */
    private void applyRootPermissions(String sid, AuthorizationType atype, Set<String> permIds,
                                      StaplerResponse rsp, boolean removing) throws Exception {
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (!(strat instanceof OmniAuthAuthorizationStrategy)) {
            rsp.sendRedirect(detailUrl(sid, atype, "error=notOmniAuth"));
            return;
        }
        OmniAuthAuthorizationStrategy current = (OmniAuthAuthorizationStrategy) strat;
        OmniAuthAuthorizationStrategy rebuilt = new OmniAuthAuthorizationStrategy();
        for (Map.Entry<Permission, Set<PermissionEntry>> e : current.getGrantedPermissionEntries().entrySet()) {
            for (PermissionEntry pe : e.getValue()) {
                if (!(pe.getSid().equals(sid) && pe.getType() == atype)) {
                    rebuilt.add(e.getKey(), pe);
                }
            }
        }
        if (!permIds.isEmpty()) {
            PermissionEntry entry = atype == AuthorizationType.GROUP
                    ? PermissionEntry.group(sid) : PermissionEntry.user(sid);
            for (String pid : permIds) {
                Permission p = Permission.fromId(pid);
                if (p != null) rebuilt.add(p, entry);
            }
        }
        Set<PermissionEntry> adminSet = rebuilt.getGrantedPermissionEntries().get(Jenkins.ADMINISTER);
        if (adminSet == null || adminSet.isEmpty()) {
            rsp.sendRedirect(detailUrl(sid, atype, "error=lastAdmin"));
            return;
        }
        Jenkins.get().setAuthorizationStrategy(rebuilt);
        Jenkins.get().save();
        rsp.sendRedirect(detailUrl(sid, atype, "saved=true"));
    }

    private String detailUrl(String sid, AuthorizationType atype, String extra) {
        if (atype == AuthorizationType.GROUP) {
            return "groupDetail?oid=" + enc(sid) + (extra != null ? "&" + extra : "");
        }
        return "userDetail?sid=" + enc(sid) + "&type=USER" + (extra != null ? "&" + extra : "");
    }

    /**
     * Apply permissions on a Job or Folder. permIds.isEmpty() means remove all grants for this user.
     * Global-scope permissions (Hudson.Read, View.Read, etc.) are routed to the global strategy;
     * only item-scoped permissions are written into the job/folder property.
     */
    @SuppressWarnings("unchecked")
    private void applyItemPermissions(Item item, String sid, AuthorizationType atype, Set<String> permIds) throws Exception {
        PermissionEntry entry = atype == AuthorizationType.GROUP
                ? PermissionEntry.group(sid) : PermissionEntry.user(sid);

        // Only item/run-scoped permissions belong in a job/folder property.
        // Global-scope permissions (Hudson.Read, View.Read) are silently ignored here —
        // login access is managed separately via Add User / global grants.
        Set<String> itemPermIds = new HashSet<>();
        for (String pid : permIds) {
            Permission p = Permission.fromId(pid);
            if (p != null && p.isContainedBy(hudson.security.PermissionScope.ITEM)) {
                itemPermIds.add(pid);
            }
        }
        // For revoke (permIds empty), effectivePerms stays empty → mutate removes all for this user.
        Set<String> effectivePermIds = permIds.isEmpty() ? Collections.emptySet() : itemPermIds;

        if (item instanceof Job) {
            Job<?, ?> job = (Job<?, ?>) item;
            hudson.security.AuthorizationMatrixProperty prop =
                    job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            if (prop == null) {
                if (effectivePermIds.isEmpty()) return;
                Map<Permission, Set<PermissionEntry>> map = new HashMap<>();
                for (String pid : effectivePermIds) {
                    Permission p = Permission.fromId(pid);
                    if (p != null) map.computeIfAbsent(p, k -> new HashSet<>()).add(entry);
                }
                prop = new hudson.security.AuthorizationMatrixProperty(map,
                        new org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy());
                job.addProperty(prop);
            } else {
                mutateGrantedPermissions(prop, sid, atype, entry, effectivePermIds);
            }
            job.save();
            return;
        }

        if (item instanceof AbstractFolder) {
            AbstractFolder<?> folder = (AbstractFolder<?>) item;
            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                    folder.getProperties().get(
                            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
            if (fp == null) {
                if (effectivePermIds.isEmpty()) return;
                fp = new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(
                        new java.util.HashMap<>());
                folder.addProperty(fp);
            }
            mutateGrantedPermissions(fp, sid, atype, entry, effectivePermIds);
            folder.save();
        }
    }

    /** Ensures a single global-scope permission exists in the global strategy (idempotent). */
    private void applyGlobalPermission(String sid, AuthorizationType atype, PermissionEntry entry, Permission perm) {
        hudson.security.AuthorizationStrategy strat = Jenkins.get().getAuthorizationStrategy();
        if (!(strat instanceof OmniAuthAuthorizationStrategy)) return;
        OmniAuthAuthorizationStrategy strategy = (OmniAuthAuthorizationStrategy) strat;
        strategy.add(perm, entry);
        try { Jenkins.get().save(); } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to save global strategy after adding " + perm.getId() + " for " + sid, e);
        }
    }

    /**
     * Mutates the grantedPermissions map of an AuthorizationMatrixProperty in-place via reflection.
     * This avoids the addProperty/removeProperty unreliability on WorkflowJob and folders.
     * If atype is null, removes entries for sid regardless of type (used for purge).
     * entry may be null when permIds is empty (remove-only operation).
     */
    @SuppressWarnings("unchecked")
    private void mutateGrantedPermissions(Object prop, String sid, AuthorizationType atype,
                                           PermissionEntry entry, Set<String> permIds) throws Exception {
        java.lang.reflect.Field gpField = null;
        Class<?> cls = prop.getClass();
        while (cls != null && gpField == null) {
            try { gpField = cls.getDeclaredField("grantedPermissions"); }
            catch (NoSuchFieldException e) { cls = cls.getSuperclass(); }
        }
        if (gpField == null)
            throw new Exception("grantedPermissions field not found on " + prop.getClass().getName());
        gpField.setAccessible(true);
        Map<Permission, Set<PermissionEntry>> gp =
                (Map<Permission, Set<PermissionEntry>>) gpField.get(prop);
        for (Set<PermissionEntry> pes : gp.values()) {
            pes.removeIf(pe -> pe.getSid().equals(sid) && (atype == null || pe.getType() == atype));
        }
        gp.entrySet().removeIf(e -> e.getValue().isEmpty());
        for (String pid : permIds) {
            Permission p = Permission.fromId(pid);
            if (p != null) gp.computeIfAbsent(p, k -> new HashSet<>()).add(entry);
        }
    }

    /** Auto-grant Item.Read on parent folders so the user can navigate to the granted item. */
    private void autoGrantParentRead(Item item, String sid, AuthorizationType atype) throws Exception {
        Set<String> readOnly = new HashSet<>();
        readOnly.add("hudson.model.Item.Read");
        ItemGroup<?> parent = item.getParent();
        while (parent instanceof Item) {
            Item parentItem = (Item) parent;
            try {
                applyItemPermissions(parentItem, sid, atype, readOnly);
            } catch (Exception ignored) {}
            if (parentItem instanceof AbstractFolder) {
                setNonInheriting((AbstractFolder<?>) parentItem);
            }
            parent = parentItem.getParent();
        }
    }

    /** Sets NonInheritingStrategy on a folder if not already set — idempotent, never reverts. */
    private void setNonInheriting(AbstractFolder<?> folder) {
        try {
            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                    folder.getProperties().get(
                            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
            if (fp == null) return;
            if (fp.getInheritanceStrategy() instanceof org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy) return;
            fp.setInheritanceStrategy(new org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy());
            folder.save();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to set NonInheriting on folder " + folder.getFullName(), e);
        }
    }

    /** Walks up the parent chain after a revoke and removes auto-granted Item.Read from folders
     *  that no longer have any descendant grants for this user. */
    private void cleanupParentRead(Item revokedItem, String sid, AuthorizationType atype) {
        ItemGroup<?> parent = revokedItem.getParent();
        while (parent instanceof AbstractFolder) {
            AbstractFolder<?> folder = (AbstractFolder<?>) parent;
            boolean hasDescendants = false;
            for (Job<?, ?> job : folder.getAllItems(Job.class)) {
                hudson.security.AuthorizationMatrixProperty p =
                        job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
                if (p != null && hasUserGrant(p.getGrantedPermissionEntries(), sid, atype)) {
                    hasDescendants = true; break;
                }
            }
            if (!hasDescendants) {
                for (AbstractFolder<?> sub : folder.getAllItems(AbstractFolder.class)) {
                    com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                            sub.getProperties().get(
                                    com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
                    if (fp != null && hasUserGrant(fp.getGrantedPermissionEntries(), sid, atype)) {
                        hasDescendants = true; break;
                    }
                }
            }
            if (!hasDescendants) {
                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty fp =
                        folder.getProperties().get(
                                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
                if (fp != null) {
                    try {
                        mutateGrantedPermissions(fp, sid, atype, null, Collections.emptySet());
                        folder.save();
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Failed to cleanup parent read on " + folder.getFullName(), e);
                    }
                }
                parent = folder.getParent();
            } else {
                break;
            }
        }
    }

    private boolean hasUserGrant(Map<Permission, Set<PermissionEntry>> entries, String sid, AuthorizationType atype) {
        for (Set<PermissionEntry> pes : entries.values()) {
            for (PermissionEntry pe : pes) {
                if (pe.getSid().equals(sid) && pe.getType() == atype) return true;
            }
        }
        return false;
    }

    private static String enc(String s) {
        try { return s == null ? "" : java.net.URLEncoder.encode(s, "UTF-8"); }
        catch (Exception e) { return ""; }
    }
    private static String type(AuthorizationType atype) {
        return atype == AuthorizationType.GROUP ? "GROUP" : "USER";
    }

    /** Converts an HTML date input value (YYYY-MM-DD) to an ISO-8601 instant string, or null if blank. */
    private static String toInstantString(String dateParam) {
        if (dateParam == null || dateParam.isBlank()) return null;
        try {
            return java.time.LocalDate.parse(dateParam.trim())
                    .atStartOfDay(java.time.ZoneOffset.UTC)
                    .plusDays(1)          // expires at end of the selected day (midnight of next day UTC)
                    .toInstant()
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ─── Inner classes for hierarchy view ────────────────────────────────────

    public static final class TreeNode {
        public final String path;
        public final String name;
        public final String type;          // root | folder | job | other
        public List<String> directPerms = new ArrayList<>();
        public String directRole;          // ADMIN/DEVELOPER/VIEWER/CUSTOM (root) or CONFIGURE/BUILD/READ/CUSTOM (item)
        public String effectiveRole;
        public List<TreeNode> children = new ArrayList<>();
        public TreeNode(String path, String name, String type) {
            this.path = path; this.name = name; this.type = type;
        }
        public String getPath()          { return path; }
        public String getName()          { return name; }
        public String getType()          { return type; }
        public String getDirectRole()    { return directRole; }
        public String getEffectiveRole() { return effectiveRole; }
        public List<String> getDirectPerms() { return directPerms; }
        public List<TreeNode> getChildren() { return children; }
        public boolean isHasDirect()     { return directRole != null; }
        public int getChildCount()       { return children.size(); }
    }

    public static final class TreeRow {
        public TreeNode node;
        public int depth;
        public String inheritedRole;       // null if direct grant exists at this node
        public String inheritedFromPath;   // path of the ancestor node where the inherited role originates
        public TreeNode getNode()         { return node; }
        public int getDepth()             { return depth; }
        public String getInheritedRole()  { return inheritedRole; }
        public String getInheritedFromPath() { return inheritedFromPath; }
        public int getIndentPx()          { return depth * 22; }
        public String getDisplayName()    {
            if ("root".equals(node.type)) return node.name;
            return node.name;
        }
    }

    public static final class UserAssignmentInfo {
        private final String scope;
        private final String displayScope;
        private final String scopeType;
        private final String roleName;
        private final List<String> permissionIds;
        private final String expiresAt;
        private final List<String> customPermissions;

        public UserAssignmentInfo(String scope, String displayScope, String scopeType,
                                  String roleName, List<String> permissionIds,
                                  String expiresAt, List<String> customPermissions) {
            this.scope             = scope;
            this.displayScope      = displayScope;
            this.scopeType         = scopeType;
            this.roleName          = roleName;
            this.permissionIds     = permissionIds;
            this.expiresAt         = expiresAt;
            this.customPermissions = customPermissions != null ? customPermissions : Collections.emptyList();
        }

        public String getScope()                     { return scope; }
        public String getDisplayScope()              { return displayScope; }
        public String getScopeType()                 { return scopeType; }
        public String getRoleName()                  { return roleName; }
        public List<String> getPermissionIds()       { return permissionIds; }
        public String getExpiresAt()                 { return expiresAt; }
        public List<String> getCustomPermissions()   { return customPermissions; }
        private boolean reviewDue = false;
        private String accessType;
        private String approverGroup;
        private int maxDurationHours;
        private int approvalTimeoutHours;

        public boolean isGlobal()                    { return scope == null || scope.isEmpty(); }
        public int getPermissionCount()              { return permissionIds != null ? permissionIds.size() : 0; }
        public boolean isReviewDue()                 { return reviewDue; }
        public void setReviewDue(boolean v)          { this.reviewDue = v; }
        public String getAccessType()                { return accessType != null ? accessType : "STANDING"; }
        public void setAccessType(String v)          { this.accessType = v; }
        public boolean isJit()                       { return "JIT".equalsIgnoreCase(accessType); }
        public String getApproverGroup()             { return approverGroup != null ? approverGroup : ""; }
        public void setApproverGroup(String v)       { this.approverGroup = v; }
        public int getMaxDurationHours()             { return maxDurationHours > 0 ? maxDurationHours : 4; }
        public void setMaxDurationHours(int v)       { this.maxDurationHours = v; }
        public int getApprovalTimeoutHours()         { return approvalTimeoutHours > 0 ? approvalTimeoutHours : 4; }
        public void setApprovalTimeoutHours(int v)   { this.approvalTimeoutHours = v; }

        public String getCustomPermissionsJson() {
            if (customPermissions == null || customPermissions.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < customPermissions.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(customPermissions.get(i).replace("\"", "\\\"")).append("\"");
            }
            sb.append("]");
            return sb.toString();
        }

        public String getPermissionSummary() {
            if (permissionIds == null || permissionIds.isEmpty()) return "none";
            List<String> names = new ArrayList<>();
            for (String pid : permissionIds) {
                int dot = pid.lastIndexOf('.');
                names.add(dot >= 0 ? pid.substring(dot + 1) : pid);
            }
            if (names.size() <= 3) return String.join(", ", names);
            return names.get(0) + ", " + names.get(1) + " + " + (names.size() - 2) + " more";
        }
    }

    public enum ScopedRole {
        READ(
            "hudson.model.Item.Read"
        ),
        BUILD(
            "hudson.model.Item.Read",
            "hudson.model.Item.Build",
            "hudson.model.Item.Cancel"
        ),
        CONFIGURE(
            "hudson.model.Item.Read",
            "hudson.model.Item.Build",
            "hudson.model.Item.Cancel",
            "hudson.model.Item.Configure",
            "hudson.model.Item.Delete"
        );

        public final Set<String> permissionIds;
        ScopedRole(String... ids) {
            this.permissionIds = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(ids)));
        }
    }

    public static final class PendingReviewItem {
        private final String userId;
        private final String displayName;
        private final String authType;
        private final String roleId;
        private final String scope;
        private final String displayScope;
        private final String scopeType;
        private final int daysAgo;
        private final boolean everReviewed;

        public PendingReviewItem(String userId, String displayName, String authType,
                                 String roleId, String scope, String displayScope,
                                 String scopeType, int daysAgo, boolean everReviewed) {
            this.userId       = userId;
            this.displayName  = displayName;
            this.authType     = authType;
            this.roleId       = roleId;
            this.scope        = scope;
            this.displayScope = displayScope;
            this.scopeType    = scopeType;
            this.daysAgo      = daysAgo;
            this.everReviewed = everReviewed;
        }

        public String getUserId()       { return userId; }
        public String getDisplayName()  { return displayName; }
        public String getAuthType()     { return authType; }
        public String getRoleId()       { return roleId; }
        public String getScope()        { return scope; }
        public String getDisplayScope() { return displayScope; }
        public String getScopeType()    { return scopeType; }
        public int getDaysAgo()         { return daysAgo; }
        public boolean isEverReviewed() { return everReviewed; }
        public boolean isGroup()        { return "GROUP".equalsIgnoreCase(authType); }

        public String getAvatarLetter() {
            String src = (displayName != null && !displayName.equals(userId)) ? displayName : userId;
            return (src != null && !src.isEmpty()) ? src.substring(0, 1).toUpperCase() : "?";
        }
    }
}
