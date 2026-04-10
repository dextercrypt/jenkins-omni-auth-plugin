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
    @Override public String getDisplayName()     { return "OmniAuth — Entra User Management"; }
    @Override public String getDescription()     { return "Manage Microsoft Entra users, review access, and clean up stale accounts."; }
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
            net.sf.json.JSONObject json = new net.sf.json.JSONObject();
            if (selected != null && selected.length > 0) {
                net.sf.json.JSONArray arr = new net.sf.json.JSONArray();
                for (String s : selected) arr.add(s);
                json.put("protectedUsers", arr);
            }
            config.configure(req, json);
        }
        rsp.sendRedirect("protectedUsers");
    }

    @POST
    public void doSaveSettings(StaplerRequest req, StaplerResponse rsp) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config != null) {
            net.sf.json.JSONObject json = new net.sf.json.JSONObject();
            // thresholds
            String stale  = req.getParameter("staleThresholdDays");
            String active = req.getParameter("activeThresholdDays");
            if (stale  != null) json.put("staleThresholdDays",  stale.trim());
            if (active != null) json.put("activeThresholdDays", active.trim());
            // cleanup
            boolean cleanupEnabled = req.getParameter("cleanupEnabled") != null;
            json.put("cleanupEnabled", cleanupEnabled);
            // If auto-cleanup is disabled, always force dry-run ON (safety default)
            boolean dryRun = !cleanupEnabled || req.getParameter("cleanupDryRun") != null;
            json.put("cleanupDryRun", dryRun);
            String cron  = req.getParameter("cleanupCron");
            String maxD  = req.getParameter("cleanupMaxDeletions");
            String email = req.getParameter("cleanupNotifyEmail");
            if (cron  != null) json.put("cleanupCron",          cron.trim());
            if (maxD  != null) json.put("cleanupMaxDeletions",   maxD.trim());
            if (email != null) json.put("cleanupNotifyEmail",    email.trim());
            // preserve protected users — don't touch them from this form
            net.sf.json.JSONArray arr = new net.sf.json.JSONArray();
            for (String u : config.getProtectedUsers()) arr.add(u);
            json.put("protectedUsers", arr);
            config.configure(req, json);
        }
        rsp.sendRedirect("settings?saved=true");
    }

    // -------------------------------------------------------------------------
    // Settings helpers
    // -------------------------------------------------------------------------

    public OmniAuthGlobalConfig getOmniAuthGlobalConfig() {
        return OmniAuthGlobalConfig.get();
    }

    // -------------------------------------------------------------------------
    // Overview stats (used by index.jelly)
    // -------------------------------------------------------------------------

    public int getTotalUserCount()  { return User.getAll().size(); }
    public int getEntraUserCount()  { return (int) User.getAll().stream().filter(u -> u.getProperty(OmniAuthUserProperty.class) != null).count(); }
    public int getLegacyUserCount() { return getTotalUserCount() - getEntraUserCount(); }
    public int getStaleUserCount()  { return getStaleUsers(staleThresholdDays()).size(); }

    // -------------------------------------------------------------------------
    // User Status list (used by userStatus.jelly)
    // -------------------------------------------------------------------------

    public List<UserStatusInfo> getUserStatusList() {
        Map<String, LastJobInfo> lastJobMap = buildLastJobMap();
        List<UserStatusInfo> result = new ArrayList<>();

        for (User user : User.getAll()) {
            OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
            LastLoginProperty    loginProp = user.getProperty(LastLoginProperty.class);

            String userType  = (entraProp != null) ? "Entra" : "Legacy";
            String lastLogin = resolveLastLogin(entraProp, loginProp);
            LastJobInfo lastJob = lastJobMap.get(user.getId());
            String status = deriveStatus(lastLogin, lastJob);

            result.add(new UserStatusInfo(
                    user.getId(),
                    user.getFullName(),
                    userType,
                    lastLogin,
                    lastJob != null ? lastJob.jobName  : null,
                    lastJob != null ? lastJob.triggeredAt : null,
                    status
            ));
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

        return new AccessInfo(
                userId,
                user.getFullName(),
                userType,
                entraProp != null ? entraProp.getEntraObjectId() : null,
                entraProp != null ? entraProp.getEntraUpn() : null,
                lastLogin,
                jobAccess,
                authStrategy,
                isAdmin, canRead, canBuild, canCreate, canConfigure
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
        if (userId != null && !userId.isEmpty()) {
            OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
            if (config != null && config.isProtected(userId)) {
                LOGGER.warning("Deletion blocked — user is protected: " + userId);
                rsp.sendRedirect("staleUsers?error=protected");
                return;
            }
            User user = User.getById(userId, false);
            if (user != null) {
                LOGGER.info("Manual stale user deletion by admin: " + userId);
                user.delete();
            }
        }
        rsp.sendRedirect("staleUsers");
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

        public String getUserId()             { return userId; }
        public String getFullName()           { return fullName; }
        public String getUserType()           { return userType; }
        public String getLastLoginAt()        { return lastLoginAt; }
        public String getLastJobName()        { return lastJobName; }
        public String getLastJobTriggeredAt() { return lastJobTriggeredAt; }
        public String getStatus()             { return status; }
        public boolean isNeverLoggedIn()      { return lastLoginAt == null; }
        public boolean isNeverTriggered()     { return lastJobName == null; }
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

        public AccessInfo(String userId, String fullName, String userType,
                          String entraOid, String entraUpn, String lastLoginAt,
                          List<JobAccessInfo> jobAccess, String authStrategy,
                          boolean isAdmin, boolean canRead, boolean canBuild,
                          boolean canCreate, boolean canConfigure) {
            this.userId       = userId;
            this.fullName     = fullName;
            this.userType     = userType;
            this.entraOid     = entraOid;
            this.entraUpn     = entraUpn;
            this.lastLoginAt  = lastLoginAt;
            this.jobAccess    = jobAccess != null ? jobAccess : Collections.emptyList();
            this.authStrategy = authStrategy;
            this.isAdmin      = isAdmin;
            this.canRead      = canRead;
            this.canBuild     = canBuild;
            this.canCreate    = canCreate;
            this.canConfigure = canConfigure;
        }

        public String getUserId()              { return userId; }
        public String getFullName()            { return fullName; }
        public String getUserType()            { return userType; }
        public String getEntraOid()            { return entraOid; }
        public String getEntraUpn()            { return entraUpn; }
        public String getLastLoginAt()         { return lastLoginAt; }
        public List<JobAccessInfo> getJobAccess() { return jobAccess; }
        public String getAuthStrategy()        { return authStrategy; }
        public boolean isAdmin()               { return isAdmin; }
        public boolean isCanRead()             { return canRead; }
        public boolean isCanBuild()            { return canBuild; }
        public boolean isCanCreate()           { return canCreate; }
        public boolean isCanConfigure()        { return canConfigure; }
        public boolean isEntraUser()           { return "Entra".equals(userType); }
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
