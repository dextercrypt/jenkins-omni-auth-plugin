package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.AsyncPeriodicWork;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Periodic background task that automatically deletes stale users on a cron schedule.
 *
 * Reads all settings from OmniAuthGlobalConfig:
 *  - cleanupEnabled        : if false, does nothing
 *  - cleanupCron           : 5-field cron expression checked every minute
 *  - cleanupDryRun         : if true, logs but does not delete
 *  - staleThresholdDays    : users inactive longer than this are candidates
 *  - cleanupMaxDeletions   : safety cap per run
 *  - cleanupNotifyEmail    : email address for post-run report (logged only for now)
 *
 * Results stored as CleanupRunRecord in OmniAuthGlobalConfig (last 10 kept).
 */
@Extension
public class StaleUserCleanupWork extends AsyncPeriodicWork {

    private static final Logger LOGGER = Logger.getLogger(StaleUserCleanupWork.class.getName());

    public StaleUserCleanupWork() {
        super("OmniAuth Stale User Cleanup");
    }

    @Override
    public long getRecurrencePeriod() {
        return MIN; // check every minute for cron accuracy
    }

    @Override
    protected void execute(TaskListener listener) throws IOException, InterruptedException {
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config == null || !config.isCleanupEnabled()) return;
        if (!cronMatches(config.getCleanupCron())) return;

        LOGGER.info("OmniAuth stale user cleanup triggered (dry-run=" + config.isCleanupDryRun() + ")");
        runCleanup(config);
    }

    /** Called by the scheduler and also by the manual "Run Now" action. */
    public static void runCleanup(OmniAuthGlobalConfig config) {
        int     thresholdDays = config.getStaleThresholdDays();
        int     maxDeletions  = config.getCleanupMaxDeletions();
        boolean dryRun        = config.isCleanupDryRun();
        Instant cutoff        = Instant.now().minus(thresholdDays, ChronoUnit.DAYS);

        List<String> affected    = new ArrayList<>();
        int          scanned     = 0;
        int          skippedProt = 0;

        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            for (User user : User.getAll()) {
                scanned++;
                String userId = user.getId();

                if (config.isProtected(userId)) {
                    skippedProt++;
                    continue;
                }

                OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
                LastLoginProperty    loginProp  = user.getProperty(LastLoginProperty.class);
                String lastLogin = resolveLastLogin(entraProp, loginProp);

                boolean isStale = (lastLogin == null) || Instant.parse(lastLogin).isBefore(cutoff);
                if (!isStale) continue;

                if (dryRun) {
                    LOGGER.info("[DRY-RUN] Would delete stale user: " + userId);
                    affected.add(userId);
                } else {
                    if (affected.size() >= maxDeletions) {
                        LOGGER.warning("Reached max deletions cap (" + maxDeletions + "), stopping.");
                        break;
                    }
                    try {
                        user.delete();
                        LOGGER.info("Deleted stale user: " + userId);
                        affected.add(userId);
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Failed to delete user: " + userId, e);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during stale user cleanup", e);
        }

        OmniAuthGlobalConfig.CleanupRunRecord record = new OmniAuthGlobalConfig.CleanupRunRecord(
                Instant.now().toString(), dryRun, scanned, affected.size(), skippedProt, affected);
        config.addCleanupRecord(record);

        LOGGER.info("OmniAuth cleanup done — scanned=" + scanned
                + " affected=" + affected.size()
                + " skippedProtected=" + skippedProt
                + " dryRun=" + dryRun);

        EmailHelper.sendCleanupReport(config, record);
    }

    // ── Cron matching ─────────────────────────────────────────────────────────

    static boolean cronMatches(String cronExpr) {
        if (cronExpr == null || cronExpr.trim().isEmpty()) return false;
        String[] parts = cronExpr.trim().split("\\s+");
        if (parts.length != 5) return false;
        Calendar now = Calendar.getInstance();
        return fieldMatches(parts[0], now.get(Calendar.MINUTE))
            && fieldMatches(parts[1], now.get(Calendar.HOUR_OF_DAY))
            && fieldMatches(parts[2], now.get(Calendar.DAY_OF_MONTH))
            && fieldMatches(parts[3], now.get(Calendar.MONTH) + 1)
            && fieldMatches(parts[4], now.get(Calendar.DAY_OF_WEEK) - 1);
    }

    static boolean fieldMatches(String field, int value) {
        if ("*".equals(field)) return true;
        try { return Integer.parseInt(field) == value; }
        catch (NumberFormatException ignored) {}
        if (field.startsWith("*/")) {
            try { int n = Integer.parseInt(field.substring(2)); return n > 0 && value % n == 0; }
            catch (NumberFormatException ignored) {}
        }
        if (field.contains("-")) {
            String[] r = field.split("-", 2);
            try { return value >= Integer.parseInt(r[0]) && value <= Integer.parseInt(r[1]); }
            catch (NumberFormatException ignored) {}
        }
        return false;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String resolveLastLogin(OmniAuthUserProperty entraProp, LastLoginProperty loginProp) {
        if (entraProp != null && entraProp.getLastLoginAt() != null) return entraProp.getLastLoginAt();
        if (loginProp  != null && loginProp.getLastLoginAt()  != null) return loginProp.getLastLoginAt();
        return null;
    }
}
