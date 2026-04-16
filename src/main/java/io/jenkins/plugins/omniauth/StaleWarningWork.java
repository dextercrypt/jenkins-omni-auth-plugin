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
import java.util.logging.Logger;

/**
 * Periodic job that scans for users approaching the stale threshold and sends a warning digest.
 * Runs on its own cron, independent of the cleanup job.
 *
 * A user is "approaching stale" when their last login falls within the warning window:
 *   (thresholdDays - warningWindowDays) < daysSinceLogin <= thresholdDays
 */
@Extension
public class StaleWarningWork extends AsyncPeriodicWork {

    private static final Logger LOGGER = Logger.getLogger(StaleWarningWork.class.getName());

    public StaleWarningWork() {
        super("OmniAuth Stale User Warning");
    }

    @Override
    public long getRecurrencePeriod() {
        return MIN;
    }

    @Override
    protected void execute(TaskListener listener) throws IOException, InterruptedException {
        OmniAuthGlobalConfig config = OmniAuthGlobalConfig.get();
        if (config == null || !config.isStaleWarningEnabled()) return;
        if (!StaleUserCleanupWork.cronMatches(config.getStaleWarningCron())) return;
        runWarning(config);
    }

    public static void runWarning(OmniAuthGlobalConfig config) {
        int thresholdDays  = config.getStaleThresholdDays();
        int windowDays     = config.getStaleWarningWindowDays();

        if (windowDays >= thresholdDays) {
            LOGGER.warning("Stale warning window (" + windowDays + ") >= threshold (" + thresholdDays + ") — skipping");
            return;
        }

        // approaching = last login is between (now - thresholdDays) and (now - (thresholdDays - windowDays))
        Instant staleAt = Instant.now().minus(thresholdDays, ChronoUnit.DAYS);
        Instant warnAt  = Instant.now().minus(thresholdDays - windowDays, ChronoUnit.DAYS);

        List<String> approaching = new ArrayList<>();

        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            for (User user : User.getAll()) {
                String userId = user.getId();
                if (config.isProtected(userId)) continue;

                OmniAuthUserProperty entraProp = user.getProperty(OmniAuthUserProperty.class);
                LastLoginProperty    loginProp  = user.getProperty(LastLoginProperty.class);
                String lastLoginStr = resolveLastLogin(entraProp, loginProp);
                if (lastLoginStr == null) continue; // never logged in = already stale, handled by cleanup

                Instant lastLogin = Instant.parse(lastLoginStr);
                boolean isApproaching = lastLogin.isAfter(staleAt) && !lastLogin.isAfter(warnAt);
                if (isApproaching) approaching.add(userId);
            }
        } catch (Exception e) {
            LOGGER.warning("Error during stale warning scan: " + e.getMessage());
        }

        LOGGER.info("Stale warning scan: " + approaching.size() + " user(s) approaching stale threshold");
        if (!approaching.isEmpty()) {
            EmailHelper.sendStaleWarningDigest(config, approaching, windowDays, thresholdDays);
        }
    }

    private static String resolveLastLogin(OmniAuthUserProperty entraProp, LastLoginProperty loginProp) {
        if (entraProp != null && entraProp.getLastLoginAt() != null) return entraProp.getLastLoginAt();
        if (loginProp  != null && loginProp.getLastLoginAt()  != null) return loginProp.getLastLoginAt();
        return null;
    }
}
