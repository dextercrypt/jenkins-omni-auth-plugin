package io.jenkins.plugins.omniauth;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * In-memory tracker for consecutive login failures per username.
 * Resets on successful login. Fires an email alert when the configured threshold is hit.
 */
public class BruteForceTracker {

    private static final Logger LOGGER = Logger.getLogger(BruteForceTracker.class.getName());
    private static final ConcurrentHashMap<String, AtomicInteger> FAILURES = new ConcurrentHashMap<>();

    private BruteForceTracker() {}

    public static void recordFailure(String username) {
        if (username == null || username.isEmpty()) return;
        int count = FAILURES.computeIfAbsent(username, k -> new AtomicInteger(0)).incrementAndGet();
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        int threshold = (cfg != null) ? cfg.getBruteForceThreshold() : 5;
        LOGGER.fine("Login failure #" + count + " for: " + username);
        if (count == threshold) {
            LOGGER.warning("Brute force threshold (" + threshold + ") reached for user: " + username);
            EmailHelper.sendBruteForceAlert(cfg, username, count);
        }
    }

    public static void recordSuccess(String username) {
        if (username != null) FAILURES.remove(username);
    }

    public static int getFailureCount(String username) {
        AtomicInteger c = FAILURES.get(username);
        return c == null ? 0 : c.get();
    }
}
