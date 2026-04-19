package io.jenkins.plugins.omniauth;

import java.time.Instant;
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

    /** Users who hit the threshold — persists through successful login until manually cleared. */
    private static final ConcurrentHashMap<String, String> ALERTED = new ConcurrentHashMap<>();

    private BruteForceTracker() {}

    public static void recordFailure(String username) {
        if (username == null || username.isEmpty()) return;
        int count = FAILURES.computeIfAbsent(username, k -> new AtomicInteger(0)).incrementAndGet();
        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        int threshold = (cfg != null) ? cfg.getBruteForceThreshold() : 5;
        LOGGER.fine("Login failure #" + count + " for: " + username);
        if (count == threshold) {
            LOGGER.warning("Brute force threshold (" + threshold + ") reached for user: " + username);
            ALERTED.put(username, Instant.now().toString());
            NotificationService.sendBruteForceAlert(cfg, username, count);
        }
    }

    public static void recordSuccess(String username) {
        if (username != null) FAILURES.remove(username);
    }

    public static int getFailureCount(String username) {
        AtomicInteger c = FAILURES.get(username);
        return c == null ? 0 : c.get();
    }

    public static java.util.Map<String, Integer> getAllFailureCounts() {
        java.util.Map<String, Integer> result = new java.util.HashMap<>();
        for (java.util.Map.Entry<String, AtomicInteger> e : FAILURES.entrySet()) {
            int v = e.getValue().get();
            if (v > 0) result.put(e.getKey(), v);
        }
        return result;
    }

    public static java.util.Map<String, String> getAlertedUsers() {
        return new java.util.HashMap<>(ALERTED);
    }

    public static void clearAlert(String username) {
        ALERTED.remove(username);
    }
}
