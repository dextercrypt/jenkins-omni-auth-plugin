package io.jenkins.plugins.omniauth;

import java.util.logging.Logger;

/**
 * Retry wrapper for notification sends — 3 attempts with 5s / 15s backoff.
 */
class NotifyRetry {

    private static final int   MAX_ATTEMPTS    = 3;
    private static final long[] BACKOFF_MS     = { 5_000L, 15_000L };

    private NotifyRetry() {}

    @FunctionalInterface
    interface Task {
        void run() throws Exception;
    }

    /**
     * Runs {@code task} up to 3 times. Returns normally on success.
     * Throws the last exception if all attempts fail.
     */
    static void run(Task task, Logger logger, String channel, String subject) throws Exception {
        Exception last = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                task.run();
                return;
            } catch (Exception e) {
                last = e;
                if (attempt < MAX_ATTEMPTS) {
                    long delay = BACKOFF_MS[attempt - 1];
                    logger.warning("OmniAuth " + channel + " failed (attempt " + attempt
                            + "/" + MAX_ATTEMPTS + "), retrying in " + (delay / 1000)
                            + "s — " + subject + ": " + e.getMessage());
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw e;
                    }
                }
            }
        }
        throw last;
    }
}
