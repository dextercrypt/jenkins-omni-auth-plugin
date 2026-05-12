package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.AsyncPeriodicWork;
import hudson.model.TaskListener;

import java.util.logging.Logger;

@Extension
public class OmniAuthExpiryWorker extends AsyncPeriodicWork {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthExpiryWorker.class.getName());

    public OmniAuthExpiryWorker() {
        super("OmniAuth Assignment Expiry Check");
    }

    @Override
    public long getRecurrencePeriod() {
        return HOUR;
    }

    @Override
    protected void execute(TaskListener listener) {
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null) return;

        // Collect expired assignments before removing so we can audit them
        OmniAuthAuditLog audit = OmniAuthAuditLog.get();
        if (audit != null) {
            config.getAssignments().stream()
                    .filter(OmniAuthAssignment::isExpired)
                    .forEach(a -> audit.logExpired(a.getUserId(), a.getScope()));
        }

        int removed = config.removeExpiredAssignments();
        if (removed > 0) {
            LOGGER.info("OmniAuth: auto-revoked " + removed + " expired assignment(s)");
        }
    }
}
