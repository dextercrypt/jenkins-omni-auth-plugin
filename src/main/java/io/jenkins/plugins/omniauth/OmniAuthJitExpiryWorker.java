package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.AsyncPeriodicWork;
import hudson.model.TaskListener;

import java.util.logging.Logger;

@Extension
public class OmniAuthJitExpiryWorker extends AsyncPeriodicWork {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthJitExpiryWorker.class.getName());

    public OmniAuthJitExpiryWorker() {
        super("OmniAuth JIT Request Expiry Check");
    }

    @Override
    public long getRecurrencePeriod() {
        return MIN; // every minute — JIT windows can be as short as 1 hour
    }

    @Override
    protected void execute(TaskListener listener) {
        OmniAuthJitRequestStore store = OmniAuthJitRequestStore.get();
        if (store == null) return;

        java.util.List<OmniAuthJitRequest> transitioned = store.processExpiredAndTimedOut();
        if (!transitioned.isEmpty()) {
            LOGGER.info("OmniAuth JIT: transitioned " + transitioned.size() + " request(s) to EXPIRED/TIMED_OUT");
            OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
            for (OmniAuthJitRequest req : transitioned) {
                if (OmniAuthJitRequest.STATUS_TIMED_OUT.equals(req.getStatus()) && req.getApprovedCount() > 0) {
                    NotificationService.sendJitTimedOutPartial(cfg, req);
                }
            }
        }

        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        int retentionDays = cfg != null ? cfg.getJitHistoryRetentionDays() : 90;
        int purged = store.purgeOldRecords(retentionDays);
        if (purged > 0) {
            LOGGER.info("OmniAuth JIT: purged " + purged + " terminal request(s) older than " + retentionDays + " days");
        }
    }
}
