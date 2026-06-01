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

        int changed = store.processExpiredAndTimedOut();
        if (changed > 0) {
            LOGGER.info("OmniAuth JIT: transitioned " + changed + " request(s) to EXPIRED/TIMED_OUT");
        }
    }
}
