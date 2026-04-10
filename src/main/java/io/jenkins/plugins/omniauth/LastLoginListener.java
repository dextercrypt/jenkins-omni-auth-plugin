package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import jenkins.security.SecurityListener;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Listens for successful logins (both native and Entra) and records the
 * timestamp on the user's LastLoginProperty.
 *
 * This gives stale user cleanup a unified last-login signal for all user types.
 * For Entra users, OmniAuthUserProperty.lastLoginAt is also set separately
 * in finishEntraLogin — this listener covers legacy users.
 */
@Extension
public class LastLoginListener extends SecurityListener {

    private static final Logger LOGGER = Logger.getLogger(LastLoginListener.class.getName());

    @Override
    protected void authenticated2(UserDetails details) {
        try {
            User user = User.getById(details.getUsername(), false);
            if (user == null) return;

            String now = Instant.now().toString();

            LastLoginProperty prop = user.getProperty(LastLoginProperty.class);
            if (prop == null) {
                prop = new LastLoginProperty(now);
            } else {
                prop.setLastLoginAt(now);
            }
            user.addProperty(prop);
            user.save();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to record last login for: " + details.getUsername(), e);
        }
    }
}
