package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import jenkins.security.SecurityListener;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Listens for successful logins and:
 *  - Updates LastLoginProperty (timestamp for stale cleanup)
 *  - Flags the username in LoginContextFilter.FRESH_LOGINS so the filter
 *    can record the full login event (IP, UA) after the request completes
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

            // Update last login timestamp (used by stale cleanup)
            LastLoginProperty prop = user.getProperty(LastLoginProperty.class);
            if (prop == null) prop = new LastLoginProperty(now);
            else prop.setLastLoginAt(now);
            user.addProperty(prop);
            user.save();

            // Flag for LoginContextFilter to record the full event with IP/UA
            LoginContextFilter.FRESH_LOGINS.put(details.getUsername(), Boolean.TRUE);

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to record login for: " + details.getUsername(), e);
        }
    }

    @Override
    protected void failedToAuthenticate(String username) {
        // Failed logins: flag with a special key so filter can record as failed
        LoginContextFilter.FRESH_LOGINS.put("__failed__" + username, Boolean.TRUE);
    }
}
