package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.Saveable;
import hudson.model.listeners.SaveableListener;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Detects when new users are granted Jenkins admin (ADMINISTER) permission and fires
 * an email alert.
 *
 * Only works when GlobalMatrixAuthorizationStrategy (or ProjectMatrixAuthorizationStrategy,
 * which extends it) is active. Silently does nothing for other strategies.
 *
 * Mechanism: listens for Jenkins config saves via SaveableListener and compares the current
 * ADMINISTER grant set against the last known set.
 */
@Extension
public class AdminChangeListener extends SaveableListener {

    private static final Logger LOGGER = Logger.getLogger(AdminChangeListener.class.getName());

    // null = not yet initialised (first save after startup establishes baseline without alerting)
    private static volatile Set<String> lastKnownAdmins = null;

    @Override
    public void onChange(Saveable o, XmlFile file) {
        if (!(o instanceof Jenkins)) return;

        OmniAuthGlobalConfig cfg = OmniAuthGlobalConfig.get();
        if (cfg == null) return;

        Set<String> current = currentAdminSet();
        Set<String> last    = lastKnownAdmins;
        lastKnownAdmins = current;

        if (last == null) return; // first run — baseline established, no alert

        Set<String> added = new HashSet<>(current);
        added.removeAll(last);
        if (added.isEmpty()) return;

        String changedBy = currentUserId();
        LOGGER.info("New admin(s) detected: " + added + " (saved by " + changedBy + ")");
        NotificationService.sendAdminGranted(cfg, new ArrayList<>(added), changedBy);
    }

    @SuppressWarnings("unchecked")
    private static Set<String> currentAdminSet() {
        try {
            hudson.security.AuthorizationStrategy as = Jenkins.get().getAuthorizationStrategy();
            // getGrantedPermissions() exists on GlobalMatrixAuthorizationStrategy (matrix-auth plugin)
            Method m = as.getClass().getMethod("getGrantedPermissions");
            Map<Permission, Set<String>> granted = (Map<Permission, Set<String>>) m.invoke(as);
            Set<String> admins = granted.get(Jenkins.ADMINISTER);
            return admins != null ? new HashSet<>(admins) : Collections.emptySet();
        } catch (NoSuchMethodException e) {
            return Collections.emptySet(); // auth strategy doesn't support matrix permissions
        } catch (Exception e) {
            LOGGER.fine("Could not read admin set: " + e.getMessage());
            return Collections.emptySet();
        }
    }

    private static String currentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getName() != null) ? auth.getName() : "unknown";
    }
}
