package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Jenkins UserProperty that stores Microsoft Entra identity data on a Jenkins User object.
 * Persisted to JENKINS_HOME/users/&lt;username&gt;/config.xml alongside the user record.
 * Used to re-link Entra users after Jenkins restarts without creating duplicates.
 */
public class OmniAuthUserProperty extends UserProperty {

    /** Azure AD Object ID — stable, unique identifier across tenant changes / UPN renames. */
    private final String entraObjectId;

    /** User Principal Name (preferred_username claim) — human-readable email address. */
    private final String entraUpn;

    /** ISO-8601 timestamp of last successful group sync. */
    private String groupsLastSynced;

    /** Display names of groups cached from the last successful Entra login. */
    private List<String> cachedGroups;

    @DataBoundConstructor
    public OmniAuthUserProperty(String entraObjectId, String entraUpn) {
        this.entraObjectId = entraObjectId;
        this.entraUpn = entraUpn;
        this.cachedGroups = new ArrayList<>();
    }

    public String getEntraObjectId() {
        return entraObjectId;
    }

    public String getEntraUpn() {
        return entraUpn;
    }

    public String getGroupsLastSynced() {
        return groupsLastSynced;
    }

    public void setGroupsLastSynced(String groupsLastSynced) {
        this.groupsLastSynced = groupsLastSynced;
    }

    public List<String> getCachedGroups() {
        return cachedGroups != null ? Collections.unmodifiableList(cachedGroups) : Collections.emptyList();
    }

    public void setCachedGroups(List<String> cachedGroups) {
        this.cachedGroups = new ArrayList<>(cachedGroups);
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public String getDisplayName() {
            return "Microsoft Entra Identity";
        }

        @Override
        public boolean isEnabled() {
            // Only show this property when OmniAuthSecurityRealm is active
            return hudson.model.Hudson.get().getSecurityRealm() instanceof OmniAuthSecurityRealm;
        }

        @Override
        public UserProperty newInstance(User user) {
            return null; // Not auto-created; only set during Entra login
        }
    }
}
