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

    /** ISO-8601 timestamp of last successful Entra login. */
    private String lastLoginAt;

    /** Display names of groups cached from the last successful Entra login. */
    private List<String> cachedGroups;

    /**
     * How this account was provisioned.
     * "INDIVIDUAL" — admin explicitly pre-provisioned this user.
     * "VIA_ENTRA_GROUP" — auto-created on first login via Azure AD group membership.
     */
    private String provisioningSource;

    /**
     * OIDs of Access Management GROUP entities currently granting this user access.
     * Only populated when provisioningSource = VIA_ENTRA_GROUP.
     * Refreshed on every login to reflect current group membership.
     */
    private List<String> activeGroupOids;

    /**
     * When true, this account is queued for deletion.
     * Set automatically when a VIA_ENTRA_GROUP user is rejected at login (removed from AD group).
     * Set manually by an admin via the User Status kebab menu.
     * Cleared automatically on a successful login (group re-added in Azure).
     */
    private boolean pendingDeletion;

    @DataBoundConstructor
    public OmniAuthUserProperty(String entraObjectId, String entraUpn) {
        this.entraObjectId = entraObjectId;
        this.entraUpn = entraUpn;
        this.cachedGroups = new ArrayList<>();
        this.activeGroupOids = new ArrayList<>();
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

    public String getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(String lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public List<String> getCachedGroups() {
        return cachedGroups != null ? Collections.unmodifiableList(cachedGroups) : Collections.emptyList();
    }

    public void setCachedGroups(List<String> cachedGroups) {
        this.cachedGroups = new ArrayList<>(cachedGroups);
    }

    public String getProvisioningSource() {
        return provisioningSource != null ? provisioningSource : "INDIVIDUAL";
    }

    public void setProvisioningSource(String provisioningSource) {
        this.provisioningSource = provisioningSource;
    }

    public boolean isViaGroup() {
        return "VIA_ENTRA_GROUP".equals(provisioningSource);
    }

    public List<String> getActiveGroupOids() {
        return activeGroupOids != null ? Collections.unmodifiableList(activeGroupOids) : Collections.emptyList();
    }

    public void setActiveGroupOids(List<String> activeGroupOids) {
        this.activeGroupOids = activeGroupOids != null ? new ArrayList<>(activeGroupOids) : new ArrayList<>();
    }

    public boolean isPendingDeletion() { return pendingDeletion; }
    public void setPendingDeletion(boolean pendingDeletion) { this.pendingDeletion = pendingDeletion; }

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
