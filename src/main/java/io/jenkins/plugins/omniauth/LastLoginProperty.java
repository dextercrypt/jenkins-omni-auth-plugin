package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

/**
 * Stores the last successful login timestamp for any Jenkins user (legacy or Entra).
 * Updated by LastLoginListener on every authenticated login.
 * Used by stale user cleanup to determine inactivity across both user types.
 */
public class LastLoginProperty extends UserProperty {

    /** ISO-8601 timestamp of the last successful login. */
    private String lastLoginAt;

    public LastLoginProperty(String lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public String getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(String lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public String getDisplayName() {
            return "Last Login";
        }

        @Override
        public boolean isEnabled() {
            return false; // internal use only — not shown in user config UI
        }

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
