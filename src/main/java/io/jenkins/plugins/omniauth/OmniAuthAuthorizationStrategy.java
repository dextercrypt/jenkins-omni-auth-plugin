package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class OmniAuthAuthorizationStrategy extends ProjectMatrixAuthorizationStrategy {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthAuthorizationStrategy.class.getName());

    private static final ConcurrentHashMap<String, ACL> aclCache = new ConcurrentHashMap<>();

    public static void invalidateCache() {
        aclCache.clear();
    }

    @Override
    public ACL getACL(AbstractItem item) {
        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        if (config == null || config.getAssignments().isEmpty()) {
            return super.getACL(item);
        }
        return aclCache.computeIfAbsent(item.getFullName(), OmniAuthItemACL::new);
    }

    @DataBoundConstructor
    public OmniAuthAuthorizationStrategy() {
        super();
    }

    @Extension
    public static final class ConverterImpl extends GlobalMatrixAuthorizationStrategy.ConverterImpl {
        @Override
        public boolean canConvert(Class type) {
            return type == OmniAuthAuthorizationStrategy.class;
        }

        @Override
        public GlobalMatrixAuthorizationStrategy create() {
            return new OmniAuthAuthorizationStrategy();
        }
    }

    @Extension
    @Symbol("omniAuthAuthorization")
    public static final class DescriptorImpl extends ProjectMatrixAuthorizationStrategy.DescriptorImpl {

        @Override
        public String getDisplayName() {
            return "OmniAuth Authorization Strategy";
        }

        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new OmniAuthAuthorizationStrategy();
        }

        /**
         * Returns true when the existing strategy has permissions to migrate.
         */
        public boolean shouldShowMigrationNotice() {
            GlobalMatrixAuthorizationStrategy source = getMigrationSource();
            return source != null && !source.getGrantedPermissionEntries().isEmpty();
        }

        /**
         * Returns the current GlobalMatrix or ProjectMatrix strategy when switching to OmniAuth
         * for the first time. Returns null if OmniAuth is already active.
         */
        public GlobalMatrixAuthorizationStrategy getMigrationSource() {
            AuthorizationStrategy current = Jenkins.get().getAuthorizationStrategy();
            if (current instanceof GlobalMatrixAuthorizationStrategy
                    && !(current instanceof OmniAuthAuthorizationStrategy)) {
                return (GlobalMatrixAuthorizationStrategy) current;
            }
            return null;
        }

        /**
         * Returns an OmniAuthAuthorizationStrategy pre-populated with permissions from the
         * existing matrix strategy, for display in the migration UI.
         */
        public OmniAuthAuthorizationStrategy getPrePopulatedInstance() {
            GlobalMatrixAuthorizationStrategy source = getMigrationSource();
            if (source == null) return null;
            OmniAuthAuthorizationStrategy pre = new OmniAuthAuthorizationStrategy();
            for (Map.Entry<Permission, Set<PermissionEntry>> e : source.getGrantedPermissionEntries().entrySet()) {
                for (PermissionEntry pe : e.getValue()) {
                    pre.add(e.getKey(), pe);
                }
            }
            return pre;
        }
    }
}
