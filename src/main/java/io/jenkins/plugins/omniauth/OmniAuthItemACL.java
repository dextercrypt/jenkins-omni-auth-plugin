package io.jenkins.plugins.omniauth;

import hudson.security.ACL;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OmniAuthItemACL extends ACL {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthItemACL.class.getName());

    private static final Set<String> NAV_PERMISSIONS;
    static {
        Set<String> nav = new HashSet<>();
        nav.add("hudson.model.Item.Read");
        NAV_PERMISSIONS = Collections.unmodifiableSet(nav);
    }

    private final String itemFullName;

    public OmniAuthItemACL(String itemFullName) {
        this.itemFullName = itemFullName;
    }

    @Override
    public boolean hasPermission2(Authentication auth, Permission permission) {
        if (auth == null) return false;

        // Jenkins internal SYSTEM user always has full access
        if (auth == ACL.SYSTEM2) return true;

        Jenkins j = Jenkins.getInstanceOrNull();
        if (j == null) return false;

        // Admin bypass via global ACL
        try {
            if (j.getAuthorizationStrategy().getRootACL().hasPermission2(auth, Jenkins.ADMINISTER)) {
                return true;
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed admin check for " + auth.getName(), e);
        }

        OmniAuthAssignmentConfig config = OmniAuthAssignmentConfig.get();
        OmniAuthRoleConfig roleConfig = OmniAuthRoleConfig.get();
        if (config == null) return false;

        String userId = auth.getName();

        List<OmniAuthAssignment> userAssignments = config.getAssignmentsForUser(userId, "USER");

        for (OmniAuthAssignment assignment : userAssignments) {
            if (assignment.isExpired()) continue;
            Set<String> granted = computeGrantedPermissions(assignment, roleConfig);
            if (impliedBy(granted, permission)) return true;
        }

        // Fall through to global matrix-auth for users with global grants
        // (doGrantAssignment with empty scope writes to matrix-auth, not OmniAuthAssignmentConfig)
        try {
            return j.getAuthorizationStrategy().getRootACL().hasPermission2(auth, permission);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Root ACL fallback failed for " + userId, e);
        }
        return false;
    }

    private Set<String> computeGrantedPermissions(OmniAuthAssignment assignment, OmniAuthRoleConfig roleConfig) {
        String scope = assignment.getScope();

        // Global assignment — full role permissions apply everywhere
        if (scope.isEmpty()) {
            return getRolePermissions(assignment, roleConfig);
        }

        String scopeType = assignment.getScopeType();

        if ("FOLDER".equals(scopeType)) {
            if (itemFullName.equals(scope)) {
                return getRolePermissions(assignment, roleConfig);       // item IS the granted folder
            }
            if (itemFullName.startsWith(scope + "/")) {
                return getRolePermissions(assignment, roleConfig);       // item is a descendant
            }
            if (scope.startsWith(itemFullName + "/")) {
                return NAV_PERMISSIONS;                                  // item is an ancestor (navigation)
            }
        } else {
            // JOB scope
            if (itemFullName.equals(scope)) {
                return getRolePermissions(assignment, roleConfig);       // item IS the granted job
            }
            if (scope.startsWith(itemFullName + "/")) {
                return NAV_PERMISSIONS;                                  // item is an ancestor (navigation)
            }
        }

        return Collections.emptySet();
    }

    /** Walks the impliedBy chain — if any granted permission directly or transitively implies the requested one. */
    private static boolean impliedBy(Set<String> granted, Permission permission) {
        Permission p = permission;
        while (p != null) {
            if (granted.contains(p.getId())) return true;
            p = p.impliedBy;
        }
        return false;
    }

    private Set<String> getRolePermissions(OmniAuthAssignment assignment, OmniAuthRoleConfig roleConfig) {
        if ("CUSTOM".equalsIgnoreCase(assignment.getRoleId())) {
            return new HashSet<>(assignment.getCustomPermissions());
        }
        if (roleConfig == null) return Collections.emptySet();
        OmniAuthRoleConfig.RoleDefinition role = roleConfig.findRole(assignment.getRoleId());
        if (role == null) return Collections.emptySet();
        return new HashSet<>(role.getPermissionIds());
    }
}
