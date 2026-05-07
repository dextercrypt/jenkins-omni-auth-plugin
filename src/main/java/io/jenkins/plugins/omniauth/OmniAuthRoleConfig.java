package io.jenkins.plugins.omniauth;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import org.jenkinsci.Symbol;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

@Extension
@Symbol("omniAuthRoles")
public class OmniAuthRoleConfig extends GlobalConfiguration {

    private List<RoleDefinition> roles = new CopyOnWriteArrayList<>();

    public OmniAuthRoleConfig() {
        load();
        if (roles.isEmpty()) {
            initDefaults();
        }
    }

    private Object readResolve() {
        if (!(roles instanceof CopyOnWriteArrayList)) {
            roles = new CopyOnWriteArrayList<>(roles != null ? roles : Collections.emptyList());
        }
        return this;
    }

    public static OmniAuthRoleConfig get() {
        return GlobalConfiguration.all().get(OmniAuthRoleConfig.class);
    }

    private void initDefaults() {
        roles = new CopyOnWriteArrayList<>();
        roles.add(new RoleDefinition("Administrator", "Full Jenkins access including system configuration",
                Arrays.asList("hudson.model.Hudson.Administer")));
        roles.add(new RoleDefinition("Developer", "Build, configure and manage jobs and views",
                Arrays.asList(
                        "hudson.model.Hudson.Read",
                        "hudson.model.Item.Build",
                        "hudson.model.Item.Cancel",
                        "hudson.model.Item.Configure",
                        "hudson.model.Item.Create",
                        "hudson.model.Item.Delete",
                        "hudson.model.Item.Move",
                        "hudson.model.Item.Read",
                        "hudson.model.Item.WipeOut",
                        "hudson.model.View.Configure",
                        "hudson.model.View.Create",
                        "hudson.model.View.Delete",
                        "hudson.model.View.Read",
                        "hudson.model.Run.Delete",
                        "hudson.model.Run.Update"
                )));
        roles.add(new RoleDefinition("Read Only", "View Jenkins and jobs without making any changes",
                Arrays.asList(
                        "hudson.model.Hudson.Read",
                        "hudson.model.Item.Read",
                        "hudson.model.View.Read"
                )));
        save();
    }

    public List<RoleDefinition> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    public RoleDefinition findRole(String name) {
        if (name == null) return null;
        for (RoleDefinition r : roles) {
            if (r.getName().equalsIgnoreCase(name)) return r;
        }
        return null;
    }

    /** Returns the role name whose permission set exactly matches permIds, or null if no match. */
    public String matchRole(Set<String> permIds) {
        if (permIds == null || permIds.isEmpty()) return null;
        for (RoleDefinition r : roles) {
            if (new HashSet<>(r.getPermissionIds()).equals(permIds)) {
                return r.getName();
            }
        }
        return null;
    }

    public void upsertRole(String name, String description, List<String> permissionIds) {
        for (int i = 0; i < roles.size(); i++) {
            if (roles.get(i).getName().equalsIgnoreCase(name)) {
                roles.set(i, new RoleDefinition(name, description, permissionIds));
                save();
                return;
            }
        }
        roles.add(new RoleDefinition(name, description, permissionIds));
        save();
    }

    public boolean deleteRole(String name) {
        boolean removed = roles.removeIf(r -> r.getName().equalsIgnoreCase(name));
        if (removed) save();
        return removed;
    }

    public void setRoles(List<RoleDefinition> roles) {
        this.roles = roles != null ? new CopyOnWriteArrayList<>(roles) : new CopyOnWriteArrayList<>();
    }

    public static class RoleDefinition {
        private String name;
        private String description;
        private List<String> permissionIds;

        public RoleDefinition() {}

        public RoleDefinition(String name, String description, List<String> permissionIds) {
            this.name = name;
            this.description = description;
            this.permissionIds = permissionIds != null ? new ArrayList<>(permissionIds) : new ArrayList<>();
        }

        public String getName() { return name != null ? name : ""; }
        public void setName(String name) { this.name = name; }
        public String getDescription() { return description != null ? description : ""; }
        public void setDescription(String description) { this.description = description; }
        public List<String> getPermissionIds() { return permissionIds != null ? permissionIds : Collections.emptyList(); }
        public void setPermissionIds(List<String> ids) { this.permissionIds = ids; }
        public int getPermissionCount() { return permissionIds != null ? permissionIds.size() : 0; }

        public String getPermissionsJson() {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String id : getPermissionIds()) {
                if (!first) sb.append(",");
                sb.append("\"").append(id.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
                first = false;
            }
            return sb.append("]").toString();
        }
    }
}
