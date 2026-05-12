package io.jenkins.plugins.omniauth;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import org.jenkinsci.Symbol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Extension
@Symbol("omniAuthAssignments")
public class OmniAuthAssignmentConfig extends GlobalConfiguration {

    private static final Logger LOGGER = Logger.getLogger(OmniAuthAssignmentConfig.class.getName());

    private List<OmniAuthAssignment> assignments = new CopyOnWriteArrayList<>();
    private List<OmniAuthGroupEntity> groups = new CopyOnWriteArrayList<>();

    public OmniAuthAssignmentConfig() {
        load();
    }

    private Object readResolve() {
        if (!(assignments instanceof CopyOnWriteArrayList)) {
            assignments = new CopyOnWriteArrayList<>(assignments != null ? assignments : Collections.emptyList());
        }
        if (!(groups instanceof CopyOnWriteArrayList)) {
            groups = new CopyOnWriteArrayList<>(groups != null ? groups : Collections.emptyList());
        }
        return this;
    }

    public static OmniAuthAssignmentConfig get() {
        return GlobalConfiguration.all().get(OmniAuthAssignmentConfig.class);
    }

    public List<OmniAuthAssignment> getAssignments() {
        return Collections.unmodifiableList(assignments);
    }

    public void setAssignments(List<OmniAuthAssignment> assignments) {
        this.assignments = assignments != null ? new CopyOnWriteArrayList<>(assignments) : new CopyOnWriteArrayList<>();
    }

    public List<OmniAuthAssignment> getAssignmentsForUser(String userId, String authType) {
        return assignments.stream()
                .filter(a -> a.getUserId().equals(userId)
                        && a.getAuthType().equalsIgnoreCase(authType))
                .collect(Collectors.toList());
    }

    public synchronized void addAssignment(OmniAuthAssignment a) {
        assignments.add(a);
        save();
        OmniAuthAuthorizationStrategy.invalidateCache();
    }

    public synchronized void removeAssignment(String userId, String authType, String scope) {
        String normalizedScope = scope != null ? scope : "";
        boolean removed = assignments.removeIf(a ->
                a.getUserId().equals(userId)
                && a.getAuthType().equalsIgnoreCase(authType)
                && a.getScope().equals(normalizedScope));
        if (removed) {
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
        }
    }

    public synchronized int removeExpiredAssignments() {
        int before = assignments.size();
        assignments.removeIf(OmniAuthAssignment::isExpired);
        int removed = before - assignments.size();
        if (removed > 0) {
            save();
            OmniAuthAuthorizationStrategy.invalidateCache();
        }
        return removed;
    }

    public synchronized void updateAssignment(String userId, String authType, String scope, OmniAuthAssignment updated) {
        String normalizedScope = scope != null ? scope : "";
        assignments.removeIf(a ->
                a.getUserId().equals(userId)
                && a.getAuthType().equalsIgnoreCase(authType)
                && a.getScope().equals(normalizedScope));
        assignments.add(updated);
        save();
        OmniAuthAuthorizationStrategy.invalidateCache();
    }

    public boolean hasAssignment(String userId, String authType, String scope) {
        String normalizedScope = scope != null ? scope : "";
        return assignments.stream().anyMatch(a ->
                a.getUserId().equals(userId)
                && a.getAuthType().equalsIgnoreCase(authType)
                && a.getScope().equals(normalizedScope));
    }

    // ── Group entity methods ──────────────────────────────────────────────────

    public List<OmniAuthGroupEntity> getGroups() {
        return Collections.unmodifiableList(groups);
    }

    public synchronized void addGroup(OmniAuthGroupEntity group) {
        groups.add(group);
        save();
    }

    public synchronized void removeGroup(String groupOid) {
        groups.removeIf(g -> g.getGroupOid().equals(groupOid));
        save();
    }

    public OmniAuthGroupEntity findGroup(String groupOid) {
        return groups.stream()
                .filter(g -> g.getGroupOid().equals(groupOid))
                .findFirst().orElse(null);
    }

    public boolean hasGroup(String groupOid) {
        return groups.stream().anyMatch(g -> g.getGroupOid().equals(groupOid));
    }

    /** Returns true if any GROUP entities have been added to Access Management. */
    public boolean hasAnyGroups() {
        return !groups.isEmpty();
    }

    /** Resolves display name for a group — called when first member logs in. */
    public synchronized void resolveGroupDisplayName(String groupOid, String displayName) {
        for (OmniAuthGroupEntity g : groups) {
            if (g.getGroupOid().equals(groupOid) && !g.isResolved()) {
                g.setDisplayName(displayName);
                save();
                break;
            }
        }
    }
}
