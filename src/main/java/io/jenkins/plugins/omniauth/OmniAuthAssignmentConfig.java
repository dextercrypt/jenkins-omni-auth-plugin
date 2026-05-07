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

    public OmniAuthAssignmentConfig() {
        load();
    }

    private Object readResolve() {
        if (!(assignments instanceof CopyOnWriteArrayList)) {
            assignments = new CopyOnWriteArrayList<>(assignments != null ? assignments : Collections.emptyList());
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
}
