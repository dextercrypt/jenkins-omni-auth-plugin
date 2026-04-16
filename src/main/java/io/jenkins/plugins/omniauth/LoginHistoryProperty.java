package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Stores the last 10 login events for a Jenkins user.
 */
public class LoginHistoryProperty extends UserProperty {

    private static final Logger LOGGER = Logger.getLogger(LoginHistoryProperty.class.getName());
    private static final int MAX_EVENTS = 10;

    private List<LoginEvent> events = new ArrayList<>();

    public List<LoginEvent> getEvents() {
        if (events == null) events = new ArrayList<>();
        return Collections.unmodifiableList(events);
    }

    public LoginEvent getLatestEvent() {
        if (events == null || events.isEmpty()) return null;
        return events.get(0);
    }

    public synchronized void addEvent(LoginEvent event) {
        if (events == null) events = new ArrayList<>();
        events.add(0, event);
        if (events.size() > MAX_EVENTS) {
            events.subList(MAX_EVENTS, events.size()).clear();
        }
    }

    /** Convenience: record an event and save the user. */
    public static void record(User user, LoginEvent event) {
        if (user == null) return;
        try {
            LoginHistoryProperty prop = user.getProperty(LoginHistoryProperty.class);
            if (prop == null) prop = new LoginHistoryProperty();
            prop.addEvent(event);
            user.addProperty(prop);
            user.save();
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to save login history for: " + user.getId(), e);
        }
    }

    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override public String getDisplayName() { return "OmniAuth Login History"; }
        @Override public boolean isEnabled() { return false; } // hide from user config UI
        @Override public LoginHistoryProperty newInstance(User user) { return new LoginHistoryProperty(); }
    }
}
