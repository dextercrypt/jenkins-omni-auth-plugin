package io.jenkins.plugins.omniauth;

import hudson.XmlFile;
import jenkins.model.Jenkins;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NotificationLog {

    private static final Logger LOGGER = Logger.getLogger(NotificationLog.class.getName());
    private static final int MAX_ENTRIES = 200;
    private static final String PREFIX = "[Jenkins OmniAuth] ";

    private List<NotificationLogEntry> entries = new ArrayList<>();

    // -------------------------------------------------------------------------
    // Singleton — lazy-loaded, persisted to JENKINS_HOME
    // -------------------------------------------------------------------------

    private static volatile NotificationLog INSTANCE;

    public static NotificationLog get() {
        if (INSTANCE == null) {
            synchronized (NotificationLog.class) {
                if (INSTANCE == null) {
                    XmlFile f = configFile();
                    if (f.exists()) {
                        try {
                            INSTANCE = (NotificationLog) f.read();
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Could not read OmniAuth notification log — starting fresh", e);
                            INSTANCE = new NotificationLog();
                        }
                    } else {
                        INSTANCE = new NotificationLog();
                    }
                }
            }
        }
        return INSTANCE;
    }

    private static XmlFile configFile() {
        return new XmlFile(new File(Jenkins.get().getRootDir(), "omniauth-notification-log.xml"));
    }

    // -------------------------------------------------------------------------
    // API
    // -------------------------------------------------------------------------

    public synchronized void addEntry(String subject, String recipients,
                                       boolean success, String errorMessage) {
        String description = subject.startsWith(PREFIX)
                ? subject.substring(PREFIX.length()) : subject;
        entries.add(0, new NotificationLogEntry(
                Instant.now().toString(), description, recipients, success, errorMessage));
        if (entries.size() > MAX_ENTRIES) {
            entries = new ArrayList<>(entries.subList(0, MAX_ENTRIES));
        }
        persist();
    }

    public synchronized List<NotificationLogEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public synchronized NotificationLogEntry lastForChannel(String prefix) {
        for (NotificationLogEntry e : entries) {
            if (e.getDescription().startsWith(prefix)) return e;
        }
        return null;
    }

    public NotificationLogEntry lastSmtpEntry()  { return lastForChannel("[Email] "); }
    public NotificationLogEntry lastSlackEntry() { return lastForChannel("[Slack] "); }
    public NotificationLogEntry lastTeamsEntry() { return lastForChannel("[Teams] "); }

    public synchronized void clear() {
        entries.clear();
        persist();
    }

    private void persist() {
        try {
            configFile().write(this);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not persist OmniAuth notification log", e);
        }
    }
}
