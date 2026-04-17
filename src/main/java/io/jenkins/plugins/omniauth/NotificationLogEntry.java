package io.jenkins.plugins.omniauth;

import java.time.Instant;

public class NotificationLogEntry {

    private String timestamp;
    private String description;
    private String recipients;
    private boolean success;
    private String errorMessage;

    private NotificationLogEntry() {}

    public NotificationLogEntry(String timestamp, String description, String recipients,
                                 boolean success, String errorMessage) {
        this.timestamp    = timestamp;
        this.description  = description;
        this.recipients   = recipients;
        this.success      = success;
        this.errorMessage = errorMessage;
    }

    public String  getTimestamp()    { return timestamp; }
    public String  getDescription()  { return description; }
    public String  getRecipients()   { return recipients; }
    public boolean isSuccess()       { return success; }
    public String  getErrorMessage() { return errorMessage; }

    public String getRelativeTime() {
        if (timestamp == null) return "unknown";
        try {
            long sec = java.time.Duration.between(Instant.parse(timestamp), Instant.now()).getSeconds();
            if (sec < 60)    return "just now";
            if (sec < 3600)  return (sec / 60)   + "m ago";
            if (sec < 86400) return (sec / 3600)  + "h ago";
            long days = sec / 86400;
            if (days < 30)   return days           + "d ago";
            return (days / 30) + "mo ago";
        } catch (Exception e) {
            return timestamp;
        }
    }

    public String getFormattedTime() {
        if (timestamp == null) return "";
        try {
            java.time.ZonedDateTime zdt = Instant.parse(timestamp)
                    .atZone(java.time.ZoneId.systemDefault());
            return String.format("%d %s %d, %02d:%02d",
                    zdt.getDayOfMonth(),
                    zdt.getMonth().getDisplayName(java.time.format.TextStyle.SHORT, java.util.Locale.ENGLISH),
                    zdt.getYear(), zdt.getHour(), zdt.getMinute());
        } catch (Exception e) {
            return timestamp;
        }
    }
}
