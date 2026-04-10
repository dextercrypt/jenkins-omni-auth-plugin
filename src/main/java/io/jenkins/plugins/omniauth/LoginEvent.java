package io.jenkins.plugins.omniauth;

/**
 * Represents a single login event stored in LoginHistoryProperty.
 */
public class LoginEvent {

    private String timestamp;
    private String ipAddress;
    private String userAgent;  // raw UA string
    private String browser;    // parsed from UA
    private String os;         // parsed from UA
    private String method;     // "Entra" or "Native"
    private boolean success;

    // No-arg constructor required for XStream deserialization
    public LoginEvent() {}

    public LoginEvent(String timestamp, String ipAddress,
                      String userAgent, String browser, String os, String method, boolean success) {
        this.timestamp  = timestamp;
        this.ipAddress  = ipAddress;
        this.userAgent  = userAgent;
        this.browser    = browser;
        this.os         = os;
        this.method     = method;
        this.success    = success;
    }

    public String  getTimestamp()  { return timestamp; }
    public String  getIpAddress()  { return ipAddress; }
    public String  getUserAgent()  { return userAgent; }
    public String  getBrowser()    { return browser; }
    public String  getOs()         { return os; }
    public String  getMethod()     { return method; }
    public boolean isSuccess()     { return success; }

    // Relative + formatted helpers (reuse ManagementLink logic)
    public String getRelativeTimestamp()  { return OmniAuthManagementLink.relativeTime(timestamp); }
    public String getFormattedTimestamp() { return OmniAuthManagementLink.formatDate(timestamp); }

    // ── User-Agent parsing ────────────────────────────────────────────────────

    static String parseBrowser(String ua) {
        if (ua == null || ua.isEmpty()) return "Unknown";
        if (ua.contains("Edg/") || ua.contains("Edge/")) return "Edge";
        if (ua.contains("OPR/") || ua.contains("Opera/")) return "Opera";
        if (ua.contains("Chrome/"))  return "Chrome";
        if (ua.contains("Firefox/")) return "Firefox";
        if (ua.contains("Safari/") && ua.contains("Version/")) return "Safari";
        if (ua.contains("curl/"))    return "curl";
        return "Other";
    }

    static String parseOs(String ua) {
        if (ua == null || ua.isEmpty()) return "Unknown";
        if (ua.contains("Android"))       return "Android";
        if (ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iOS")) return "iOS";
        if (ua.contains("Windows"))       return "Windows";
        if (ua.contains("Mac OS X"))      return "macOS";
        if (ua.contains("Linux"))         return "Linux";
        return "Other";
    }
}
