package io.jenkins.plugins.omniauth;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ActiveSessionManager {

    private static final ConcurrentHashMap<String, ActiveSession> SESSIONS = new ConcurrentHashMap<>();

    static final String SESSION_ATTR = "omniauth_session_hook";

    public static class ActiveSession {
        public final String sessionId;
        public final String userId;
        public final String fullName;
        public final String userType;
        public final String loginTime;
        public final String ip;
        public final String browser;
        public final String os;
        final HttpSession session;

        ActiveSession(HttpSession session, String userId, String fullName, String userType,
                      String ip, String browser, String os) {
            this.sessionId = session.getId();
            this.userId    = userId;
            this.fullName  = fullName;
            this.userType  = userType;
            this.loginTime = Instant.now().toString();
            this.ip        = ip;
            this.browser   = browser;
            this.os        = os;
            this.session   = session;
        }

        public String getSessionId() { return sessionId; }
        public String getUserId()    { return userId; }
        public String getFullName()  { return fullName; }
        public String getUserType()  { return userType; }
        public String getLoginTime() { return loginTime; }
        public String getIp()        { return ip; }
        public String getBrowser()   { return browser; }
        public String getOs()        { return os; }

        public String getRelativeLoginTime() {
            try {
                long secs = Instant.now().getEpochSecond() - Instant.parse(loginTime).getEpochSecond();
                if (secs < 60)   return secs + "s ago";
                if (secs < 3600) return (secs / 60) + "m ago";
                if (secs < 86400) return (secs / 3600) + "h ago";
                return (secs / 86400) + "d ago";
            } catch (Exception e) { return loginTime; }
        }
    }

    public static void register(HttpSession httpSession, String userId, String fullName,
                                String userType, String ip, String browser, String os) {
        ActiveSession s = new ActiveSession(httpSession, userId, fullName, userType, ip, browser, os);
        SESSIONS.put(httpSession.getId(), s);
        httpSession.setAttribute(SESSION_ATTR, new DeregisterHook(httpSession.getId()));
    }

    public static void deregister(String sessionId) {
        SESSIONS.remove(sessionId);
    }

    public static List<ActiveSession> getAll() {
        List<ActiveSession> list = new ArrayList<>(SESSIONS.values());
        list.sort((a, b) -> b.loginTime.compareTo(a.loginTime));
        return list;
    }

    public static boolean revoke(String sessionId) {
        ActiveSession s = SESSIONS.remove(sessionId);
        if (s == null) return false;
        try { s.session.invalidate(); } catch (Exception ignored) {}
        return true;
    }

    private static class DeregisterHook implements HttpSessionBindingListener {
        private final String sessionId;
        DeregisterHook(String sessionId) { this.sessionId = sessionId; }

        @Override public void valueBound(HttpSessionBindingEvent e) {}
        @Override public void valueUnbound(HttpSessionBindingEvent e) {
            SESSIONS.remove(sessionId);
        }
    }
}
