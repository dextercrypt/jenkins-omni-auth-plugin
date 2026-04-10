package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.util.PluginServletFilter;
import hudson.model.User;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PluginServletFilter runs AFTER Spring Security's filter chain, so by the time
 * this filter executes, the user is already authenticated. We:
 *   1. Capture IP + UA before chain.doFilter()
 *   2. Check if SecurityListener flagged a fresh login (SecurityContext already loaded)
 *   3. If yes, record the login event with the IP/UA we captured in step 1
 */
@Extension
public class LoginContextFilter {

    /** Username → true: SecurityListener saw a fresh login on this thread. */
    static final ConcurrentHashMap<String, Boolean> FRESH_LOGINS = new ConcurrentHashMap<>();

    @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
    public static void registerFilter() throws Exception {
        PluginServletFilter.addFilter(new ContextFilter());
    }

    private static class ContextFilter implements Filter {

        @Override public void init(FilterConfig config) {}
        @Override public void destroy() {}

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {

            // Spring Security's FilterChainProxy runs BEFORE PluginServletFilter,
            // so SecurityContextHolder is already populated when we arrive here.
            // Capture IP/UA from this request, then check FRESH_LOGINS immediately.
            String ip = "unknown";
            String ua = null;
            if (request instanceof HttpServletRequest) {
                HttpServletRequest http = (HttpServletRequest) request;
                String forwarded = http.getHeader("X-Forwarded-For");
                String raw = (forwarded != null && !forwarded.isEmpty())
                        ? forwarded.split(",")[0].trim()
                        : http.getRemoteAddr();
                // Normalize all loopback variants to "localhost"
                String stripped = raw.replaceAll("[\\[\\]]", ""); // remove brackets
                ip = (stripped.equals("127.0.0.1") || stripped.equals("0:0:0:0:0:0:0:1")
                        || stripped.equals("::1"))
                        ? "localhost" : raw;
                ua = http.getHeader("User-Agent");
            }

            // Record fresh login events — SecurityContextHolder already has auth loaded
            if (ua != null && !FRESH_LOGINS.isEmpty()) {
                try {
                    String browser  = LoginEvent.parseBrowser(ua);
                    String os       = LoginEvent.parseOs(ua);
                    String now      = Instant.now().toString();
                    String finalIp  = ip;
                    String finalUa  = ua;

                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null && auth.isAuthenticated()) {
                        String username = auth.getName();
                        if (FRESH_LOGINS.remove(username) != null) {
                            User user = User.getById(username, false);
                            if (user != null) {
                                OmniAuthUserProperty p = user.getProperty(OmniAuthUserProperty.class);
                                String method = (p != null) ? "Entra" : "Native";
                                LoginHistoryProperty.record(user,
                                        new LoginEvent(now, finalIp, finalUa, browser, os, method, true));
                            }
                        }
                    }

                    // Failed logins
                    FRESH_LOGINS.keySet().stream()
                            .filter(k -> k.startsWith("__failed__"))
                            .forEach(k -> {
                                FRESH_LOGINS.remove(k);
                                String uname = k.substring("__failed__".length());
                                User user = User.getById(uname, false);
                                if (user != null) {
                                    OmniAuthUserProperty p = user.getProperty(OmniAuthUserProperty.class);
                                    String method = (p != null) ? "Entra" : "Native";
                                    LoginHistoryProperty.record(user,
                                            new LoginEvent(now, finalIp, finalUa, browser, os, method, false));
                                }
                            });
                } catch (Exception ignored) {}
            }

            chain.doFilter(request, response);
        }
    }
}
