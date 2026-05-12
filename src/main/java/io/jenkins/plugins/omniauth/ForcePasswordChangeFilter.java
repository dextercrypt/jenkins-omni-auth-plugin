package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.User;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

@Extension
public class ForcePasswordChangeFilter {

    @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
    public static void registerFilter() throws Exception {
        PluginServletFilter.addFilter(new PwdChangeFilter());
    }

    private static class PwdChangeFilter implements Filter {

        @Override public void init(FilterConfig config) {}
        @Override public void destroy() {}

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {

            HttpServletRequest  req = (HttpServletRequest)  request;
            HttpServletResponse rsp = (HttpServletResponse) response;

            String path = req.getRequestURI();
            String ctx  = req.getContextPath();

            // Allow pass-through for paths that must be reachable during password change
            if (isExempt(path, ctx)) {
                chain.doFilter(request, response);
                return;
            }

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || isAnonymous(auth)) {
                chain.doFilter(request, response);
                return;
            }

            String username = auth.getName();
            User user = User.getById(username, false);
            if (user == null) {
                chain.doFilter(request, response);
                return;
            }

            OmniAuthForcePasswordProperty prop = user.getProperty(OmniAuthForcePasswordProperty.class);
            if (prop != null && prop.isForcePasswordChange()) {
                rsp.sendRedirect(ctx + "/omniauth/changePassword");
                return;
            }

            chain.doFilter(request, response);
        }

        private boolean isExempt(String path, String ctx) {
            String p = path.startsWith(ctx) ? path.substring(ctx.length()) : path;
            return p.startsWith("/omniauth/changePassword")
                    || p.startsWith("/omniauth/submitPasswordChange")
                    || p.startsWith("/logout")
                    || p.startsWith("/adjuncts/")
                    || p.startsWith("/static/")
                    || p.startsWith("/images/")
                    || p.startsWith("/css/")
                    || p.startsWith("/scripts/")
                    || p.startsWith("/favicon")
                    || p.contains(".css")
                    || p.contains(".js")
                    || p.contains(".png")
                    || p.contains(".ico");
        }

        private boolean isAnonymous(Authentication auth) {
            return "anonymousUser".equals(auth.getName())
                    || auth.getAuthorities().stream()
                           .anyMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()));
        }
    }
}
