package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
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
import java.io.IOException;

/**
 * Forwards /loginError to securityRealm/loginError when OmniAuth is active,
 * so OmniAuthSecurityRealm/loginError.jelly (which includes the Microsoft button)
 * is served instead of Jenkins' built-in login error page.
 *
 * Why a servlet filter: Jenkins core's loginError.jelly is loaded from the core
 * classloader and cannot be overridden from a plugin. A servlet filter intercepts
 * before Stapler dispatch and lets us forward to our own SecurityRealm view.
 */
@Extension
public class LoginErrorInterceptor {

    @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
    public static void registerFilter() throws Exception {
        PluginServletFilter.addFilter(new LoginErrorFilter());
    }

    private static class LoginErrorFilter implements Filter {

        @Override
        public void init(FilterConfig filterConfig) {}

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse rsp = (HttpServletResponse) response;

            String contextPath = req.getContextPath();
            String uri = req.getRequestURI();
            String path = contextPath.isEmpty() ? uri : uri.substring(contextPath.length());

            if ("/loginError".equals(path)
                    && Jenkins.get().getSecurityRealm() instanceof OmniAuthSecurityRealm) {
                // getRequestDispatcher path is relative to the servlet context root (no context path prefix)
                req.getRequestDispatcher("/securityRealm/loginError")
                        .forward(request, response);
                return;
            }
            chain.doFilter(request, response);
        }

        @Override
        public void destroy() {}
    }
}
