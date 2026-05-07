package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.stapler.StaplerDispatchable;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Exposes the Microsoft Entra OAuth2 endpoints at /omniauth/commenceLogin and
 * /omniauth/finishLogin as an UnprotectedRootAction.
 *
 * Why not on OmniAuthSecurityRealm directly?
 * OmniAuthSecurityRealm extends HudsonPrivateSecurityRealm, which configures
 * Spring Security to require authentication for all paths except the built-in
 * login/logout/signup pages. Our commenceLogin and finishLogin endpoints must
 * be reachable by unauthenticated users (that is the whole point — they are
 * trying to log in). UnprotectedRootAction is the Jenkins-supported mechanism
 * for exactly this use case: Jenkins automatically adds /omniauth/** to the
 * Spring Security permit list for all UnprotectedRootAction implementations.
 */
@Extension
public class OmniAuthRootAction implements UnprotectedRootAction {

    /** URL prefix: /omniauth/... */
    @Override
    public String getUrlName() {
        return "omniauth";
    }

    /** No icon — this action is not visible in the side panel. */
    @Override
    public String getIconFileName() {
        return null;
    }

    /** No display name — hidden from the Jenkins UI. */
    @Override
    public String getDisplayName() {
        return null;
    }

    /**
     * Step 1 — redirect browser to Azure AD login page.
     * URL: GET /omniauth/commenceLogin[?from=…]
     */
    @StaplerDispatchable
    public HttpResponse doCommenceLogin(StaplerRequest req) throws Exception {
        OmniAuthSecurityRealm realm = getOmniAuthRealm();
        if (realm == null) {
            return HttpResponses.error(503,
                    "Omni Auth security realm is not active.");
        }
        return realm.startEntraLogin(req);
    }

    /**
     * Step 2 — Azure AD posts back with an authorization code.
     * URL: GET /omniauth/finishLogin?code=…&state=…
     */
    @StaplerDispatchable
    public HttpResponse doFinishLogin(StaplerRequest req) throws Exception {
        OmniAuthSecurityRealm realm = getOmniAuthRealm();
        if (realm == null) {
            return HttpResponses.error(503,
                    "Omni Auth security realm is not active.");
        }
        return realm.finishEntraLogin(req);
    }

    /** GET: serve the change-password page. */
    @StaplerDispatchable
    public void doChangePassword(StaplerRequest req, StaplerResponse rsp) throws Exception {
        req.getView(this, "changePassword.jelly").forward(req, rsp);
    }

    /** POST: process the new password, clear the force-change flag, redirect to dashboard. */
    @POST
    @StaplerDispatchable
    public void doSubmitPasswordChange(StaplerRequest req, StaplerResponse rsp) throws Exception {
        String newPwd     = req.getParameter("newPassword");
        String confirmPwd = req.getParameter("confirmPassword");
        String ctx        = req.getContextPath();

        if (newPwd == null || newPwd.length() < 8) {
            rsp.sendRedirect(ctx + "/omniauth/changePassword?error=tooShort"); return;
        }
        if (!newPwd.equals(confirmPwd)) {
            rsp.sendRedirect(ctx + "/omniauth/changePassword?error=mismatch"); return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            rsp.sendRedirect(ctx + "/login"); return;
        }

        User user = User.getById(auth.getName(), false);
        if (user == null) {
            rsp.sendRedirect(ctx + "/omniauth/changePassword?error=noUser"); return;
        }

        // Update password via reflection (fromPlainPassword is package-private in Jenkins core)
        try {
            java.lang.reflect.Method m = HudsonPrivateSecurityRealm.Details.class
                    .getDeclaredMethod("fromPlainPassword", String.class);
            m.setAccessible(true);
            HudsonPrivateSecurityRealm.Details details =
                    (HudsonPrivateSecurityRealm.Details) m.invoke(null, newPwd);
            user.addProperty(details);
        } catch (Exception e) {
            rsp.sendRedirect(ctx + "/omniauth/changePassword?error=saveFailed"); return;
        }

        // Clear the force-change flag
        OmniAuthForcePasswordProperty prop = user.getProperty(OmniAuthForcePasswordProperty.class);
        if (prop != null) {
            prop.setForcePasswordChange(false);
        }
        user.save();

        rsp.sendRedirect(ctx + "/");
    }

    private OmniAuthSecurityRealm getOmniAuthRealm() {
        hudson.security.SecurityRealm realm = Jenkins.get().getSecurityRealm();
        return realm instanceof OmniAuthSecurityRealm
                ? (OmniAuthSecurityRealm) realm
                : null;
    }
}
