package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * Holds Azure AD / Microsoft Entra configuration:
 * tenant ID, client ID, client secret, scopes, and optional group sync flag.
 */
public class EntraOAuthConfig extends AbstractDescribableImpl<EntraOAuthConfig> {

    private final String tenantId;
    private final String clientId;
    private final Secret clientSecret;
    private boolean enableGroupSync;

    @DataBoundConstructor
    public EntraOAuthConfig(String tenantId, String clientId, Secret clientSecret) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public boolean isEnableGroupSync() {
        return enableGroupSync;
    }

    @DataBoundSetter
    public void setEnableGroupSync(boolean enableGroupSync) {
        this.enableGroupSync = enableGroupSync;
    }

    /**
     * Returns the OAuth2 scopes to request. Always includes openid, profile, email.
     * Adds Graph API scope when group sync is enabled.
     */
    public String getScope() {
        if (enableGroupSync) {
            return "openid profile email https://graph.microsoft.com/.default";
        }
        return "openid profile email";
    }

    /**
     * Returns the Azure AD authority URL for this tenant.
     */
    public String getAuthority() {
        return "https://login.microsoftonline.com/" + tenantId;
    }

    @Extension
    @Symbol("entraConfig")
    public static class DescriptorImpl extends Descriptor<EntraOAuthConfig> {

        @Override
        public String getDisplayName() {
            return "Microsoft Entra (Azure AD) Configuration";
        }

        public FormValidation doCheckTenantId(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Tenant ID is required");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientId(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Client ID is required");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientSecret(@QueryParameter Secret value) {
            if (value == null || Secret.toString(value).trim().isEmpty()) {
                return FormValidation.error("Client Secret is required");
            }
            return FormValidation.ok();
        }
    }
}
