package io.jenkins.plugins.omniauth;

/**
 * Presets for the external SSO sign-in button shown on the login page.
 *
 * <p>Each provider supplies its own button label; the matching logo is rendered in
 * {@code login.jelly} keyed off {@link #getId()}. Today only Microsoft Entra exists,
 * but new OAuth/OIDC providers can be added here without touching the login markup
 * (add an enum constant + a logo branch in the jelly's {@code <j:choose>}).
 */
public enum SsoProvider {
    MICROSOFT("microsoft", "Sign in with Microsoft", "Redirecting to Microsoft…");

    // Future providers slot in here, e.g.:
    // GOOGLE("google", "Sign in with Google", "Redirecting to Google…"),
    // OKTA("okta", "Sign in with Okta", "Redirecting to Okta…"),
    // GENERIC_OIDC("oidc", "Sign in with SSO", "Redirecting…");

    private final String id;
    private final String buttonLabel;
    private final String loadingLabel;

    SsoProvider(String id, String buttonLabel, String loadingLabel) {
        this.id = id;
        this.buttonLabel = buttonLabel;
        this.loadingLabel = loadingLabel;
    }

    /** Stable key used to select the provider's logo in the login markup. */
    public String getId() {
        return id;
    }

    /** Text shown on the sign-in button, e.g. "Sign in with Microsoft". */
    public String getButtonLabel() {
        return buttonLabel;
    }

    /** Text shown on the button while redirecting to the provider, e.g. "Redirecting to Microsoft…". */
    public String getLoadingLabel() {
        return loadingLabel;
    }
}
