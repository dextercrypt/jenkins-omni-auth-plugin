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
    MICROSOFT("microsoft", "Sign in with Microsoft");

    // Future providers slot in here, e.g.:
    // GOOGLE("google", "Sign in with Google"),
    // OKTA("okta", "Sign in with Okta"),
    // GENERIC_OIDC("oidc", "Sign in with SSO");

    private final String id;
    private final String buttonLabel;

    SsoProvider(String id, String buttonLabel) {
        this.id = id;
        this.buttonLabel = buttonLabel;
    }

    /** Stable key used to select the provider's logo in the login markup. */
    public String getId() {
        return id;
    }

    /** Text shown on the sign-in button, e.g. "Sign in with Microsoft". */
    public String getButtonLabel() {
        return buttonLabel;
    }
}
