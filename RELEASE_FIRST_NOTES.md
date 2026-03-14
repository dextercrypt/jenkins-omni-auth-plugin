# Dual-Auth Plugin — First Release Notes
**Version:** 1.0-SNAPSHOT
**Date:** 2026-03-15
**Jenkins target:** 2.541.2
**Java:** 21 (Amazon Corretto)

---

## What This Plugin Does

Adds a **"Sign in with Microsoft"** button to Jenkins's standard login page, backed by
Microsoft Entra (Azure AD) OAuth2 / OIDC. The native Jenkins username/password login
continues to work exactly as before — both methods live side-by-side on the same page.

---

## Architecture

| Component | Role |
|-----------|------|
| `DualAuthSecurityRealm` | Extends `HudsonPrivateSecurityRealm` — inherits 100% of native login behaviour, adds Entra OAuth2 endpoints |
| `EntraOAuthConfig` | Holds tenantId, clientId, clientSecret (Jenkins-encrypted), enableGroupSync flag |
| `EntraUserDetails` | Spring Security `UserDetails` for an Entra-authenticated user |
| `EntraAuthenticationToken` | Spring Security `Authentication` token placed in the security context |
| `EntraGroupDetails` | Implements `GrantedAuthority` for each Azure AD group |
| `DualAuthUserProperty` | Jenkins `UserProperty` storing OID + UPN + last group sync time per user |
| `MsalTokenHelper` | Wraps MSAL4J — builds auth URL, exchanges code for tokens, parses ID token |
| `GraphApiHelper` | Calls MS Graph `/me/memberOf` using Java 11 `HttpClient` to fetch group memberships |
| `DualAuthSecurityRealm/login.jelly` | Custom login page — verbatim Jenkins 2.541.2 login + Microsoft button appended |

---

## OAuth2 Flow

```
Browser                    Jenkins                        Azure AD
  |                           |                              |
  |-- GET /securityRealm/login|                              |
  |<-- login page (both btns) |                              |
  |                           |                              |
  |-- GET commenceLogin ------>|                              |
  |                           |-- store state nonce in session
  |<-- 302 to Azure AD --------|-- 302 ------------->         |
  |                                                           |-- user authenticates
  |<-- 302 to finishLogin ------------------------------------ |
  |-- GET finishLogin?code&state ->                           |
  |                           |-- validate state nonce        |
  |                           |-- exchange code for tokens    |
  |                           |-- parse ID token (oid, upn)   |
  |                           |-- optional: Graph API groups  |
  |                           |-- provision/update Jenkins user
  |                           |-- set Spring Security context |
  |                           |-- store _JENKINS_SESSION_SEED |
  |<-- 302 to dashboard -------|                              |
```

---

## Key Decisions & Why

### 1. User ID = UPN (email address)
Entra users are stored in Jenkins with their UPN (`mayank.purohit@enveu.com`) as the
user ID, not the Azure OID. This means admins can pre-provision permissions in the
authorization matrix by email **before** the user's first login — no red strikethrough.

### 2. OID as stable identity anchor
The Azure Object ID (OID) is stored in `DualAuthUserProperty` and used to look up
returning users. OID never changes even if the user's email/UPN changes.

### 3. No OkHttp — uses java.net.http.HttpClient
OkHttp's Kotlin stdlib is compiled for a newer JVM class version that breaks the
Jenkins license plugin's Groovy/ASM scanner during build. Replaced with the standard
`java.net.http.HttpClient` (Java 11+).

### 4. Groups via MS Graph API
When `enableGroupSync = true`, the plugin calls MS Graph `/me/memberOf` using the
access token and maps each group to a `GrantedAuthority`. Group names are cached in
`DualAuthUserProperty` for display.

### 5. `AUTHENTICATED_AUTHORITY2` in EntraUserDetails
Jenkins's `FullControlOnceLoggedInAuthorizationStrategy` checks for the `"authenticated"`
granted authority. Without it, even a logged-in Entra user was treated as anonymous.
Added `SecurityRealm.AUTHENTICATED_AUTHORITY2` to `getAuthorities()`.

### 6. Pre-provisioning via loadUserByUsername2 override
Overrides `loadUserByUsername2()` to return a stub `EntraUserDetails` for any
email-format username when Entra is configured. This prevents the red strikethrough
in the Project Matrix UI for pre-provisioned Entra users.

---

## Critical Bug Fixed: The "Flash" Login Issue

**Symptom:** Clicking "Sign in with Microsoft" completed Azure authentication but
immediately returned to the Jenkins login page without logging in.

**Root cause:** Jenkins's `HttpSessionContextIntegrationFilter2` (Jenkins's custom
Spring Security filter) validates a session attribute called `_JENKINS_SESSION_SEED`
on **every incoming request**. If the attribute is absent, it immediately nullifies
the `SPRING_SECURITY_CONTEXT` in the session — wiping the authentication we just saved.

The normal path that stores this seed (`SecurityListener.fireAuthenticated2()`) uses
`Stapler.getCurrentRequest2()` which is the **Jakarta Servlet API**. However,
`doFinishLogin` is declared with the old `StaplerRequest` API, so
`getCurrentRequest2()` returns `null` and the seed write silently no-ops.

**Fix:** Explicitly store `_JENKINS_SESSION_SEED` directly using `req.getSession()` —
the same request object we already use throughout `doFinishLogin`.

```java
jenkins.security.seed.UserSeedProperty seedProp =
        jenkinsUser.getProperty(jenkins.security.seed.UserSeedProperty.class);
if (seedProp != null) {
    req.getSession().setAttribute(
            jenkins.security.seed.UserSeedProperty.USER_SESSION_SEED,
            seedProp.getSeed());
}
```

Also explicitly use `SecurityContextImpl` (concrete class) instead of
`SecurityContextHolder.getContext()` which in Spring Security 6 may return a
deferred/lazy wrapper that doesn't serialize correctly into the session.

---

## Build Fixes

### Maven license plugin failure
**Problem:** `io.jenkins.tools.maven:license-maven-plugin` uses Groovy with an old ASM
version that fails to parse newer Java class files present in Maven 3.9.13's classpath.

**Fix in pom.xml:**
```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.jenkins.tools.maven</groupId>
      <artifactId>license-maven-plugin</artifactId>
      <executions>
        <execution>
          <id>default</id>
          <phase>none</phase>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```
Also set `<spotless.check.skip>true</spotless.check.skip>` and
`<license.skip>true</license.skip>` in properties.

### Running Jenkins for development
`mvn hpi:run` fails because Jetty 10 in the hpi plugin does not process
`META-INF/web-fragment.xml` from `jenkins-core-2.541.2.jar`, so the Stapler servlet
and `WebAppMain` listener never register.

**Workaround:** Run the standalone Jenkins WAR directly:
```bash
JENKINS_HOME=/path/to/dual-auth/work \
java -jar jenkins-war-2.541.2.war --httpPort=9090 --prefix=/jenkins
```

---

## Azure App Registration Setup

Use **OAuth2 / OIDC App Registration** (NOT SAML Enterprise Application).

| Field | Value |
|-------|-------|
| Redirect URI | `http://<jenkins-host>/jenkins/securityRealm/finishLogin` |
| Supported account types | Single tenant (your org only) |
| Token type | ID token + Access token |
| API permissions | `openid`, `profile`, `email`, `User.Read` (+ `GroupMember.Read.All` if group sync enabled) |

Credentials needed for plugin config:
- **Tenant ID** — Azure Portal → Azure Active Directory → Overview
- **Client ID** — App Registration → Overview
- **Client Secret** — App Registration → Certificates & Secrets

---

## Session Behaviour

- **Inactivity timeout:** Same as native Jenkins — Jetty's default HTTP session timeout
  (30 minutes). Session expires, next request redirects to login page.
- **Logout:** Jenkins session is destroyed. Microsoft browser session is NOT invalidated
  (planned for next release).

---

## What's Working

- [x] Native username/password login (unchanged from Jenkins built-in)
- [x] "Sign in with Microsoft" button on login page
- [x] OAuth2 Authorization Code flow via MSAL4J
- [x] ID token parsing (oid, preferred_username, name, email)
- [x] Jenkins user auto-provisioned on first Entra login (UPN as user ID)
- [x] Returning user recognised by OID (stable even if email changes)
- [x] Optional group sync via MS Graph API
- [x] Groups surfaced as `GrantedAuthority` for authorization strategies
- [x] Pre-provisioning by email in Project Matrix (no red strikethrough)
- [x] CSRF protection via OAuth2 state nonce
- [x] Session persistence across OAuth redirect (seed fix)
- [x] Friendly error messages for session expiry and Azure errors
- [x] Works with `ProjectMatrixAuthorizationStrategy`
- [x] Works with `FullControlOnceLoggedInAuthorizationStrategy`
- [x] Inactivity session timeout (inherited from Jenkins/Jetty)

---

## What's Planned (Next Release)

- [ ] Microsoft logout sync — invalidate Azure AD browser session on Jenkins logout
- [ ] PKCE support for enhanced OAuth2 security
- [ ] Nonce claim validation in ID token
- [ ] JCasC support (`@Symbol` annotation for configuration-as-code)
- [ ] Integration tests (JenkinsRule + WireMock for Azure AD mock)
