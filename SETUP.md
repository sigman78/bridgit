# Bridgit setup and validation runbook

Status: the OIDC-to-SAML protocol path is implemented and testable. Real Omada interoperability is not yet certified; read the compatibility note before changing production access.

## Compatibility note

Bridgit currently implements **SP-initiated SAML only**: Omada must send an HTTP-Redirect `AuthnRequest` to Bridgit. Do not browse to `/saml/sso` directly; that endpoint begins with a valid SAML request rather than a standalone login page.

TP-Link's current Omada setup guides primarily demonstrate **IdP-initiated** launch from the identity provider using a Base64-encoded `resourceId_omadaId` RelayState. Bridgit does not yet have an IdP launch URL or Pocket ID application tile, so a controller which does not expose an SP-initiated SSO action cannot complete an interactive login with this MVP. You can still complete configuration, validate OIDC and metadata, and run the simulated end-to-end test. Adding an Omada-specific IdP-initiated launch is the next practical compatibility increment.

Keep a local Omada administrator account and an already authenticated admin browser open while testing. Do not make SAML the only recovery path until a real login succeeds.

## Example topology

Substitute your own names throughout this guide:

| Component | Example public URL | Role |
| --- | --- | --- |
| Pocket ID | `https://id.home.example` | OIDC provider |
| Bridgit | `https://bridge.home.example` | OIDC client and SAML IdP |
| Omada | `https://omada.home.example:8043` | SAML SP |

All three names must resolve in the test browser. The Bridgit host must be able to resolve and trust the TLS certificate of Pocket ID. The browser must trust the TLS certificates of all browser-visible endpoints.

Bridgit listens on HTTP internally and must be placed behind an HTTPS reverse proxy. HTTPS is not optional: its session cookie is always `Secure` and named with the `__Host-` prefix. Testing the browser flow directly on `http://localhost:8080` will lose the cookie and fail.

For example, a Caddy proxy on the same host can use:

```caddyfile
bridge.home.example {
    reverse_proxy 127.0.0.1:8080
}
```

For an internal-only domain, Caddy's `tls internal` is also possible, but its root CA must be trusted by the browser. Use a certificate trusted by the Bridgit host for Pocket ID itself.

## 1. Build Bridgit

The module currently requires Go 1.26.6 or newer.

Linux/macOS:

```sh
go version
go test ./...
go build -o bridgit ./cmd/bridgit
```

Windows PowerShell:

```powershell
go version
go test ./...
go build -o .\bridgit.exe ./cmd/bridgit
```

If `go version` reports an older release, update Go before proceeding. The current machine's default `go` executable is 1.14.6 and cannot build this module.

## 2. Choose the Omada group

For the first test, use one dedicated group name everywhere, for example:

```text
omada-admins
```

The Pocket ID group name and Omada **SAML User Group Name** must match exactly, including case. Omada integrations are reported to behave most predictably with one Omada group per user. Bridgit currently forwards every value in the Pocket ID `groups` claim, so use a test user with only the one relevant group for the first validation.

## 3. Create the SAML signing keypair

This key signs SAML assertions; it is independent of the reverse proxy's TLS certificate. Run from the Bridgit working directory:

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout saml.key -out saml.crt -days 3650 \
  -subj "/CN=bridge.home.example"
```

On PowerShell, the same command can be entered on one line:

```powershell
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -keyout saml.key -out saml.crt -days 3650 -subj "/CN=bridge.home.example"
```

Back up both files, restrict access to `saml.key`, and keep them persistent across upgrades. If the keypair changes, Omada must import updated Bridgit metadata before it will trust new assertions.

## 4. Generate Bridgit metadata before normal startup

There is an intentional bootstrap cycle: Omada needs Bridgit IdP metadata before it creates its SP metadata, while normal Bridgit startup requires Omada SP metadata. The offline command breaks that cycle and needs only the public URL and signing keypair.

Linux/macOS:

```sh
export BRIDGIT_PUBLIC_URL=https://bridge.home.example
export BRIDGIT_SAML_CERT_FILE=./saml.crt
export BRIDGIT_SAML_KEY_FILE=./saml.key
./bridgit metadata > bridgit-idp-metadata.xml
```

Windows PowerShell:

```powershell
$env:BRIDGIT_PUBLIC_URL = "https://bridge.home.example"
$env:BRIDGIT_SAML_CERT_FILE = ".\saml.crt"
$env:BRIDGIT_SAML_KEY_FILE = ".\saml.key"
cmd /c "bridgit.exe metadata > bridgit-idp-metadata.xml"
```

Use `cmd /c` for redirection on Windows PowerShell 5, which otherwise may rewrite native output as UTF-16. The result should be XML whose entity ID is:

```text
https://bridge.home.example/saml/metadata
```

and whose Redirect SSO service is:

```text
https://bridge.home.example/saml/sso
```

## 5. Configure Omada as the SAML service provider

The precise labels vary slightly by controller version. TP-Link's current guides use these steps for supported Software, Standard Cloud-Based, OC300, and OC400 controllers:

1. Sign in with the retained local administrator account and enter **Global View**.
2. Go to **Settings -> SAML SSO**.
3. Select **Add New SAML Connection**.
4. Name it `Bridgit`, choose **Metadata File**, and upload `bridgit-idp-metadata.xml`.
5. Apply or create the connection.
6. Open its **Details** and record its **Entity ID**, **Sign-On URL**, **Omada ID**, and **Resource ID**.
7. Use the download action on the connection to save Omada's SP metadata as `omada-sp-metadata.xml` beside the Bridgit executable.
8. Select **Go to SAML User Group** (called **SAML Role** on some older versions).
9. Add a group named exactly `omada-admins`, select the desired Omada role, user type, validity, site access, and privileges, then create it.

Treat `omada-sp-metadata.xml` as a trust allowlist. Before using it, inspect that:

- `entityID` is the Omada Entity ID shown in the connection details;
- every `AssertionConsumerService Location` is your real Omada URL;
- it contains no stale test host or unexpected external ACS URL.

If the download button is absent, construct this minimal file using the exact Entity ID and Sign-On/ACS URL shown by Omada:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="REPLACE_WITH_OMADA_ENTITY_ID">
  <SPSSODescriptor AuthnRequestsSigned="false"
                   WantAssertionsSigned="true"
                   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="REPLACE_WITH_OMADA_SIGN_ON_OR_ACS_URL"
        index="0"
        isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

Prefer Omada's own downloaded file when available.

## 6. Configure Pocket ID

In Pocket ID:

1. Go to **User Groups**, create `omada-admins`, and add the test user.
2. Go to **Settings -> OIDC Clients** and create a client named `Bridgit`.
3. Set the callback URL exactly to `https://bridge.home.example/oidc/callback`.
4. Leave **Public Client** disabled. Bridgit is a confidential server and requires a client secret.
5. Enable PKCE if Pocket ID exposes the option. Bridgit always sends an S256 PKCE challenge.
6. Leave Client Launch URL empty for now; Bridgit has no IdP-initiated launch endpoint yet.
7. Under **Allowed User Groups**, add `omada-admins`. Alternatively explicitly choose unrestricted access for a temporary test. A newly created Pocket ID client with no allowed groups permits no users.
8. Save and copy the Client ID and Client Secret.

Bridgit requests `openid profile email groups`. Its defaults require these ID-token claims:

| Claim | Required shape | Bridgit use |
| --- | --- | --- |
| `sub` | non-empty string | persistent SAML NameID |
| `preferred_username` | non-empty string | SAML `username` |
| `groups` | non-empty string array | SAML `usergroup_name` values |
| `email`, `name`, `given_name`, `family_name` | strings, optional | retained in the local principal; not currently sent to Omada |

Confirm Pocket ID discovery is reachable from the Bridgit host:

```powershell
Invoke-RestMethod https://id.home.example/.well-known/openid-configuration |
  Select-Object issuer, authorization_endpoint, token_endpoint, jwks_uri
```

Set `BRIDGIT_OIDC_ISSUER` to the returned `issuer` value exactly—not to the `.well-known` URL.

## 7. Configure and launch Bridgit

Copy [.env.example](.env.example) to an untracked working file and replace every example value:

```text
BRIDGIT_PUBLIC_URL=https://bridge.home.example
BRIDGIT_LISTEN_ADDR=127.0.0.1:8080
BRIDGIT_OIDC_ISSUER=https://id.home.example
BRIDGIT_OIDC_CLIENT_ID=<Pocket-ID-client-ID>
BRIDGIT_OIDC_CLIENT_SECRET=<Pocket-ID-client-secret>
BRIDGIT_SAML_CERT_FILE=./saml.crt
BRIDGIT_SAML_KEY_FILE=./saml.key
BRIDGIT_SAML_SP_METADATA_FILE=./omada-sp-metadata.xml
BRIDGIT_USERNAME_CLAIM=preferred_username
BRIDGIT_GROUPS_CLAIM=groups
BRIDGIT_TRANSACTION_TTL=1m
BRIDGIT_SESSION_TTL=8h
BRIDGIT_LOG_LEVEL=info
```

Bridgit does not parse `.env` files itself. Load the variables into the process environment before launching it.

Linux/macOS, for a trusted local environment file containing shell-safe values:

```sh
set -a
. ./bridgit.env
set +a
./bridgit
```

Windows PowerShell:

```powershell
Get-Content .\bridgit.env | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $name, $value = $line -split "=", 2
        Set-Item -Path "Env:$name" -Value $value
    }
}
.\bridgit.exe
```

Use `BRIDGIT_LISTEN_ADDR=:8080` instead if the reverse proxy runs in another host or container that cannot reach loopback. Restrict port 8080 at the firewall; browser traffic should use only the HTTPS proxy.

Successful startup performs OIDC discovery first and then emits a JSON log similar to:

```json
{"level":"INFO","msg":"Bridgit listening","address":"127.0.0.1:8080","public_url":"https://bridge.home.example"}
```

If discovery, the keypair, or SP metadata is invalid, startup exits non-zero instead of listening.

## 8. Verify the running process

From a machine using the public HTTPS name:

```sh
curl -i https://bridge.home.example/healthz
curl -i https://bridge.home.example/readyz
curl -o running-idp-metadata.xml https://bridge.home.example/saml/metadata
```

Both health endpoints should return `200 OK` and `ok`. At present readiness is a startup-state check, not ongoing dependency monitoring. `/` returning `404 Not Found` is expected.

The downloaded running metadata should contain the same entity ID, SSO URL, and signing certificate as `bridgit-idp-metadata.xml`.

## 9. Exercise login

If your Omada version exposes an SSO/Test/Login action which produces an SP-initiated SAML request, use that action. In the browser network trace, the first Bridgit request must look like:

```text
GET https://bridge.home.example/saml/sso?SAMLRequest=...&RelayState=...
```

The expected browser sequence is:

1. Omada redirects the browser to Bridgit with `SAMLRequest` and usually `RelayState`.
2. Bridgit validates the Omada entity ID and ACS against `omada-sp-metadata.xml`.
3. Bridgit redirects to Pocket ID with OIDC state, nonce, scopes, and an S256 PKCE challenge.
4. The user authenticates to Pocket ID using a passkey.
5. Pocket ID redirects to `/oidc/callback`; Bridgit exchanges the code and validates the ID token.
6. Bridgit sets `__Host-bridgit_session`, resumes the original SAML request, and returns an auto-submitting HTML form.
7. The browser POSTs `SAMLResponse` and the unchanged `RelayState` to Omada's allowlisted ACS.
8. Omada grants the role and privileges associated with `omada-admins`.

Complete the Pocket ID interaction within the transaction TTL (one minute by default, at most 90 seconds). A Bridgit restart invalidates in-flight logins and local sessions but does not change Omada trust if `saml.key` and `saml.crt` are preserved.

If Omada has no way to send the initial `AuthnRequest`, stop here: that is the known IdP-initiated compatibility gap, not a Pocket ID configuration failure. Browsing directly to Bridgit, setting Pocket ID's launch URL to Bridgit, or inventing a RelayState will not work with the current implementation.

## 10. Simulate the endpoints without Pocket ID or Omada

The repository's integration harness provides the fastest current simulation. It starts an in-process OIDC provider with discovery/token/JWKS endpoints, uses a real Crewjam SAML service provider to generate the request, runs the callback, verifies the signature, and checks the Omada attributes and RelayState:

```sh
go test -count=1 -v ./internal/server \
  -run '^TestAuthenticatedPrincipalBecomesVerifiableOmadaAssertion$'
```

Run the whole protocol suite with:

```sh
go test -count=1 ./...
```

These tests do not open listening ports for manual browser use. A different interactive OIDC server can replace Pocket ID if it supplies:

- HTTPS OIDC discovery with an issuer matching `BRIDGIT_OIDC_ISSUER` exactly;
- authorization code flow for a confidential client;
- nonce and PKCE S256 support;
- a token endpoint returning a signed ID token;
- a reachable JWKS URI;
- non-empty `sub`, `preferred_username`, and string-array `groups` claims.

Keycloak, Dex, or another conforming provider can meet that contract after configuring its group mapper to put `groups` in the **ID token**. The built-in test provider is the reference simulation and requires no external configuration.

## Troubleshooting

| Symptom | Likely cause or check |
| --- | --- |
| Startup says `invalid configuration` | A required variable is absent, the public URL has a path, or an HTTPS requirement failed. |
| Startup says `initialize OIDC provider` | Pocket ID DNS/TLS/discovery is unreachable, or the configured issuer differs from discovery. |
| Startup rejects SP metadata | Use Omada's downloaded SP metadata; verify it has an entity ID, an SP descriptor, and an absolute ACS URL. |
| Omada rejects Bridgit metadata | Regenerate it with the same public URL and a currently valid RSA certificate; avoid PowerShell 5 UTF-16 redirection. |
| Pocket ID says access is denied | Add the user to a group allowed on the OIDC client, or explicitly unrestrict the client. |
| Browser loops through Pocket ID | The Secure session cookie was not stored; use the public HTTPS name, not direct HTTP port 8080. |
| Callback returns `400 Bad Request` | State was missing, expired, or already used; start a new Omada login and finish within the TTL. |
| Callback returns `401 Unauthorized` | Code exchange, ID-token signature/audience/expiry/nonce, username, or groups validation failed. |
| `/saml/sso` returns `400` | It was opened without a valid Omada `SAMLRequest`, or the entity ID/ACS is not allowlisted. |
| Omada reports invalid request parameters | Check exact `username` and `usergroup_name` attributes and the case-sensitive SAML group name. |
| Omada shows 405 | Check that Omada's ACS receives an HTTP POST and that its Entity ID/ACS values came from its own metadata. |
| Omada login cannot be started | The controller is expecting IdP-initiated SAML, which this MVP does not yet implement. |

`POST /logout` clears only Bridgit's local cookie. It does not log the browser out of Pocket ID or Omada; SAML Single Logout is not implemented.

## Source references

- Pocket ID OIDC client authentication: <https://pocket-id.org/docs/guides/oidc-client-authentication>
- Pocket ID allowed user groups: <https://pocket-id.org/docs/configuration/allowed-groups>
- Pocket ID client example showing issuer, scopes, groups, and PKCE: <https://pocket-id.org/docs/client-examples/headscale>
- TP-Link Omada SAML setup guide: <https://support.omadanetworks.com/en/document/26917/>
- TP-Link Omada Controller 6.2 user guide: <https://static.tp-link.com/upload/manual/2026/202604/20260401/1900002482_Omada%20SDN%20Controller_V6.2_User%20Guide.pdf>
- Authentik's current Omada interoperability notes, including the single-group recommendation: <https://integrations.goauthentik.io/networking/omada-controller/>
