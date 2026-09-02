# Bridgit

Bridgit is a small standalone OIDC-to-SAML identity bridge. It authenticates a browser with Pocket ID over OpenID Connect and issues a signed SAML assertion to an explicitly configured service provider such as Omada Controller.

Bridgit is an OIDC relying party toward Pocket ID and a SAML identity provider toward Omada. It stores no passwords and performs no user provisioning.

## Implemented MVP

- SAML 2.0 SP-initiated Web SSO.
- Incoming HTTP-Redirect `AuthnRequest`; outgoing HTTP-POST `SAMLResponse`.
- Persistent RSA/SHA-256 assertion signing and IdP metadata.
- Strict SP entity-ID and ACS allowlisting from an administrator-supplied metadata file.
- Pocket ID discovery and confidential authorization-code flow with state, nonce, and PKCE S256.
- Persistent OIDC `sub` NameID.
- `preferred_username` mapped to Omada's `username` attribute.
- `groups` mapped to Omada's multi-valued `usergroup_name` attribute.
- Bounded, expiring, in-memory transactions and sessions.
- Single-use OAuth state and SAML request replay protection.
- Local logout, liveness, readiness, server timeouts, and graceful shutdown.

This first version is intentionally single-process. Restarting Bridgit invalidates browser sessions and in-flight logins but does not disturb Omada trust as long as the SAML keypair is persistent.

## Build

Go 1.26.6 or newer is required. Earlier 1.26 patch releases contain standard-library vulnerabilities on Bridgit's HTTP/XML paths.

```sh
go build -o bridgit ./cmd/bridgit
go test ./...
```

The workstation used to develop this repository had an obsolete Go 1.14 installation, so development verification used the official portable Go 1.26.6 toolchain without modifying the system installation.

## Omada and Pocket ID setup

Start with the concrete PowerShell checklist in [QUICKSTART.md](QUICKSTART.md). For deployment details, alternative environments, expected browser flow, simulation, and troubleshooting, use [SETUP.md](SETUP.md). The important current limitation is that Bridgit implements SP-initiated SAML while TP-Link's documented Omada launch flow is primarily IdP-initiated; controllers without an SP-initiated SSO action require the planned Omada launcher before interactive login can work.

Omada creates its SP metadata only after importing IdP metadata. Bridgit therefore has an offline metadata command that does not require Pocket ID or Omada SP configuration.

### 1. Create a persistent signing keypair

Keep these files across upgrades and container recreation. Replacing them requires updating the trusted IdP metadata in Omada.

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout saml.key -out saml.crt -days 3650 \
  -subj "/CN=bridge.example.com"
```

Protect `saml.key` as a secret. The certificate is public and appears in IdP metadata.

### 2. Generate Bridgit IdP metadata

```sh
export BRIDGIT_PUBLIC_URL=https://bridge.example.com
export BRIDGIT_SAML_CERT_FILE=./saml.crt
export BRIDGIT_SAML_KEY_FILE=./saml.key
./bridgit metadata > bridgit-idp-metadata.xml
```

On Windows PowerShell 5, use `cmd /c "bridgit.exe metadata > bridgit-idp-metadata.xml"` so native XML bytes are not rewritten as UTF-16.

### 3. Configure Omada

In Omada Global View:

1. Open **Settings → SAML SSO**.
2. Add a SAML connection and upload `bridgit-idp-metadata.xml`.
3. Create an Omada SAML user group. Its name must match a Pocket ID group that will be authorized for Omada.
4. Download the SAML service-provider metadata from the new connection and save it as `omada-sp-metadata.xml`.

The exact menu names vary slightly by controller version. SAML SSO first appeared in the 5.15 line; the current Omada guide demonstrates version 6.1.

### 4. Configure Pocket ID

Create a confidential OIDC client:

- Callback URL: `https://bridge.example.com/oidc/callback`
- Public client: disabled
- Client authentication: client secret
- Allowed groups: grant the groups that may use Omada, or deliberately unrestrict the client

Bridgit requests `openid profile email groups`. Current Pocket ID versions restrict new OIDC clients by default, so a client with no allowed groups cannot be used.

### 5. Start Bridgit

Set the full environment from [.env.example](.env.example), then run:

```sh
./bridgit
```

Bridgit listens on plain HTTP by design and should sit behind the homelab TLS reverse proxy for `BRIDGIT_PUBLIC_URL`. It never derives security-sensitive URLs from `Host` or forwarded headers.

If the controller exposes an SP-initiated SSO action, test from that action. A Pocket ID user must have at least one group, and one returned group must exactly match an Omada SAML user-group name. See [SETUP.md](SETUP.md) before testing; browsing directly to `/saml/sso` does not start a login.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `BRIDGIT_PUBLIC_URL` | yes | — | Public HTTPS origin, with no path |
| `BRIDGIT_LISTEN_ADDR` | no | `:8080` | Internal HTTP listener |
| `BRIDGIT_OIDC_ISSUER` | yes | — | Pocket ID issuer URL |
| `BRIDGIT_OIDC_CLIENT_ID` | yes | — | Pocket ID client ID |
| `BRIDGIT_OIDC_CLIENT_SECRET` | yes | — | Pocket ID client secret |
| `BRIDGIT_SAML_CERT_FILE` | yes | — | PEM signing certificate |
| `BRIDGIT_SAML_KEY_FILE` | yes | — | Matching RSA private key, at least 2048 bits |
| `BRIDGIT_SAML_SP_METADATA_FILE` | yes | — | Omada-exported SP metadata XML |
| `BRIDGIT_USERNAME_CLAIM` | no | `preferred_username` | OIDC claim mapped to `username` |
| `BRIDGIT_GROUPS_CLAIM` | no | `groups` | String-array OIDC claim mapped to `usergroup_name` |
| `BRIDGIT_TRANSACTION_TTL` | no | `1m` | OIDC continuation lifetime; maximum `90s` |
| `BRIDGIT_SESSION_TTL` | no | `8h` | Local Bridgit browser-session lifetime |
| `BRIDGIT_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, or `error` |

Endpoints:

- `GET /saml/metadata`
- `GET /saml/sso`
- `GET /oidc/callback`
- `POST /logout`
- `GET /healthz`
- `GET /readyz`

## Security and limitations

- HTTPS termination is mandatory for browser use because the session cookie is always `Secure` and uses the `__Host-` prefix.
- SP metadata is a trust allowlist, not merely descriptive configuration. Review it and supply it as a local file; Bridgit never fetches arbitrary metadata URLs.
- The signing key, OIDC client secret, authorization codes, tokens, SAML payloads, and claims must not be logged.
- Only one SP is configured in the MVP.
- SAML single logout, IdP-initiated login, HTTP-POST `AuthnRequest`, dynamic registration, SCIM, and multi-replica state are not implemented yet.
- Omada's IdP-initiated launch uses a controller-specific Base64 `resourceId_omadaId` RelayState. It is intentionally deferred until the user's exported Omada metadata and actual controller version can be tested.

See [PLAN.md](PLAN.md) for the architecture and widening roadmap, [TEST_PLAN.md](TEST_PLAN.md) for automated and homelab validation, and [CONTEXT.md](CONTEXT.md) for the project vocabulary.
