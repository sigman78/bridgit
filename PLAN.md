# Bridgit implementation plan

Status: approved; secure MVP implemented, real-controller validation pending.

## Outcome

Build one small Go server that lets an Omada Controller use Pocket ID authentication:

1. Omada sends a SAML 2.0 authentication request to Bridgit.
2. Bridgit validates the request against administrator-supplied Omada SP metadata.
3. Bridgit redirects the browser through Pocket ID's OIDC authorization-code flow with state, nonce, and PKCE.
4. Bridgit verifies the returned ID token and creates a short-lived local session.
5. Bridgit returns a signed SAML response to Omada's allowlisted ACS URL, preserving RelayState.

Bridgit stores no passwords and does not provision or synchronize users.

## Initial compatibility profile

The MVP deliberately implements the smallest interoperable Web SSO profile needed by Omada:

- SAML 2.0 SP-initiated SSO.
- HTTP-Redirect binding for incoming `AuthnRequest`.
- HTTP-POST binding for outgoing `SAMLResponse`.
- Signed assertions using a persistent RSA X.509 keypair.
- One configured service provider, loaded from a local metadata XML file.
- Exact ACS and entity-ID allowlisting from that metadata.
- RelayState round-tripping without interpreting it.
- OIDC discovery and authorization-code exchange with a confidential Pocket ID client.
- OIDC scopes `openid profile email groups` and PKCE S256.
- Pocket ID `sub` as a persistent SAML NameID.
- OIDC `preferred_username` -> SAML `username`.
- OIDC `groups` -> multi-valued SAML `usergroup_name`.
- In-memory authentication transactions, sessions, and replay cache for a single process.

Omada's current setup guide requires the custom `username` and `usergroup_name` attributes, imports IdP metadata, and identifies its entity ID and reply/ACS URL in downloaded SP metadata. The guide also describes a special Base64 RelayState for IdP-initiated launch; that is a compatibility extension, not part of the first SP-initiated slice.

## Trust boundaries and invariants

- Only SP entity IDs and ACS endpoints present in configured SP metadata receive assertions.
- OIDC issuer discovery must match the configured issuer exactly.
- ID token signature, issuer, audience, expiry, and nonce are verified before claims become a principal.
- OAuth state and PKCE verifier are random, short-lived, server-side, and consumed atomically once.
- Each SAML request ID is accepted for assertion issuance at most once within the replay window.
- Session cookies contain only random identifiers and use `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/` (`__Host-bridgit_session` on HTTPS).
- Public endpoint URLs come only from an explicit public base URL; forwarded headers are not trusted.
- Production public URLs and Pocket ID issuer URLs must use HTTPS. Tests may use loopback HTTP.
- Credentials, authorization codes, tokens, SAML payloads, and full claim sets are never logged.
- Startup fails closed for invalid URLs, keypairs, metadata, claim configuration, or OIDC discovery.
- HTTP server read-header, read, write, idle, and graceful-shutdown timeouts are explicit.

## Go shape

Use one module and keep application packages internal until a genuine reusable API appears:

```text
cmd/bridgit/             process startup, signals, dependency wiring
internal/config/         environment parsing and fail-closed validation
internal/identity/       Principal and claim translation vocabulary
internal/oidcclient/     discovery, auth URL, code exchange, ID-token verification
internal/samlidp/        crewjam adapter, SP metadata registry, Omada attributes
internal/session/        concurrency-safe TTL transactions, sessions, replay IDs
internal/server/         HTTP routes and browser-flow orchestration
testdata/                generated test certificates and SP metadata fixtures
```

There will be no generic `utils`, global mutable state, framework, database, or public package tree. Protocol-specific types stay behind their adapters. The server is assembled with a small constructor and tested through `http.Handler`, while time, randomness, and state storage are narrow injected dependencies where determinism matters.

Primary dependencies:

- `github.com/crewjam/saml` for SAML parsing, metadata, assertion construction/signing, and test-side SAML validation.
- `github.com/coreos/go-oidc/v3/oidc` plus `golang.org/x/oauth2` for OIDC discovery, authorization, exchange, and ID-token validation.
- Go standard library for HTTP, configuration, logging, state, cryptography, and lifecycle.

Dependencies will be pinned, checked with `govulncheck`, and kept behind the two protocol adapters. Target Go is 1.26; the workstation's current Go 1.14.6 is too old for current `crewjam/saml` (which declares Go 1.22) and must be replaced or bypassed with a local modern toolchain before implementation.

## External interface

HTTP endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/saml/metadata` | Bridgit IdP metadata for upload to Omada |
| `GET` | `/saml/sso` | SAML HTTP-Redirect SSO endpoint |
| `GET` | `/oidc/callback` | Pocket ID authorization callback |
| `POST` | `/logout` | Delete only the local Bridgit session |
| `GET` | `/healthz` | Process liveness |
| `GET` | `/readyz` | Configuration/discovery readiness |

MVP environment configuration:

| Variable | Meaning | Default |
| --- | --- | --- |
| `BRIDGIT_PUBLIC_URL` | Externally visible HTTPS origin | required |
| `BRIDGIT_LISTEN_ADDR` | HTTP listen address behind the TLS proxy | `:8080` |
| `BRIDGIT_OIDC_ISSUER` | Pocket ID issuer origin | required |
| `BRIDGIT_OIDC_CLIENT_ID` | Pocket ID client ID | required |
| `BRIDGIT_OIDC_CLIENT_SECRET` | Pocket ID client secret | required |
| `BRIDGIT_SAML_CERT_FILE` | Persistent PEM signing certificate | required |
| `BRIDGIT_SAML_KEY_FILE` | Matching PEM private key | required |
| `BRIDGIT_SAML_SP_METADATA_FILE` | Omada SP metadata XML | required for readiness/SSO |
| `BRIDGIT_USERNAME_CLAIM` | OIDC source for `username` | `preferred_username` |
| `BRIDGIT_GROUPS_CLAIM` | OIDC source for `usergroup_name` | `groups` |
| `BRIDGIT_TRANSACTION_TTL` | OIDC continuation lifetime | `1m` (maximum `90s`) |
| `BRIDGIT_SESSION_TTL` | Local bridge session lifetime | `8h` |
| `BRIDGIT_LOG_LEVEL` | Structured log threshold | `info` |

The Pocket ID callback registered for the client is `${BRIDGIT_PUBLIC_URL}/oidc/callback`. Pocket ID access must also be granted to the relevant Pocket ID groups because new clients are restricted by default in current Pocket ID versions.

## Test-driven delivery

Tests exercise observable HTTP/protocol behavior. A local fake OIDC provider serves discovery, token, and JWKS endpoints; a real `crewjam/saml` service-provider instance generates requests and verifies returned assertions. Internal collaborators are not mocked merely to assert call sequences.

Each item is one red-green-refactor cycle, in this order:

1. IdP metadata exposes the configured entity ID, SSO URL, binding, and certificate.
2. A valid registered-SP request redirects to OIDC with state, nonce, PKCE, and required scopes.
3. A verified OIDC callback consumes state once, establishes an opaque session, and returns to the original SAML request.
4. The resumed request produces an SP-verifiable signed assertion with correct audience, recipient, request correlation, NameID, `username`, `usergroup_name`, and unchanged RelayState.
5. Unknown SPs and unregistered ACS URLs fail without beginning OIDC.
6. Wrong/replayed state, wrong nonce, bad issuer/audience/signature, expired token, and missing required username/groups fail closed.
7. A replayed SAML request ID cannot produce another assertion.
8. Expired transactions/sessions are rejected and eventually removed.
9. Logout clears the local session; health and readiness report their distinct contracts.
10. Configuration errors produce actionable startup failures without exposing secrets.

After every green cycle: run focused tests, then `go test ./...`; after the MVP is green: run `go test -race ./...`, `go vet ./...`, and `govulncheck ./...`.

## Delivery increments

### Increment 1: protocol tracer

- Modern Go module and test harness.
- Keypair and Omada metadata fixture loading.
- IdP metadata endpoint.
- One complete SP-initiated browser flow through a fake OIDC provider to a cryptographically verified SAML assertion.

### Increment 2: secure MVP

- All negative-path and replay tests above.
- Strict environment configuration.
- Bounded in-memory TTL stores with cleanup.
- Secure cookie, request limits, timeouts, structured logs, health/readiness, graceful shutdown.
- README with Pocket ID and Omada two-stage setup instructions.

### Increment 3: practical Omada compatibility

- Validate against metadata exported by the user's actual Omada Controller/version.
- Adjust only the Omada profile adapter if its XML/claim expectations differ.
- Add IdP-initiated launch with configured Omada entity ID and Base64 `resourceId_omadaId` RelayState.
- Honor relevant `ForceAuthn` behavior if Omada emits it.
- Add HTTP-POST `AuthnRequest` resume support only if observed or needed.

### Increment 4: modest widening

- Multiple SP metadata files and per-SP claim mappings in a small YAML config.
- Optional group allowlist/renaming per SP.
- Certificate rotation with overlapping published signing certificates.
- Pluggable state storage only when multiple replicas are actually required.
- Container image, non-root runtime, read-only filesystem, and deployment example.

SAML single logout, OIDC refresh-token storage, dynamic SP registration, a web admin UI, SCIM, arbitrary expression-based claim mapping, and multi-replica state are explicit non-goals until a concrete consumer requires them.

## MVP acceptance

- Omada can import Bridgit metadata and initiate SSO.
- An allowed Pocket ID principal lands in Omada with the intended Omada SAML group.
- Omada rejects a tampered assertion, and Bridgit rejects tampered OIDC/SAML inputs.
- An unregistered SP/ACS cannot turn Bridgit into an open assertion signer.
- Restarting the process invalidates only in-flight/local sessions; the persistent SAML certificate keeps Omada trust intact.
- The executable starts from environment variables alone and is ready for a later container wrapper.

## Evidence behind the profile

- Crewjam supports the SAML Web SSO profile, Redirect/POST requests, POST responses, and signed assertions: <https://github.com/crewjam/saml>.
- Crewjam's IdP API delegates session acquisition to the application and validates an AuthnRequest's issuer/ACS against SP metadata: <https://github.com/crewjam/saml/blob/main/identity_provider.go>.
- `go-oidc` performs discovery and ID-token verification but documents nonce checking as the caller's responsibility: <https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc>.
- Pocket ID documents confidential authorization-code clients and the `openid profile email groups` usage in client examples: <https://pocket-id.org/docs/guides/oidc-client-authentication> and <https://pocket-id.org/docs/client-examples/opencloud>.
- Omada documents metadata exchange, Entity ID/ACS configuration, RelayState, and exact `username` / `usergroup_name` attributes: <https://support.omadanetworks.com/en/document/26917/?app=web>.
