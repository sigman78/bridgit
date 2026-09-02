# Bridgit test plan

Status: active

This plan verifies that Bridgit safely translates a Pocket ID-authenticated OIDC principal into a SAML assertion accepted by an explicitly configured service provider. Omada Controller is the release-gating service provider for the MVP.

## Objectives

Testing must establish that:

1. A valid Omada-initiated login completes through Pocket ID and returns the user to Omada with the intended group.
2. No unverified OIDC identity can become a SAML principal.
3. Bridgit cannot be used as an open assertion signer for an unknown entity or ACS URL.
4. Browser continuations, sessions, and SAML requests cannot be replayed outside their intended lifetime.
5. Metadata, certificate, configuration, and operational failures are explicit and fail closed.
6. The process remains suitable for a single-instance homelab deployment behind an HTTPS reverse proxy.

The plan favors protocol-level tests through HTTP handlers and cryptographic verification. Tests should remain valid if packages are refactored internally.

## Risk priorities

| Priority | Meaning | Examples |
| --- | --- | --- |
| P0 | Release blocker; authentication bypass, assertion misdelivery, signature failure, or broken Omada login | Invalid ID token accepted, unregistered ACS receives assertion, wrong Omada group, replay succeeds |
| P1 | Important operational or compatibility defect with a safe failure mode | Expiry behavior, malformed configuration, restart behavior, proxy/browser compatibility |
| P2 | Future surface or non-critical hardening | Multiple SPs, IdP-initiated login, SLO, certificate rotation |

Any security boundary defect is P0 even if it occurs only in an unusual input case.

## Test layers

### Fast automated tests

Run on every change. A local OIDC test server exposes real discovery, token, and JWKS HTTP endpoints. A real `crewjam/saml` service provider creates authentication requests and cryptographically validates returned assertions. Time, keys, metadata, and browser cookies are controlled test inputs.

Small package tests are appropriate for deterministic configuration, bounded state, and key-loading behavior. Protocol behavior should be tested through public HTTP or adapter interfaces rather than by asserting internal calls.

### Automated security and quality checks

Run in CI and before release:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
govulncheck ./...
go build -trimpath ./cmd/bridgit
```

The race run should execute on a Linux CI runner with CGO support. The current Windows workstation has no C compiler, so it cannot provide the race result locally.

Fuzz targets should run for a bounded period in regular CI and for longer before release:

```sh
go test -fuzz=FuzzServiceProviderMetadata -fuzztime=30s ./internal/samlidp
go test -fuzz=FuzzOIDCClaims -fuzztime=30s ./internal/oidcclient
```

These commands become release requirements after the corresponding planned fuzz targets exist.

### Homelab interoperability tests

Automated protocol tests do not prove Omada compatibility. Every release candidate must complete the manual lab run against the actual Pocket ID and Omada versions intended for deployment, through the real reverse proxy and at least one supported browser.

## Test environments

| Environment | Purpose | Required components |
| --- | --- | --- |
| Local/CI | Deterministic behavior and negative paths | Go 1.26.6+, fake OIDC HTTP server, Crewjam SP verifier, generated RSA keys |
| Race CI | Concurrency correctness | Linux amd64, CGO-enabled Go, `-race` |
| Homelab staging | Release-gating interoperability | Actual Pocket ID, actual Omada Controller, HTTPS reverse proxy, persistent Bridgit keypair |
| Browser matrix | Cookie and redirect behavior | Current Firefox and Chromium; private/incognito session for clean-state runs |

Record exact Pocket ID, Omada, browser, reverse-proxy, Go, and Bridgit versions with each lab result.

## Test data and fixtures

- Generate ephemeral RSA keys for automated tests. Never check a private deployment key into the repository.
- Keep a sanitized copy of real Omada SP metadata under `testdata/` after it is supplied. Internal hostnames may be replaced consistently, but entity ID, ACS shape, bindings, indices, and certificate descriptors must remain structurally representative.
- Use distinct example domains for the bridge, registered Omada SP, unknown SP, and attacker ACS.
- Include principals with one group, multiple groups, Unicode names, XML-sensitive characters, and renamed usernames.
- Keep tokens short-lived and generate them inside tests so expiry, nonce, issuer, audience, signature, and claim types are independently controllable.
- Never place real client secrets, authorization codes, ID tokens, session IDs, or private claims in fixtures or test logs.

## Existing automated baseline

These behaviors are implemented and passing today.

| ID | Priority | Behavior | Evidence |
| --- | --- | --- | --- |
| META-001 | P0 | IdP metadata contains the configured entity ID, Redirect SSO endpoint, and exact signing certificate | `TestMetadataPublishesConfiguredIdentityProvider` |
| META-002 | P1 | Offline `bridgit metadata` works before Omada SP and Pocket ID configuration exist | `TestMetadataCommandBootstrapsOmadaWithoutSPConfiguration` |
| OIDC-001 | P0 | Authorization request contains state, nonce, PKCE S256, callback, client ID, and required scopes | `TestAuthorizationURLProtectsTheOIDCRequest` |
| OIDC-002 | P0 | A signed token maps `sub`, username, profile, email, and multiple groups | `TestCompleteVerifiesTokenAndMapsPocketIDClaims` |
| OIDC-003 | P0 | Nonce mismatch and missing Omada groups are rejected | `TestCompleteRejectsNonceMismatchAndMissingOmadaGroups` |
| FLOW-001 | P0 | A registered SP request begins the protected OIDC flow | `TestRegisteredServiceProviderStartsProtectedOIDCLogin` |
| FLOW-002 | P0 | Callback establishes an opaque secure session and resumes the original SAML request | `TestOIDCCallbackEstablishesSessionAndResumesSAMLRequest` |
| SAML-001 | P0 | Crewjam accepts the signed response with request correlation, NameID, Omada attributes, and RelayState | `TestAuthenticatedPrincipalBecomesVerifiableOmadaAssertion` |
| TRUST-001 | P0 | Unknown entity IDs and unregistered ACS URLs fail before OIDC | `TestUnknownServiceProviderAndUnregisteredACSFailBeforeOIDC` |
| REPLAY-001 | P0 | OAuth state is single-use | `TestOIDCStateCannotBeReused` |
| REPLAY-002 | P0 | A SAML request ID cannot issue a second assertion | `TestAuthenticatedSAMLRequestCannotIssueASecondAssertion` |
| STATE-001 | P1 | Pending transaction storage is bounded and expired entries are reclaimed | `TestMemoryBoundsPendingTransactionsAndReclaimsExpiredEntries` |
| OPS-001 | P1 | Health, readiness, and local logout have their documented behavior | `TestOperationalEndpointsAndLocalLogout` |
| CFG-001 | P1 | Complete configuration loads with documented defaults | `TestLoadAcceptsCompleteProductionEnvironmentAndAppliesDefaults` |
| CFG-002 | P0 | Insecure public URL and an OIDC continuation longer than SAML validity are rejected | Configuration rejection tests |

## Planned automated coverage

Implement these one vertical red-green cycle at a time, in priority order. Do not create all tests in advance.

### P0: identity verification

| ID | Scenario | Expected result |
| --- | --- | --- |
| OIDC-004 | ID token has wrong issuer | Callback returns a generic failure; no session or assertion is created |
| OIDC-005 | ID token has wrong or missing audience | Callback fails closed |
| OIDC-006 | ID token signature is invalid or uses an unadvertised key | Callback fails closed; JWKS refresh cannot make the bad token valid |
| OIDC-007 | ID token is expired or not yet valid | Callback fails closed |
| OIDC-008 | ID token is missing `sub` or configured username | Callback fails closed |
| OIDC-009 | Username is not a string, groups is not a string array, or a group is empty | Callback fails closed |
| OIDC-010 | Pocket ID returns `error=access_denied`, missing code, or token-endpoint error | State is consumed once, response is generic, and no session is created |
| OIDC-011 | Discovery issuer differs by host, path, or trailing slash | Startup fails; issuer comparison is exact |

### P0: SAML trust and assertion integrity

| ID | Scenario | Expected result |
| --- | --- | --- |
| SAML-002 | Authentication request is malformed, expired, wrong version, or has wrong destination | HTTP 400; OIDC is not contacted |
| SAML-003 | ACS index and ACS URL conflict with registered metadata | HTTP 400; no assertion is produced |
| SAML-004 | Returned SAML response or assertion is changed after signing | Crewjam SP verification fails |
| SAML-005 | Assertion certificate differs from imported IdP metadata | SP verification fails |
| SAML-006 | Principal has multiple groups | One `usergroup_name` attribute contains all values in stable input order |
| SAML-007 | Username or group contains `&`, `<`, quotes, or Unicode | XML remains valid and the SP receives the exact original values |
| SAML-008 | RelayState is absent, ordinary, and at its accepted boundary size | It is returned unchanged and never interpreted as a URL by Bridgit |
| TRUST-002 | Metadata contains no SP descriptor, no ACS, relative ACS, or malformed XML | Startup fails with a non-secret diagnostic |

### P0: state, cookie, and replay behavior

| ID | Scenario | Expected result |
| --- | --- | --- |
| STATE-002 | Authentication transaction expires before callback | Callback returns 400; token endpoint is not called |
| STATE-003 | Bridge session expires | The next valid SAML request starts a fresh OIDC flow |
| STATE-004 | Session cookie is absent, random, truncated, or from a restarted process | It is treated as unauthenticated without leaking its value |
| STATE-005 | Pending-transaction capacity is exhausted through valid SAML requests | Additional request receives 503; memory remains bounded |
| REPLAY-003 | Two callbacks race with the same state | Exactly one may establish a session |
| REPLAY-004 | Two authenticated requests race with the same SAML request ID | Exactly one may produce an assertion |
| COOKIE-001 | Successful callback cookie inspection | Cookie is opaque, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, has no Domain, and expires with the server session |

### P1: configuration and signing material

| ID | Scenario | Expected result |
| --- | --- | --- |
| CFG-003 | Each required environment variable is individually missing or blank | Startup names the missing variable without printing other values |
| CFG-004 | Durations are invalid, zero, negative, or exceed protocol limits | Startup fails |
| CFG-005 | Public URL contains user info, path, query, fragment, or non-HTTPS scheme | Startup fails |
| KEY-001 | Certificate and key do not match | Startup and metadata command fail |
| KEY-002 | Key is non-RSA or below 2048 bits | Startup fails |
| KEY-003 | Certificate is expired or not yet valid | Startup fails |
| KEY-004 | Metadata file exceeds the size limit | Startup fails without excessive allocation |
| META-003 | Metadata command output is byte-valid XML under Unix shell and Windows invocation documented in the README | Omada import succeeds |

### P1: operational behavior

| ID | Scenario | Expected result |
| --- | --- | --- |
| OPS-002 | Unsupported methods are sent to every endpoint | 405 where applicable; no state mutation |
| OPS-003 | OIDC discovery, token, or JWKS endpoint hangs beyond its timeout | Startup/callback fails within the configured bound |
| OPS-004 | Process receives SIGTERM with idle connections | Listener stops and graceful shutdown completes within ten seconds |
| OPS-005 | Process restarts with the same keypair | Old local sessions fail, but generated IdP metadata keeps the same certificate and entity ID |
| OPS-006 | Process restarts with a different keypair | Metadata changes; documented Omada trust update is required |
| LOG-001 | Success and every negative flow run with captured logs | No secret, code, token, SAML payload, cookie, state, nonce, or full claim set appears |
| CONC-001 | Many independent SAML/OIDC flows execute concurrently | No race, cross-user identity mix-up, deadlock, or unbounded state growth |

### P1: fuzz and parser resilience

| ID | Target | Seed corpus and invariant |
| --- | --- | --- |
| FUZZ-001 | SP metadata parser | Valid minimal metadata plus malformed/truncated/nested XML; never panic, hang, or accept relative ACS |
| FUZZ-002 | OIDC claim translation | Valid claim set plus arbitrary JSON types; never panic and never create a partial principal |
| FUZZ-003 | SAML Redirect request handler | Valid Crewjam request plus corrupted Base64/DEFLATE/XML; never panic or begin OIDC for invalid input |

## Homelab release-gating runbook

### Preconditions

- Record Pocket ID and Omada Controller versions.
- Put both products and Bridgit behind their intended HTTPS names and reverse proxy.
- Create a persistent Bridgit signing keypair.
- Create two Pocket ID users: one authorized with a matching Omada group and one intentionally unauthorized.
- Preserve a local Omada administrator login as a recovery path.
- Start each run in a clean browser profile or clear Bridgit, Pocket ID, and Omada cookies.

### LAB-001: metadata bootstrap

1. Run `bridgit metadata` with only the public URL and signing-key variables.
2. Parse the output locally as XML.
3. Import it as a new Omada SAML connection.
4. Download Omada SP metadata and configure Bridgit with it.
5. Start Bridgit and request `/saml/metadata` and `/readyz`.

Pass when Omada accepts the metadata, Bridgit accepts Omada's export, readiness is 200, and the served metadata matches the offline entity ID and certificate.

### LAB-002: authorized SP-initiated login

1. Open the Omada login page and choose the Bridgit SAML connection.
2. Confirm the browser reaches Pocket ID and displays the expected client.
3. Authenticate with the authorized user's passkey.
4. Confirm the browser POSTs back only to the ACS shown in Omada metadata.
5. Confirm Omada creates/selects the user with the expected SAML group and privileges.

Pass when the user reaches Omada without a second credential prompt and has exactly the configured role/site permissions.

### LAB-003: multiple-group mapping

1. Give the authorized user multiple Pocket ID groups, including one exact Omada group.
2. Repeat SP-initiated login in a clean session.
3. Inspect the assertion only in a controlled test environment if troubleshooting is required.

Pass when Omada selects the intended matching group and no group value is concatenated, dropped, or XML-corrupted.

### LAB-004: access denial

Run these independently:

- User is excluded by Pocket ID's allowed-group policy.
- User reaches Bridgit but has no groups claim.
- User has groups, but none match an Omada SAML user group.

Pass when none of the cases grants an Omada session or fallback privilege. Record whether denial is displayed by Pocket ID, Bridgit, or Omada.

### LAB-005: RelayState and repeated login

1. Start login from Omada rather than navigating directly to Bridgit.
2. Complete login and note the final Omada page.
3. Sign out of Omada, retain the Bridgit session, and start a new Omada login.
4. Repeat after local Bridgit logout.

Pass when RelayState is preserved, the first repeated login may reuse the valid Bridgit session, and local Bridgit logout forces a new Pocket ID flow. Local logout is not expected to perform SAML SLO or terminate the Omada session.

### LAB-006: restart and key persistence

1. Establish a working login.
2. Restart Bridgit with unchanged configuration and key files.
3. Start a fresh Omada login.
4. Compare IdP metadata before and after restart.

Pass when the pre-restart Bridgit cookie is no longer useful, the new login succeeds, and Omada does not require metadata re-import.

### LAB-007: browser and proxy compatibility

Repeat LAB-002 with current Firefox and Chromium through the intended reverse proxy. Verify callback URL, redirects, form POST, `Secure` cookie behavior, and absence of mixed-content warnings.

Pass when both browsers complete the same flow and the proxy does not need trusted forwarded headers for Bridgit to construct protocol URLs.

## Future-feature gates

The following tests are designed only when the corresponding feature is approved:

- IdP-initiated Omada launch with the Base64 `resourceId_omadaId` RelayState.
- `ForceAuthn` semantics and Pocket ID reauthentication.
- Incoming HTTP-POST `AuthnRequest` continuation.
- Multiple SPs with isolated claim mappings and no cross-SP ACS use.
- Certificate rotation with overlapping published certificates.
- Shared state and replay protection across multiple replicas.
- SAML single logout.

## Exit criteria

The MVP is releasable for a specific homelab when all of the following are true:

- All implemented P0 and P1 automated tests pass on the release commit.
- `go test -race`, `go vet`, build, and `govulncheck` pass in CI.
- No reachable known vulnerability is reported for the release toolchain or dependencies.
- LAB-001, LAB-002, LAB-004, LAB-006, and LAB-007 pass against the recorded Pocket ID and Omada versions.
- The actual Omada SP metadata is represented by a sanitized regression fixture.
- No test or captured log contains secrets or reusable authentication material.
- Any deferred P0/P1 case has a documented reason, owner, and safe operational mitigation.

Coverage percentage is recorded for trend information but is not a release gate. Behavioral traceability and trust-boundary coverage are the gate.

## Test evidence

For each release candidate retain:

- Commit identifier and dependency lock files.
- Go version and `go env` platform summary.
- Automated test, race, vet, build, and vulnerability-scan output.
- Sanitized lab environment/version matrix.
- Pass/fail notes for each required LAB case.
- Browser network trace only when needed for diagnosis, scrubbed of cookies, codes, tokens, and SAML payloads before retention.

## References

- [Architecture and delivery plan](PLAN.md)
- [Deployment and Omada setup](README.md)
- [Domain language](CONTEXT.md)
- [Omada SAML SSO guide](https://support.omadanetworks.com/en/document/26917/?app=web)
- [Pocket ID documentation](https://pocket-id.org/docs/)
- [Crewjam SAML library](https://github.com/crewjam/saml)
