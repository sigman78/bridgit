# Bridgit security audit

Audited: 2026-09-01 · Last updated: 2026-09-02
Scope: `cmd/bridgit`, `internal/*` at commit `f5fdc27` ("Initial secure OIDC to SAML bridge MVP").
Method: independent code audit, two parallel reviews, plus targeted execution probes.

## Remediation status

3 of 20 findings are fixed and in review; 17 remain open.

| | Findings |
| --- | --- |
| **Fixed, in review** | BR-01, BR-02, BR-17 |
| **Open — before exposure** | BR-03, BR-05, BR-07 |
| **Open — before publishing** | BR-04, BR-06, BR-08, BR-09, BR-12, BR-13, BR-14, BR-16, BR-18 |
| **Open — needs a decision, not code** | BR-10, BR-11 |
| **Accepted / no action** | BR-15, BR-19, BR-20, structural limitation |

Both **High** findings are fixed. Line references in the fixed findings below point at the
pre-fix code and no longer resolve; each carries a *Fixed* block naming the commit.

The fixes are stacked pull requests, in merge order:

| PR | Commit | Finding |
| --- | --- | --- |
| [#1](https://github.com/sigman78/bridgit/pull/1) | `3d18633` | BR-01 — bind transactions to the browser |
| [#2](https://github.com/sigman78/bridgit/pull/2) | `19c675e` | BR-02 — independent SAML session index |
| [#3](https://github.com/sigman78/bridgit/pull/3) | `6888749` | BR-17 — advertise the NameID format actually issued |

## Method

- Full read of all application source (~1,000 lines of Go across 8 packages) and its tests.
- Source-level review of the protocol libraries **only where Bridgit's own correctness depends
  on their behaviour** — `crewjam/saml@v0.5.1`, `goxmldsig@v1.6.0`, `go-oidc/v3@v3.21.0`,
  `oauth2@v0.36.0`, `go-jose/v4@v4.1.4`, Go 1.26.7 stdlib. The libraries are treated as trusted,
  battle-tested dependencies; they were not audited for their own vulnerabilities.
- Two independent reviews covering the SAML IdP path and the OIDC relying-party / session layer
  separately. Findings below are the merged, cross-corroborated set.
- `govulncheck ./...` — **0 reachable vulnerabilities** (19 advisories in required modules, none
  called).
- `go test ./...` — all pass. `-race` could not run locally (no cgo toolchain); already
  documented as a CI gap in TEST_PLAN.md.
- Executed probes against Bridgit's real `http.Handler` to confirm BR-03 and BR-08 empirically
  rather than by inspection.

Severity reflects impact on this deployment: an SSO bridge that mints credentials for a network
controller. Availability of the bridge equals availability of administrative access.

---

## Ranked findings

| ID | Severity | Status | Finding | Confirmed by |
| --- | --- | --- | --- | --- |
| BR-01 | **High** | ✅ Fixed ([#1](https://github.com/sigman78/bridgit/pull/1)) | OAuth `state` is not bound to the browser — login CSRF / session swap | Code, both reviews, existing test |
| BR-02 | **High** | ✅ Fixed ([#2](https://github.com/sigman78/bridgit/pull/2)) | Bridge session cookie is transmitted to Omada as `SessionIndex` | Library source, verified in emitted XML |
| BR-03 | **Medium** | ☐ Open | Unauthenticated login-flow denial of service in 0.44 s | **Executed probe** |
| BR-04 | **Medium** | ☐ Open | Assertion encryption fails open silently | Library source |
| BR-05 | **Medium** | ☐ Open | No authentication audit log at all | Code |
| BR-06 | **Medium** | ☐ Open | 8 h sessions, no upstream revocation, no TTL ceiling | Code |
| BR-07 | **Medium** | ☐ Open | No `Cache-Control` or security headers on identity-bearing responses | Library source + code |
| BR-08 | **Low** | ☐ Open | Unauthenticated nil-pointer panic (log-flood primitive) | **Executed probe** |
| BR-09 | **Low** | ☐ Open | Authenticated session-table exhaustion blocks logins for up to 8 h | Code |
| BR-10 | **Low** | ☐ Open — needs a decision | Multi-valued `usergroup_name` vs Omada's single-group support | Vendor docs + code |
| BR-11 | **Low** | ☐ Open — needs a decision | `preferred_username` is mutable; no claim canonicalisation | Code |
| BR-12 | **Low** | ☐ Open | Log injection via unsanitised `Issuer` / `Destination` | Library source |
| BR-13 | **Low** | ☐ Open | Client secret sent in POST body on auth-style probe | Library source |
| BR-14 | **Low** | ☐ Open | `.gitignore` uses exact paths, not patterns, for key material | Code |
| BR-15 | Info | ○ Accepted | `azp` and `iat` are not validated | Library source |
| BR-16 | Info | ☐ Open | Empty nonce / PKCE verifier not defensively rejected | Code |
| BR-17 | Info | ✅ Fixed ([#3](https://github.com/sigman78/bridgit/pull/3)) | Metadata advertises `transient` NameID, assertions emit `persistent` | Library source + code |
| BR-18 | Info | ☐ Open | Signing certificate expiry checked only at startup | Code |
| BR-19 | Info | ○ Accepted | `AuthnInstant` in local timezone; `@Address` is the proxy's IP | Library source + code |
| BR-20 | Info | ○ Deferred to CI | `-race` has never run | TEST_PLAN.md |

---

## High

### BR-01 — OAuth `state` is not bound to the browser

**✅ Fixed** in `3d18633` ([PR #1](https://github.com/sigman78/bridgit/pull/1)).
`GetSession` mints a binding secret, stores its SHA-256 on the transaction, and returns it as a
short-lived `__Host-bridgit_txn` cookie. `handleOIDCCallback` requires that cookie and compares
it with `subtle.ConstantTimeCompare` before exchanging the code. The cookie is read *before*
`TakeTransaction`, so a cookieless callback cannot cancel somebody else's pending login, and it
is cleared once the transaction is taken. `PutTransaction` now rejects an unbound transaction, so
the binding cannot be omitted by a future caller. Covered by
`TestOIDCCallbackRequiresTheBrowserThatStartedTheTransaction` (absent, empty, and foreign
cookie), `TestRejectedCallbackLeavesTheTransactionUsable`,
`TestTransactionCookieIsScopedAndClearedOnCompletion`, and
`TestPutTransactionRequiresABrowserBinding`.

*Original finding, against pre-fix code:*

`internal/server/server.go:119,144,178-202`, `internal/session/memory.go:124`

`GetSession` generates `state`, `nonce`, and `pkceVerifier`, stores them in a process-global map
keyed by `state`, and redirects to Pocket ID — **setting no cookie on that response**. The
callback reads only `?state` and `?code`; it never reads a cookie. On success it unconditionally
sets `__Host-bridgit_session`, overwriting any session already in that browser.

`TestOIDCCallbackEstablishesSessionAndResumesSAMLRequest` sends the callback with **no cookies at
all** and succeeds. The vulnerability is demonstrated by the project's own test suite.

**Attack.** Mallory needs only a Pocket ID account permitted for the Bridgit client.

1. Mallory obtains a valid `AuthnRequest` URL — from Omada's SSO button, or forged, since
   requests are unsigned and unverifiable (see *Structural limitation*).
2. Her script hits `GET /saml/sso?SAMLRequest=…`; transaction `T(state=S, nonce=N, verifier=V)`
   is stored; she is redirected to Pocket ID.
3. She authenticates **as herself** and intercepts the redirect
   `https://bridge/oidc/callback?code=C&state=S` without letting it reach Bridgit.
4. She causes Alice's browser to perform a top-level GET of that URL. `SameSite=Lax` does not
   help: the callback reads no cookie, and Lax cookies *are stored* on a cross-site top-level
   navigation — that is how every OAuth callback works.
5. Bridgit consumes `T`, exchanges `C` against its own verifier `V`, matches nonce `N`, and
   plants a session for **Mallory** in **Alice's** browser for 8 hours. Alice's legitimate
   session, if any, is silently replaced.
6. Alice opens Omada and receives a signed assertion for `NameID=Mallory.sub`,
   `username=Mallory`, `usergroup_name=Mallory's groups`.

The transaction TTL (≤ 90 s) is not a mitigation: Mallory's server runs steps 2–3 on demand when
Alice loads her page.

**Impact.** Everything Alice does in the controller is attributed to, and later visible in, an
account Mallory controls. This defeats the central guarantee of an identity bridge.

**Fix.** In `GetSession`, set `__Host-bridgit_txn` to 32 random bytes
(`Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=<transactionTTL>`) and store `sha256` of it on
the `Transaction`. In `handleOIDCCallback`, require the cookie and compare with
`subtle.ConstantTimeCompare` **before** calling `Complete`; clear it afterwards. Add a test that
a callback without the cookie is rejected.

The reverse attack — injecting a victim's code into an attacker's transaction — is **not**
possible: PKCE binds the code to the transaction's own verifier, and `TakeTransaction` is atomic
and single-use.

### BR-02 — Bridge session cookie is shipped to Omada as `SessionIndex`

**✅ Fixed** in `19c675e` ([PR #2](https://github.com/sigman78/bridgit/pull/2)).
`BridgeSession` carries an independently generated `SAMLSessionIndex`, and that is what reaches
the service provider; the cookie no longer leaves the process. `PutSession` rejects a session
whose index is absent or equal to the session ID, so the two cannot silently converge again.
`TestAssertionDoesNotDiscloseTheBrowserSessionCookie` decodes the emitted `SAMLResponse` and
asserts neither cookie value appears in it — verified as a real control by reintroducing the old
assignment and watching it fail.

> **Residual, still open.** The second half of the recommended fix — keying the session map by
> `sha256(cookie)` so a heap dump does not yield usable cookies — was **not** implemented. Session
> IDs are still stored in plaintext in memory. Lower value than the disclosure itself, since it
> only matters against an attacker who can already read process memory, but it remains a
> reasonable hardening step. Tracked below under *Follow-up*.

*Original finding, against pre-fix code:*

`internal/server/server.go:175,213,216`

`samlSession` passes the raw `__Host-bridgit_session` value as both `saml.Session.ID` and
`.Index`. `Index` is transmitted: `identity_provider.go:830` writes it into
`<saml:AuthnStatement SessionIndex="...">`. Confirmed present in emitted assertion XML.
(`Session.ID` is never read by the core library and is harmless.)

**Impact.** A bearer credential for Bridgit is handed to a third-party system that will typically
persist it for single-logout, and which logs assertions. Anyone able to read Omada's database,
its logs, an unencrypted assertion (BR-04), or a SAML debugging tool can set that cookie and mint
fresh assertions for that user through `/saml/sso` for the remaining `SessionTTL`, and can call
`/logout` for them.

**Fix.** Generate a second independent random value at session creation, store it on
`BridgeSession`, and use it for `Index`. Additionally, key the session map by `sha256(cookie)` so
a heap dump does not yield usable cookies. crewjam's own reference implementation uses
independent values for exactly this reason.

---

## Medium

### BR-03 — Unauthenticated login-flow denial of service

`internal/session/memory.go:13,131`, `internal/server/server.go:193,198-200`

`MaxPendingTransactions` is 1024, and `PutTransaction` **rejects new entries** when full rather
than evicting old ones. Every cookieless `AuthnRequest` to `/saml/sso` creates one transaction
with a 60 s TTL. `UseSAMLRequest` is only reached on the *authenticated* path, so a single
captured or forged request can be replayed without limit.

**Confirmed by execution.** A probe driving crafted `AuthnRequest`s through Bridgit's real handler
hit the wall at request **#1025**, after which every login returned `503 Service Unavailable`.
Total elapsed: **0.44 seconds**. Sustaining the lockout needs roughly 17 requests per second. The
crafted request needs only the SP entity ID and ACS URL, both published in metadata.

**Impact.** Any unauthenticated party who can reach `/saml/sso` can hold SSO login closed
indefinitely. If SSO is the only path into the controller, that is a lockout.

**Fix.** Evict the oldest transaction instead of refusing the newest; once BR-01's cookie exists,
cap pending transactions to one per browser; rate-limit `/saml/sso` per client IP at the reverse
proxy; and log the 503 (BR-05).

### BR-04 — Assertion encryption fails open silently

`identity_provider.go:874-877`, `internal/samlidp/registry.go:22-44`

If the SP metadata contains no `KeyDescriptor` with `use="encryption"` (and no key-less
descriptor carrying a usable certificate), the library emits a **signed but cleartext**
assertion. No error, no log line, no configuration flag to require encryption.

**Impact.** The full claim set — subject, username, groups, email — plus the session identifier
from BR-02 travels in cleartext through the user's browser in a cacheable page (BR-07).

`identity_provider.go:986` also indexes `X509Certificates[0]` with no length check, so SP metadata
declaring an encryption descriptor with no certificate panics. `NewRegistry` does not validate
this.

**Fix.** Inspect your actual Omada metadata for an encryption certificate. If present, verify
encryption happens. If absent, record it as an accepted risk — and fix BR-02 so the session
identifier is not part of what leaks. Validate the certificate list in `NewRegistry`.

### BR-05 — No authentication audit log

`internal/server/server.go:114-155,164-204`

No package under `internal/` imports `log` or `log/slog`. There is no record of transaction
creation, callback success, callback failure or its reason (state miss, exchange error, nonce
mismatch, missing groups), capacity exhaustion, replay rejection, or logout. Failures return bare
HTTP status codes.

**Impact.** No forensic record. None of the attacks above would leave a trace, and BR-01 in
particular would be invisible afterwards. The README's own troubleshooting table cannot be
actioned, because a user missing a group surfaces only as a bare 401.

**Fix.** Emit structured `slog` events in `handleOIDCCallback` and `GetSession` with `event`,
`outcome`, `reason`, `sub`, `username`, `sp_entity_id`, `saml_request_id`, and the
proxy-supplied client IP. Never log codes, tokens, verifiers, cookie values, SAML payloads, or
full claim sets — PLAN.md already states this invariant, so the logging just needs to exist
within it.

### BR-06 — Sessions survive upstream deprovisioning

`internal/server/server.go:135-140`, `internal/config/config.go:90-93`

`BridgeSession` snapshots the principal **including groups** and is never revalidated. Disabling
a user, deleting them, or removing them from the authorised group in Pocket ID has no effect
until expiry. There is no idle timeout, no session rotation, and — unlike `TransactionTTL`, which
is capped at 90 s — `BRIDGIT_SESSION_TTL` has **no upper bound**, so a misconfiguration can
create arbitrarily long-lived sessions.

**Impact.** Up to an 8-hour window between offboarding and effective loss of access, on defaults.
This is the gap SSO is usually adopted to close.

**Fix.** Cap `SessionTTL` the way `TransactionTTL` is capped, and lower the default to 15–60 min.
Better: drop the bridge session entirely and re-run the OIDC flow on every SP request — Pocket
ID's own SSO session makes that invisible to users and gives you revocation for free.

### BR-07 — No cache or security headers on identity-bearing responses

`identity_provider.go:959-978`, `internal/samlidp/provider.go:69-75`, `internal/server/server.go:88`

`Cache-Control: no-store` is set only on `/healthz`. It is missing from the SSO redirect (which
carries `state`), the callback response (which carries `Set-Cookie`), and the **SAML auto-POST
page** — which crewjam writes with no headers at all, not even `Content-Type`. There is no
`X-Frame-Options`, `Referrer-Policy`, or CSP anywhere; `X-Content-Type-Options` appears only
incidentally via `http.Error`.

RelayState itself is safe — rendered through `html/template` with correct contextual escaping.
There is no XSS here.

**Impact.** A signed assertion sits in a cacheable HTML page in browser history and any
intermediate cache. Without `X-Frame-Options`, the auto-submit form can be framed for silent SSO
or clickjacking.

**Fix.** Wrap the mux in middleware setting `Cache-Control: no-store`, `Referrer-Policy:
no-referrer`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`. A CSP on the
auto-POST page needs a nonce, which requires supplying a custom
`IdentityProvider.ResponseFormTemplate`.

---

## Low

### BR-08 — Unauthenticated nil-pointer panic

An `AuthnRequest` omitting `<saml:Issuer>` dereferences nil at `identity_provider.go:446`.
**Confirmed by execution** through Bridgit's route. `net/http` recovers per connection, so this
drops the connection and writes a stack trace rather than crashing the process — one
unauthenticated GET per stack trace makes it a cheap log-flood primitive.

**Fix.** Reject requests with an absent or empty issuer in the `/saml/sso` handler before
delegating to `ServeSSO`.

### BR-09 — Authenticated session-table exhaustion

`internal/session/memory.go:14,100`. `maxBridgeSessions` is 4096, each entry lives the full 8 h,
and `PutSession` fails closed. An authorised user scripting 4096 logins through their existing
Pocket ID SSO session blocks **everyone's** callback with 503 for up to 8 hours. The 8192-entry
SAML request-ID cache (`memory.go:15,72-74`) has the same shape but self-heals in 90 s.

**Fix.** Per-subject session cap (e.g. 5, evict oldest) and evict-oldest rather than refusing.

### BR-10 — Multi-valued `usergroup_name` vs Omada's single-group support

`internal/server/server.go:208-211`. Bridgit maps every OIDC group into a multi-valued attribute.
authentik's Omada integration notes state **"Omada supports one SAML user group value per
user."** If Omada selects arbitrarily among the values, role assignment becomes nondeterministic
— a security problem if it can land on the more privileged group. All of the user's groups are
also forwarded regardless of relevance to Omada.

**Fix.** Establish Omada's actual behaviour, then send exactly one group under a documented
selection rule, or add a configurable group allowlist/prefix filter.

### BR-11 — `preferred_username` is mutable; no claim canonicalisation

`internal/config/config.go:80`, `internal/oidcclient/client.go:136-171`. OIDC Core §5.1 says RPs
MUST NOT rely on `preferred_username` being unique or stable. `sub` is correctly used for NameID,
but if Omada keys accounts on the `username` attribute, a user who can self-edit it could shadow
another account. Claim values also receive no trimming, no NFKC normalisation, no
control/format-character rejection, and no length cap; only empty group strings are rejected.

Realistic impact is account shadowing and audit confusion rather than privilege gain, since role
assignment is gated by the admin-controlled groups claim.

**Fix.** Document that the configured username claim must be immutable and admin-controlled;
offer `sub` as an alternative source. Trim, reject non-printable and format characters,
NFKC-normalise and reject if the value changes, cap length at 256, and dedupe groups.

### BR-12 — Log injection

Attacker-controlled `Issuer` and `Destination` values are interpolated unsanitised into error
strings at `identity_provider.go:231,237,433,449` and written to stdout via crewjam's plaintext
`logger.DefaultLogger` (wired at `provider.go:59`), newlines included. This forges log entries and
corrupts the JSON stream produced by `slog`.

**Fix.** Supply a `saml.Logger` adapter that routes through `slog` and escapes its input.

### BR-13 — Client secret sent in POST body on auth-style probe

`oauth2/internal/token.go:215-246`. The library auto-probes the token endpoint's authentication
style and, if the first attempt fails, retries with the client secret in the request **body**
rather than the `Authorization` header.

**Fix.** Set `oauth2Config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader` in
`internal/oidcclient/client.go`. Removes both the extra request and the body-borne secret.

### BR-14 — `.gitignore` uses exact paths for key material

`/saml.key` and `/saml.crt` are ignored only at the repository root, and `.env` is not ignored at
all (only `/bridgit.env`). A key generated in a subdirectory or under a different name is
committable.

**Fix.** Use patterns: `*.key`, `*.pem`, `.env`, `.env.*`, `!.env.example`.

---

## Informational

**BR-15 — `azp` and `iat` are not validated.** go-oidc explicitly skips `azp`
(`verify.go:250`) and never reads `iat`. Harmless against a single-tenant Pocket ID. If Bridgit
is ever pointed at a multi-client IdP that mints multi-audience tokens, add an
`azp == client_id` check in `Complete`.

**BR-16 — Empty nonce / verifier not defensively rejected.** `Complete` would accept
`expectedNonce == ""` against a token carrying `nonce: ""`, and `PutTransaction` does not require
`Nonce` or `PKCEVerifier` to be non-empty. Not reachable today, since both are always generated.
Add explicit guards at the top of `Complete`.

BR-01's fix added a `BindingHash` presence check to `PutTransaction` but deliberately left the
`Nonce` and `PKCEVerifier` guards alone, so this finding is **untouched**. The natural place to
finish it is the same validation block.

**BR-17 — NameID format mismatch. ✅ Fixed** in `6888749`
([PR #3](https://github.com/sigman78/bridgit/pull/3)). IdP metadata advertised only `transient`
(`identity_provider.go:164`) while assertions emit `persistent` (`server.go:218`), which a strict
SP rejects. `Provider.metadata()` now narrows `NameIDFormats` to `persistent` in the same loop
that already strips the POST binding. `TestMetadataNameIDFormatMatchesTheIssuedAssertion` fetches
published metadata, issues a real assertion, and compares the advertised format against the
emitted `NameID/@Format`, so the two cannot drift apart again from either side.
**Deployment note:** existing Omada connections hold the old metadata and should be re-imported.
The signing certificate and all endpoint URLs are unchanged, so trust is not disturbed.

**BR-18 — Certificate expiry checked only at startup.** `keypair.go:32-34` validates the
signing certificate once. A long-running process keeps signing with an expired certificate. Add a
periodic check that fails `/readyz`.

**BR-19 — Timestamp and address details.** `server.go:134` passes local `time.Now()`, so
`AuthnInstant` carries a local offset while every other timestamp is UTC; SAML says timestamps
SHOULD be UTC. Separately, crewjam fills `SubjectConfirmationData/@Address` from `RemoteAddr`
(`identity_provider.go:810`), which behind the reverse proxy is `127.0.0.1:port` — an interop
risk if Omada validates it, not a security issue.

**BR-20 — `-race` has never run.** Already acknowledged in TEST_PLAN.md and correctly deferred to
a Linux CI runner. The session store is the code most worth racing; treat CI as a release gate.

---

## Structural limitation (not fixable in Bridgit)

**`AuthnRequest` signatures are never verified.** `crewjam/saml` parses the `Signature` element
but never checks it, never reads the HTTP-Redirect `Signature`/`SigAlg` parameters, and provides
no way to set `WantAuthnRequestsSigned` on an `IdentityProvider` — the field its own validator
consults is never populated by `Metadata()`. Consequently anyone who can reach `/saml/sso` can
submit a well-formed request. This enables BR-01 step 1, BR-03, and BR-08, and it means an
attacker can drive assertion issuance for an already-authenticated victim.

This is inherent to the library. Compensate with rate limiting and network exposure control, and
record it as an accepted risk. Do not attempt to work around it in application code.

---

## Verified clean

Checked and found correct — the parts worth *not* changing:

- **ACS URL validation is strict.** `identity_provider.go:456-551` resolves the destination only
  from registered SP metadata endpoints. An unregistered URL fails closed and does **not** fall
  back to a default. No assertion redirection is possible. This is the most dangerous class of
  SAML IdP bug and it is handled.
- **Signing is correct.** Both Response and Assertion are enveloped-signed with RSA-SHA256 and
  exclusive C14N. `provider.go:58` correctly overrides the library's RSA-SHA1 default. The only
  remaining SHA-1 is the OAEP/MGF1 digest inside `EncryptedKey` — not a signature hash, and
  cryptographically acceptable.
- **Assertion binding is correct.** `Audience`, `InResponseTo`, `Recipient`, `NotBefore`, and
  `NotOnOrAfter` are all properly bound to the originating request.
- **PKCE is correct end to end.** `S256ChallengeOption` on authorization, `VerifierOption` on
  exchange, same transaction-held verifier both sides. `randomString(32)` yields 43 characters —
  exactly RFC 7636's minimum and identical to `oauth2.GenerateVerifier`.
- **Algorithm confusion is impossible.** go-oidc filters the discovery document's algorithm list
  down to asymmetric RS/ES/PS/EdDSA before handing it to go-jose, which rejects anything else at
  parse time. **`none` and HS256 can never be accepted**, even if the IdP advertises them.
  `InsecureSkipSignatureCheck` is not set. Exactly one signature is required.
- **No double-parse inconsistency.** go-oidc and the application unmarshal the *same* verified
  payload bytes with the same `encoding/json` semantics. The application never touches the JWS
  header. No header/payload or duplicate-key confusion.
- **Nonce is compared before the principal is built**, with `subtle.ConstantTimeCompare`, and a
  missing nonce is rejected. Consuming the transaction before the exchange is a deliberate
  protection, not a flaw — it prevents retrying different codes against one state.
- **No open redirect.** `ReturnURL` derives from `r.URL.RequestURI()`, but every hostile shape
  fails before the handler: `//`-prefixed and opaque request-targets are collapsed by
  `path.Clean` and answered with a 307 to the cleaned path without invoking the handler; `/\` does
  not match the mux prefix; CR/LF are rejected at URL parse. Any value reaching `PutTransaction`
  begins with a single `/`. Confirmed against the toolchain source.
- **No Referer leak of `code`/`state`.** The callback returns an immediate same-origin 303; no
  document is ever rendered at the callback URL, so nothing carries it as a Referer.
- **No XXE or entity expansion.** Go's `encoding/xml` treats DOCTYPE as an opaque directive with
  a nil entity map. `xml-roundtrip-validator` *is* invoked on the request path
  (`identity_provider.go:397`). Inflate is capped at 10 MiB.
- **No XSS via RelayState.** Rendered through `html/template` with correct contextual escaping.
- **Cookie attributes are correct.** `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`,
  `Path=/`, no `Domain`, opaque 256-bit value from `crypto/rand`. Logout is POST-only, so
  cross-site logout CSRF is blocked.
- **No forwarded-header trust.** All public URLs derive from `BRIDGIT_PUBLIC_URL`; `Host` and
  `X-Forwarded-*` are never consulted.
- **Secrets do not leak.** The client secret is never logged; startup errors name only the
  variable; the token-endpoint error body is discarded in favour of a bare 401.
- **Fail-closed startup.** Invalid URLs, weak or expired keypairs, malformed metadata, and failed
  OIDC discovery all abort before the listener opens. RSA ≥ 2048 is enforced.
- **`govulncheck` is clean** — 0 reachable vulnerabilities.

---

## What to address, in order

**Before any real deployment** — ✅ complete

1. ✅ **BR-01** — bind `state` to the browser with a transaction cookie. Done in
   [#1](https://github.com/sigman78/bridgit/pull/1).
2. ✅ **BR-02** — give `SessionIndex` its own random value. Done in
   [#2](https://github.com/sigman78/bridgit/pull/2), minus the hashed-key residual.

Also done out of order, because it would otherwise be mistaken for a controller-side fault during
interop debugging: ✅ **BR-17** in [#3](https://github.com/sigman78/bridgit/pull/3).

**Before exposing `/saml/sso` beyond a trusted network** — next up

3. ☐ **BR-03** — evict-oldest plus a per-IP cap on the transaction table. BR-01's cookie is now
   in place, so the per-browser cap it enables is available too. Covers BR-09.
4. ☐ **BR-05** — add authentication audit logging. Nothing else on this list is diagnosable
   without it, and none of the fixed findings would have left a trace.
5. ☐ **BR-07** — a headers middleware. Ten lines, covers several findings' worth of hardening.

**Before publishing the project**

6. ☐ **BR-04** — determine whether Omada supplies an encryption certificate; document the answer.
7. ☐ **BR-06** — cap `SessionTTL`, lower the default, or drop bridge sessions entirely.
8. ☐ **BR-08**, **BR-12**, **BR-13**, **BR-14**, **BR-16**, **BR-18** — small, cheap, no design
   decisions required. Good candidates for one batched pull request.

**Needs a decision, not code**

9. ☐ **BR-10** and **BR-11** depend on facts about Omada and Pocket ID that are not in this
   repository: whether Omada keys accounts on `username` or NameID, whether it normalises names,
   how it behaves with multiple group values, and whether Pocket ID lets users self-edit their
   username. Establish these, then encode the answers.

---

## Follow-up

Items created or left behind by the fixes so far, distinct from the original findings.

**Residual from BR-02 — session IDs stored in plaintext.** The recommended hashed-key storage
(`sha256(cookie)` as the map key) was not implemented. Only relevant against an attacker who can
already read process memory, so it is hardening rather than a fix. Fold into whichever PR next
touches `internal/session`.

**BR-16 is adjacent to shipped code.** `PutTransaction` gained a `BindingHash` presence check in
BR-01 but still does not require `Nonce` or `PKCEVerifier`. The guard belongs in the same block;
cheap to finish while the context is fresh.

**Re-import Omada IdP metadata after BR-17 merges.** Endpoint URLs and the signing certificate
are unchanged, so this is safe to do at any time, but it must happen before a controller that
enforces the advertised NameID format will accept a login.

**Re-audit scope after the next batch.** This document reflects commit `f5fdc27`. BR-03, BR-05,
and BR-07 all touch the request path; once they land, the *Verified clean* list — particularly
the open-redirect, header, and logging claims — should be re-checked rather than assumed to
carry forward.

**Publication caution.** This document is a working exploitation guide for findings that are
still open; BR-03 in particular includes the exact request count and rate needed to lock out
logins. The repository is public. Keep this file untracked, or trim the reproduction details,
until BR-03, BR-05, and BR-07 are fixed.

**The project-level risk is still unresolved.** Bridgit implements SP-initiated SAML only, while
TP-Link's documented Omada flow appears to be IdP-initiated. This outranks every remaining
finding: confirm a real controller can complete a login before spending more effort here.

---

## Assessment

The security fundamentals here are better than most hand-rolled identity code. Strict SP
allowlisting, correct PKCE, nonce verification with constant-time comparison, fail-closed
startup, no forwarded-header trust, bounded state with TTLs, and a genuinely careful set of
documented invariants in PLAN.md that the code mostly honours. The two things that most often go
wrong in a SAML IdP — ACS validation and signature algorithm selection — are both correct. Two
independent reviews of different halves of the system converged on the same short list, which is
a good sign about the code's clarity.

The findings clustered in one place: **state that should be bound to a browser was not**
(BR-01), and **state that should stay inside Bridgit leaked outward** (BR-02). Both were small,
local fixes, and both are now closed. Everything remaining is hardening, capacity handling, and
operational visibility — no further finding threatens the integrity of an issued assertion.

The most valuable remaining work is not the highest-severity item but **BR-05**: with no
authentication logging at all, neither of the two High findings would have left any trace had
they been exploited, and none of the open ones would either.

The largest risk to the project does not appear on this list, because it is not a security issue.
Bridgit implements SP-initiated SAML only, while TP-Link's documented Omada flow appears to be
IdP-initiated. **Confirm the bridge can complete a login against a real controller before
investing further effort anywhere on this list.**
