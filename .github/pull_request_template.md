# Summary

<!-- What this change does, in one or two sentences. -->

## Motivation

<!-- Why this change is needed. Link the audit finding (e.g. BR-01), issue, or
     the behaviour that prompted it. If it fixes a security finding, say so and
     name the finding. -->

## Changes

<!-- Bullet list of what actually changed, by package. -->

-

## Security review

Bridgit mints credentials for a service provider, so every change is treated as
security-relevant. Check what applies and delete the rest.

- [ ] Does not weaken SP entity-ID or ACS allowlisting.
- [ ] Does not weaken ID-token verification (signature, issuer, audience, expiry, nonce).
- [ ] OAuth `state`, PKCE verifier, and nonce remain random, short-lived, server-side,
      single-use, and bound to the browser that started the transaction.
- [ ] No secret, authorization code, token, session identifier, cookie value, SAML
      payload, or full claim set is logged or sent to a service provider.
- [ ] Session and transaction state stays bounded, with a TTL, and fails closed.
- [ ] Public URLs still derive only from `BRIDGIT_PUBLIC_URL`; no `Host` or
      `X-Forwarded-*` trust is introduced.
- [ ] Startup still fails closed on invalid configuration, keys, or metadata.
- [ ] N/A — no security-relevant surface touched.

## Protocol compatibility

- [ ] IdP metadata still matches what assertions actually contain (bindings, NameID
      format, signing certificate).
- [ ] Change is compatible with the configured service provider, or the incompatibility
      is documented below.
- [ ] N/A — no protocol surface touched.

<!-- If IdP metadata changed, note whether the service provider must re-import it. -->

## Testing

<!-- What you ran, and what new coverage this adds. Negative-path and replay tests
     matter more than happy-path ones here. -->

- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] `govulncheck ./...` reports no reachable vulnerabilities.
- [ ] New or updated tests cover the change, including its failure paths.
- [ ] `go test -race ./...` passes, or is deferred to CI (no local cgo toolchain).

## Operational impact

- [ ] No configuration change required.
- [ ] New or changed environment variable — documented in `README.md` and `.env.example`.
- [ ] Requires re-importing IdP metadata into the service provider.
- [ ] Invalidates existing browser sessions on deploy.

## Notes for the reviewer

<!-- Anything you want looked at closely, or a decision you are unsure about. -->
