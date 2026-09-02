# Bridgit concrete quickstart

This is the shortest setup path. It assumes:

- Pocket ID: `https://id.home.example`
- Bridgit: `https://bridge.home.example`
- Omada: your existing controller
- authorization group: `omada-admins`
- Windows PowerShell

Replace the two example hostnames with your real DNS names.

## What you are creating

You do **not** create a SAML IdP in Pocket ID.

```text
Pocket ID (OIDC IdP) -> Bridgit (OIDC client)
Bridgit (SAML IdP)   -> Omada   (SAML SP)
```

Bridgit becomes the SAML IdP as soon as it has:

1. its public URL;
2. an RSA signing key and certificate;
3. Omada's SP metadata.

There is no IdP database or separate IdP account to create inside Bridgit.

## Before starting

Keep a local Omada administrator account. Do not disable ordinary Omada login.

Make sure these names resolve from your browser:

```text
id.home.example
bridge.home.example
```

Bridgit also must be able to open `https://id.home.example`. Both sites need browser-trusted HTTPS certificates.

## Step 1: build Bridgit

In `D:\non-esp\bridgit`:

```powershell
go version
go test ./...
go build -o .\bridgit.exe ./cmd/bridgit
```

The required Go version is 1.26.6 or newer. If `go version` reports the currently installed 1.14.6, install a current Go toolchain first.

Expected result: `bridgit.exe` exists in the current directory.

## Step 2: create Bridgit's SAML identity

Generate the persistent signing keypair:

```powershell
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -keyout saml.key -out saml.crt -days 3650 -subj "/CN=bridge.home.example"
```

Generate the file Omada needs to learn about Bridgit:

```powershell
$env:BRIDGIT_PUBLIC_URL = "https://bridge.home.example"
$env:BRIDGIT_SAML_CERT_FILE = ".\saml.crt"
$env:BRIDGIT_SAML_KEY_FILE = ".\saml.key"
cmd /c "bridgit.exe metadata > bridgit-idp-metadata.xml"
```

Expected files:

```text
saml.key                     private; do not share
saml.crt                     public signing certificate
bridgit-idp-metadata.xml     upload this to Omada
```

At this point Bridgit's SAML IdP identity exists. Its ID is:

```text
https://bridge.home.example/saml/metadata
```

## Step 3: tell Omada about Bridgit

In the Omada administrator UI:

1. Enter **Global View**.
2. Open **Settings**.
3. Open **SAML SSO**.
4. Click **Add New SAML Connection**.
5. Set **Identity Provider Name** to `Bridgit`.
6. Choose **Metadata File**.
7. Upload `bridgit-idp-metadata.xml`.
8. Click **Send**, **Apply**, or **Create**, depending on the controller version.
9. Open **Details** for the new connection.
10. Confirm that its IdP/SSO URL is `https://bridge.home.example/saml/sso`.
11. Click the connection's download icon to download Omada's metadata.
12. Rename the downloaded file to `omada-sp-metadata.xml` and place it in `D:\non-esp\bridgit`.

That download is the reverse half of the trust exchange:

```text
bridgit-idp-metadata.xml -> Omada learns which Bridgit key to trust
omada-sp-metadata.xml    -> Bridgit learns which Omada ID and ACS to trust
```

Now create the Omada authorization group:

1. On the **SAML SSO** page, click **Go to SAML User Group**. Older versions may call this **SAML Role**.
2. Click **Add New SAML User Group**.
3. Set **SAML User Group Name** to exactly `omada-admins`.
4. Choose the Omada role and site privileges this group should receive.
5. Save it.

Expected result: Omada trusts Bridgit's certificate and has a role-bearing group named `omada-admins`.

If Omada has no metadata download icon, copy the **Entity ID** and **Sign-On URL** from Details and use the manual SP metadata template in [SETUP.md](SETUP.md#5-configure-omada-as-the-saml-service-provider).

## Step 4: tell Pocket ID about Bridgit

In the Pocket ID administrator UI:

1. Open **User Groups**.
2. Create a group whose name is exactly `omada-admins`.
3. Add your test user to that group.
4. Open **Settings -> OIDC Clients**.
5. Click **Add OIDC Client** or **Create Client**.
6. Set the name to `Bridgit`.
7. Set its callback URL to exactly:

   ```text
   https://bridge.home.example/oidc/callback
   ```

8. Leave **Public Client** disabled.
9. Enable **PKCE** if that switch is present.
10. Leave **Client Launch URL** empty for now.
11. Save the client.
12. In **Allowed User Groups**, select `omada-admins`. A new Pocket ID client with no allowed groups allows nobody.
13. Copy the generated **Client ID** and **Client Secret**.

Expected result: Pocket ID has one confidential OIDC client which may be used by members of `omada-admins`.

## Step 5: create Bridgit's runtime configuration

Create `bridgit.env` in `D:\non-esp\bridgit` with these contents, replacing the two credential placeholders:

```dotenv
BRIDGIT_PUBLIC_URL=https://bridge.home.example
BRIDGIT_LISTEN_ADDR=127.0.0.1:8080
BRIDGIT_OIDC_ISSUER=https://id.home.example
BRIDGIT_OIDC_CLIENT_ID=PASTE_CLIENT_ID_HERE
BRIDGIT_OIDC_CLIENT_SECRET=PASTE_CLIENT_SECRET_HERE
BRIDGIT_SAML_CERT_FILE=./saml.crt
BRIDGIT_SAML_KEY_FILE=./saml.key
BRIDGIT_SAML_SP_METADATA_FILE=./omada-sp-metadata.xml
BRIDGIT_USERNAME_CLAIM=preferred_username
BRIDGIT_GROUPS_CLAIM=groups
BRIDGIT_TRANSACTION_TTL=1m
BRIDGIT_SESSION_TTL=8h
BRIDGIT_LOG_LEVEL=info
```

Do not commit `bridgit.env`; it contains the Pocket ID client secret.

## Step 6: put HTTPS in front of Bridgit

Bridgit listens on `127.0.0.1:8080` using HTTP. Configure your reverse proxy to expose it as `https://bridge.home.example`.

Minimal Caddy configuration:

```caddyfile
bridge.home.example {
    reverse_proxy 127.0.0.1:8080
}
```

Do not use `http://bridge.home.example:8080` in the browser. Bridgit deliberately uses a Secure cookie which works only through HTTPS.

## Step 7: launch Bridgit

Load `bridgit.env` and start the server:

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

Expected log:

```json
{"level":"INFO","msg":"Bridgit listening","address":"127.0.0.1:8080","public_url":"https://bridge.home.example"}
```

If Bridgit exits, read the `startup failed` error. It usually identifies one of:

- Pocket ID cannot be reached or its TLS certificate is not trusted;
- the Pocket ID issuer is wrong;
- `saml.crt` and `saml.key` do not match;
- `omada-sp-metadata.xml` is missing or invalid.

## Step 8: verify the endpoints

Open another PowerShell window:

```powershell
curl.exe -i https://bridge.home.example/healthz
curl.exe -i https://bridge.home.example/readyz
curl.exe -o live-idp-metadata.xml https://bridge.home.example/saml/metadata
```

Expected:

- health and readiness return `HTTP/1.1 200 OK` and `ok`;
- `live-idp-metadata.xml` downloads successfully;
- opening `https://bridge.home.example/` returns 404, which is normal;
- opening `https://bridge.home.example/saml/sso` directly returns 400, which is also normal because it lacks Omada's `SAMLRequest`.

## Step 9: test authentication—and understand the current limit

Look in Omada for a Test SSO or SAML login action. A compatible SP-initiated action sends the browser to a URL shaped like:

```text
https://bridge.home.example/saml/sso?SAMLRequest=...&RelayState=...
```

If that happens, expect:

1. Bridgit redirects to Pocket ID.
2. You authenticate with your Pocket ID passkey.
3. Pocket ID returns to Bridgit.
4. Bridgit posts a signed `SAMLResponse` to Omada.
5. Omada gives the user the permissions configured for `omada-admins`.

However, TP-Link's documented Omada flow normally starts from an application tile at the SAML IdP and uses a special RelayState. Bridgit does not yet provide that launch endpoint. If your Omada version has no SP-initiated Test/Login action, the real browser login cannot be started yet. This is a missing Bridgit feature, not a setup mistake.

You can still prove the complete protocol implementation with the simulated Pocket ID and Omada endpoints:

```powershell
go test -count=1 -v ./internal/server -run "^TestAuthenticatedPrincipalBecomesVerifiableOmadaAssertion$"
```

Expected result: `PASS`. This test starts a fake OIDC provider, creates a real SAML `AuthnRequest`, completes the callback, and cryptographically verifies Bridgit's SAML assertion and Omada attributes.

## What should be automated next

The Bridgit-owned setup should be automated. The proposed commands are:

```text
bridgit bootstrap --public-url https://bridge.home.example --output-dir .\data
bridgit check --env-file .\bridgit.env
```

`bootstrap` should safely create the RSA keypair and `bridgit-idp-metadata.xml`, refusing to overwrite existing keys. `check` should load the complete configuration, perform Pocket ID discovery, validate Omada metadata, and print the trusted Entity ID and ACS without showing secrets.

The Omada metadata upload/download and Pocket ID group/client creation should remain manual initially. Those operations modify external authorization systems, vary by installed version, and are performed only once. Automating them through undocumented browser/UI calls would be fragile and could create lockout risk. If either product exposes a stable supported administration API, optional automation can be added later with explicit credentials and a dry-run mode.
