package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/sigman78/bridgit/internal/oidcclient"
	"golang.org/x/oauth2"
)

func TestRegisteredServiceProviderStartsProtectedOIDCLogin(t *testing.T) {
	key, certificate := testKeyPair(t, "bridge.example.test")
	serviceProvider := testServiceProvider(t)
	serviceProviderMetadata, err := xml.Marshal(serviceProvider.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	issuer := discoveryServer(t)
	oidc, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       issuer.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	publicURL := mustURL(t, "https://bridge.example.test")
	bridge, err := New(Config{
		PublicURL:               *publicURL,
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: serviceProviderMetadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
	}, oidc)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	metadataRequest := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/saml/metadata", nil)
	metadataResponse := httptest.NewRecorder()
	bridge.ServeHTTP(metadataResponse, metadataRequest)
	var idpMetadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataResponse.Body.Bytes(), &idpMetadata); err != nil {
		t.Fatalf("parse IdP metadata: %v", err)
	}
	serviceProvider.IDPMetadata = &idpMetadata

	authenticationURL, err := serviceProvider.MakeRedirectAuthenticationRequest("omada-relay-state")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("SSO status = %d, want %d; body=%s", response.Code, http.StatusFound, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(name) == "" {
			t.Errorf("OIDC redirect is missing %s", name)
		}
	}
	if got, want := query.Get("code_challenge_method"), "S256"; got != want {
		t.Errorf("code_challenge_method = %q, want %q", got, want)
	}
}

func TestUnknownServiceProviderAndUnregisteredACSFailBeforeOIDC(t *testing.T) {
	key, certificate := testKeyPair(t, "bridge.example.test")
	registered := testServiceProvider(t)
	metadata, err := xml.Marshal(registered.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	issuer := discoveryServer(t)
	oidc, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       issuer.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		PublicURL:               *mustURL(t, "https://bridge.example.test"),
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: metadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
	}, oidc)
	if err != nil {
		t.Fatal(err)
	}
	idpMetadata := fetchIDPMetadata(t, bridge)

	tests := []struct {
		name string
		sp   *saml.ServiceProvider
	}{
		{
			name: "unknown entity",
			sp: &saml.ServiceProvider{
				EntityID:    "https://unknown.example.test/saml/entity",
				MetadataURL: *mustURL(t, "https://unknown.example.test/saml/metadata"),
				AcsURL:      registered.AcsURL,
			},
		},
		{
			name: "unregistered ACS",
			sp: &saml.ServiceProvider{
				EntityID:    registered.EntityID,
				MetadataURL: registered.MetadataURL,
				AcsURL:      *mustURL(t, "https://attacker.example.test/acs"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.sp.IDPMetadata = idpMetadata
			authenticationURL, err := test.sp.MakeRedirectAuthenticationRequest("")
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
			response := httptest.NewRecorder()
			bridge.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestAuthenticatedPrincipalBecomesVerifiableOmadaAssertion(t *testing.T) {
	key, certificate := testKeyPair(t, "bridge.example.test")
	serviceProvider := testServiceProvider(t)
	serviceProviderMetadata, err := xml.Marshal(serviceProvider.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	upstream := fullOIDCServer(t)
	oidc, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       upstream.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		PublicURL:               *mustURL(t, "https://bridge.example.test"),
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: serviceProviderMetadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
	}, oidc)
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider.IDPMetadata = fetchIDPMetadata(t, bridge)
	authenticationURL, err := serviceProvider.MakeRedirectAuthenticationRequest("omada-relay-state")
	if err != nil {
		t.Fatal(err)
	}
	authnRequestID := redirectAuthnRequestID(t, authenticationURL)

	startRequest := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
	startResponse := httptest.NewRecorder()
	bridge.ServeHTTP(startResponse, startRequest)
	authorizationURL := mustURL(t, startResponse.Header().Get("Location"))
	upstream.Nonce = authorizationURL.Query().Get("nonce")
	upstream.PKCEChallenge = authorizationURL.Query().Get("code_challenge")

	callbackRequest := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/oidc/callback?state="+url.QueryEscape(authorizationURL.Query().Get("state"))+"&code=authorization-code", nil)
	callbackRequest.AddCookie(namedCookie(t, startResponse.Result().Cookies(), transactionCookieName))
	callbackResponse := httptest.NewRecorder()
	bridge.ServeHTTP(callbackResponse, callbackRequest)
	cookie := namedCookie(t, callbackResponse.Result().Cookies(), sessionCookieName)

	resumeRequest := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
	resumeRequest.AddCookie(cookie)
	resumeResponse := httptest.NewRecorder()
	bridge.ServeHTTP(resumeResponse, resumeRequest)
	if resumeResponse.Code != http.StatusOK {
		t.Fatalf("resumed SAML status = %d, want %d; body=%s", resumeResponse.Code, http.StatusOK, resumeResponse.Body.String())
	}
	samlResponse := hiddenFormValue(t, resumeResponse.Body.String(), "SAMLResponse")
	if got, want := hiddenFormValue(t, resumeResponse.Body.String(), "RelayState"), "omada-relay-state"; got != want {
		t.Errorf("RelayState = %q, want %q", got, want)
	}

	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {"omada-relay-state"}}
	acsRequest := httptest.NewRequest(http.MethodPost, serviceProvider.AcsURL.String(), strings.NewReader(form.Encode()))
	acsRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := acsRequest.ParseForm(); err != nil {
		t.Fatal(err)
	}
	assertion, err := serviceProvider.ParseResponse(acsRequest, []string{authnRequestID})
	if err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) {
			t.Fatalf("service provider rejected SAML response: %v", invalid.PrivateErr)
		}
		t.Fatalf("service provider rejected SAML response: %v", err)
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		t.Fatal("assertion has no NameID")
	}
	if got, want := assertion.Subject.NameID.Value, "pocket-id-subject"; got != want {
		t.Errorf("NameID = %q, want %q", got, want)
	}
	if got, want := assertion.Subject.NameID.Format, string(saml.PersistentNameIDFormat); got != want {
		t.Errorf("NameID format = %q, want %q", got, want)
	}
	if got, want := strings.Join(attributeValues(assertion, "username"), ","), "alice"; got != want {
		t.Errorf("username attribute = %q, want %q", got, want)
	}
	if got, want := strings.Join(attributeValues(assertion, "usergroup_name"), ","), "omada-admins"; got != want {
		t.Errorf("usergroup_name attribute = %q, want %q", got, want)
	}
}

func TestAuthenticatedSAMLRequestCannotIssueASecondAssertion(t *testing.T) {
	harness := authenticatedBridge(t)

	firstRequest := httptest.NewRequest(http.MethodGet, harness.authenticationURL.String(), nil)
	firstRequest.AddCookie(harness.cookie)
	firstResponse := httptest.NewRecorder()
	harness.bridge.ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first assertion status = %d, want %d", firstResponse.Code, http.StatusOK)
	}

	secondRequest := httptest.NewRequest(http.MethodGet, harness.authenticationURL.String(), nil)
	secondRequest.AddCookie(harness.cookie)
	secondResponse := httptest.NewRecorder()
	harness.bridge.ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusBadRequest {
		t.Fatalf("replayed request status = %d, want %d", secondResponse.Code, http.StatusBadRequest)
	}
}

func TestOIDCStateCannotBeReused(t *testing.T) {
	harness := authenticatedBridge(t)
	request := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
	request.AddCookie(harness.transactionCookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestOIDCCallbackRequiresTheBrowserThatStartedTheTransaction(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		cookie *http.Cookie
	}{
		{name: "no transaction cookie"},
		{name: "transaction cookie from another browser", cookie: &http.Cookie{Name: transactionCookieName, Value: "kAcSaEBOs2y2gVv6xhHRjKGMEGmZ4d2sVEBhIkNRkkY"}},
		{name: "empty transaction cookie", cookie: &http.Cookie{Name: transactionCookieName, Value: ""}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := unauthenticatedBridge(t)
			request := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
			if testCase.cookie != nil {
				request.AddCookie(testCase.cookie)
			}
			response := httptest.NewRecorder()
			harness.bridge.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("callback status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == sessionCookieName && cookie.Value != "" {
					t.Fatalf("callback established a session for a browser that did not start the login: %#v", cookie)
				}
			}
		})
	}
}

// A callback that is rejected for want of the binding cookie must not consume
// the transaction, or an attacker could cancel somebody else's login.
func TestRejectedCallbackLeavesTheTransactionUsable(t *testing.T) {
	harness := unauthenticatedBridge(t)

	unboundRequest := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
	unboundResponse := httptest.NewRecorder()
	harness.bridge.ServeHTTP(unboundResponse, unboundRequest)
	if unboundResponse.Code != http.StatusBadRequest {
		t.Fatalf("unbound callback status = %d, want %d", unboundResponse.Code, http.StatusBadRequest)
	}

	boundRequest := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
	boundRequest.AddCookie(harness.transactionCookie)
	boundResponse := httptest.NewRecorder()
	harness.bridge.ServeHTTP(boundResponse, boundRequest)
	if boundResponse.Code != http.StatusSeeOther {
		t.Fatalf("bound callback status = %d, want %d; body=%s", boundResponse.Code, http.StatusSeeOther, boundResponse.Body.String())
	}
}

func TestTransactionCookieIsScopedAndClearedOnCompletion(t *testing.T) {
	harness := authenticatedBridge(t)
	issued := harness.transactionCookie
	if issued.Value == "" || !issued.HttpOnly || !issued.Secure || issued.Path != "/" || issued.SameSite != http.SameSiteLaxMode || issued.MaxAge < 1 {
		t.Errorf("transaction cookie lacks the required __Host security properties: %#v", issued)
	}

	request := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
	request.AddCookie(issued)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	cleared := namedCookie(t, response.Result().Cookies(), transactionCookieName)
	if cleared.Value != "" || cleared.MaxAge != -1 {
		t.Errorf("completed callback did not clear the transaction cookie: %#v", cleared)
	}
}

// The SessionIndex reaches the service provider inside the signed assertion and
// is normally retained there, so it must never carry the browser's session
// cookie, which would let anyone reading Omada's storage impersonate the user.
func TestAssertionDoesNotDiscloseTheBrowserSessionCookie(t *testing.T) {
	harness := authenticatedBridge(t)
	request := httptest.NewRequest(http.MethodGet, harness.authenticationURL.String(), nil)
	request.AddCookie(harness.cookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("assertion status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}

	encoded := hiddenFormValue(t, response.Body.String(), "SAMLResponse")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	assertion := string(decoded)
	if strings.Contains(assertion, harness.cookie.Value) {
		t.Error("assertion contains the browser session cookie value")
	}
	if strings.Contains(assertion, harness.transactionCookie.Value) {
		t.Error("assertion contains the transaction binding secret")
	}

	sessionIndex := attributeValue(t, assertion, "SessionIndex")
	if sessionIndex == "" {
		t.Fatal("assertion has no SessionIndex")
	}
	if sessionIndex == harness.cookie.Value {
		t.Error("SessionIndex is the browser session cookie value")
	}
}

func nameIDFormat(t *testing.T, document string) string {
	t.Helper()
	match := regexp.MustCompile(`<saml:NameID[^>]*\sFormat="([^"]*)"`).FindStringSubmatch(document)
	if match == nil {
		return ""
	}
	return match[1]
}

func attributeValue(t *testing.T, document, name string) string {
	t.Helper()
	match := regexp.MustCompile(name + `="([^"]*)"`).FindStringSubmatch(document)
	if match == nil {
		return ""
	}
	return match[1]
}

// A service provider validates assertions against the metadata it imported, so
// the advertised name-identifier format and the emitted one must not drift.
func TestMetadataNameIDFormatMatchesTheIssuedAssertion(t *testing.T) {
	harness := authenticatedBridge(t)

	metadata := fetchIDPMetadata(t, harness.bridge)
	if len(metadata.IDPSSODescriptors) != 1 {
		t.Fatalf("IdP descriptors = %d, want 1", len(metadata.IDPSSODescriptors))
	}
	advertised := metadata.IDPSSODescriptors[0].NameIDFormats
	if len(advertised) != 1 {
		t.Fatalf("advertised NameIDFormats = %v, want exactly one", advertised)
	}

	request := httptest.NewRequest(http.MethodGet, harness.authenticationURL.String(), nil)
	request.AddCookie(harness.cookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("assertion status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(hiddenFormValue(t, response.Body.String(), "SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}

	emitted := nameIDFormat(t, string(decoded))
	if emitted == "" {
		t.Fatal("assertion NameID has no Format attribute")
	}
	if emitted != string(advertised[0]) {
		t.Errorf("assertion NameID Format = %q, but metadata advertises %q", emitted, advertised[0])
	}
}

func TestOperationalEndpointsAndLocalLogout(t *testing.T) {
	harness := authenticatedBridge(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		request := httptest.NewRequest(http.MethodGet, "https://bridge.example.test"+path, nil)
		response := httptest.NewRecorder()
		harness.bridge.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, response.Code, http.StatusOK)
		}
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "https://bridge.example.test/logout", nil)
	logoutRequest.AddCookie(harness.cookie)
	logoutResponse := httptest.NewRecorder()
	harness.bridge.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", logoutResponse.Code, http.StatusNoContent)
	}
	cleared := logoutResponse.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != "__Host-bridgit_session" || cleared[0].MaxAge >= 0 {
		t.Fatalf("logout did not expire the session cookie: %#v", cleared)
	}

	request := httptest.NewRequest(http.MethodGet, harness.authenticationURL.String(), nil)
	request.AddCookie(harness.cookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("logged-out SAML request status = %d, want fresh OIDC redirect %d", response.Code, http.StatusFound)
	}
}

type authenticatedTestBridge struct {
	bridge            http.Handler
	authenticationURL *url.URL
	cookie            *http.Cookie
	callbackURL       string
	transactionCookie *http.Cookie
}

// unauthenticatedBridge starts one login and stops at the OIDC redirect, so a
// test can drive the callback itself.
func unauthenticatedBridge(t *testing.T) authenticatedTestBridge {
	t.Helper()
	key, certificate := testKeyPair(t, "bridge.example.test")
	serviceProvider := testServiceProvider(t)
	serviceProviderMetadata, err := xml.Marshal(serviceProvider.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	upstream := fullOIDCServer(t)
	oidc, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       upstream.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		PublicURL:               *mustURL(t, "https://bridge.example.test"),
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: serviceProviderMetadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
	}, oidc)
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider.IDPMetadata = fetchIDPMetadata(t, bridge)
	authenticationURL, err := serviceProvider.MakeRedirectAuthenticationRequest("omada-relay-state")
	if err != nil {
		t.Fatal(err)
	}
	startRequest := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
	startResponse := httptest.NewRecorder()
	bridge.ServeHTTP(startResponse, startRequest)
	authorizationURL := mustURL(t, startResponse.Header().Get("Location"))
	upstream.Nonce = authorizationURL.Query().Get("nonce")
	upstream.PKCEChallenge = authorizationURL.Query().Get("code_challenge")
	return authenticatedTestBridge{
		bridge:            bridge,
		authenticationURL: authenticationURL,
		callbackURL:       "https://bridge.example.test/oidc/callback?state=" + url.QueryEscape(authorizationURL.Query().Get("state")) + "&code=authorization-code",
		transactionCookie: namedCookie(t, startResponse.Result().Cookies(), transactionCookieName),
	}
}

// authenticatedBridge additionally completes the callback, yielding a browser
// that holds an established bridge session.
func authenticatedBridge(t *testing.T) authenticatedTestBridge {
	t.Helper()
	harness := unauthenticatedBridge(t)
	request := httptest.NewRequest(http.MethodGet, harness.callbackURL, nil)
	request.AddCookie(harness.transactionCookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want %d; body=%s", response.Code, http.StatusSeeOther, response.Body.String())
	}
	harness.cookie = namedCookie(t, response.Result().Cookies(), sessionCookieName)
	return harness
}

func namedCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q", name)
	return nil
}

func TestOIDCCallbackEstablishesSessionAndResumesSAMLRequest(t *testing.T) {
	key, certificate := testKeyPair(t, "bridge.example.test")
	serviceProvider := testServiceProvider(t)
	serviceProviderMetadata, err := xml.Marshal(serviceProvider.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	upstream := fullOIDCServer(t)
	oidc, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer:       upstream.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		PublicURL:               *mustURL(t, "https://bridge.example.test"),
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: serviceProviderMetadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
	}, oidc)
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider.IDPMetadata = fetchIDPMetadata(t, bridge)
	authenticationURL, err := serviceProvider.MakeRedirectAuthenticationRequest("omada-relay-state")
	if err != nil {
		t.Fatal(err)
	}

	startRequest := httptest.NewRequest(http.MethodGet, authenticationURL.String(), nil)
	startResponse := httptest.NewRecorder()
	bridge.ServeHTTP(startResponse, startRequest)
	authorizationURL := mustURL(t, startResponse.Header().Get("Location"))
	upstream.Nonce = authorizationURL.Query().Get("nonce")
	upstream.PKCEChallenge = authorizationURL.Query().Get("code_challenge")

	callbackURL := "https://bridge.example.test/oidc/callback?state=" + url.QueryEscape(authorizationURL.Query().Get("state")) + "&code=authorization-code"
	callbackRequest := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackRequest.AddCookie(namedCookie(t, startResponse.Result().Cookies(), transactionCookieName))
	callbackResponse := httptest.NewRecorder()
	bridge.ServeHTTP(callbackResponse, callbackRequest)

	if callbackResponse.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want %d; body=%s", callbackResponse.Code, http.StatusSeeOther, callbackResponse.Body.String())
	}
	if got, want := callbackResponse.Header().Get("Location"), authenticationURL.RequestURI(); got != want {
		t.Errorf("callback location = %q, want original SAML request %q", got, want)
	}
	cookie := namedCookie(t, callbackResponse.Result().Cookies(), sessionCookieName)
	if cookie.Value == "" || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie does not have the required opaque __Host security properties: %#v", cookie)
	}
}

func testServiceProvider(t *testing.T) *saml.ServiceProvider {
	t.Helper()
	return &saml.ServiceProvider{
		EntityID:    "https://omada.example.test/saml/entity",
		MetadataURL: *mustURL(t, "https://omada.example.test/saml/metadata"),
		AcsURL:      *mustURL(t, "https://omada.example.test/api/v2/saml/acs"),
	}
}

func fetchIDPMetadata(t *testing.T, bridge http.Handler) *saml.EntityDescriptor {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/saml/metadata", nil)
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, request)
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	return &metadata
}

func redirectAuthnRequestID(t *testing.T, authenticationURL *url.URL) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(authenticationURL.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(bytes.NewReader(compressed))
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var request saml.AuthnRequest
	if err := xml.Unmarshal(decompressed, &request); err != nil {
		t.Fatal(err)
	}
	return request.ID
}

func hiddenFormValue(t *testing.T, body, name string) string {
	t.Helper()
	expression := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	match := expression.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("response form has no %s field", name)
	}
	return html.UnescapeString(match[1])
}

func attributeValues(assertion *saml.Assertion, name string) []string {
	var values []string
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if attribute.Name != name {
				continue
			}
			for _, value := range attribute.Values {
				values = append(values, value.Value)
			}
		}
	}
	return values
}

func discoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                upstream.URL,
			"authorization_endpoint":                upstream.URL + "/authorize",
			"token_endpoint":                        upstream.URL + "/token",
			"jwks_uri":                              upstream.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

type testOIDCProvider struct {
	*httptest.Server
	Key           *rsa.PrivateKey
	Nonce         string
	PKCEChallenge string
}

func fullOIDCServer(t *testing.T) *testOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testOIDCProvider{Key: key}
	provider.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]any{
				"issuer":                                provider.URL,
				"authorization_endpoint":                provider.URL + "/authorize",
				"token_endpoint":                        provider.URL + "/token",
				"jwks_uri":                              provider.URL + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeTestJSON(t, w, map[string]any{"keys": []any{map[string]any{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if got := oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")); got != provider.PKCEChallenge {
				t.Errorf("PKCE challenge = %q, want %q", got, provider.PKCEChallenge)
			}
			now := time.Now()
			idToken := signTestJWT(t, key, map[string]any{
				"iss":                provider.URL,
				"sub":                "pocket-id-subject",
				"aud":                "pocket-id-client",
				"exp":                now.Add(time.Hour).Unix(),
				"iat":                now.Unix(),
				"nonce":              provider.Nonce,
				"preferred_username": "alice",
				"email":              "alice@example.test",
				"name":               "Alice Example",
				"given_name":         "Alice",
				"family_name":        "Example",
				"groups":             []string{"omada-admins"},
			})
			writeTestJSON(t, w, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	return provider
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode JSON response: %v", err)
	}
}

func testKeyPair(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
