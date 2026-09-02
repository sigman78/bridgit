package server

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/sigman78/bridgit/internal/oidcclient"
)

// TestIdentityProviderInitiatedLoginIssuesUnsolicitedAssertion covers the whole
// entry point for a service provider that cannot start SAML itself: a bare GET
// establishes the session through the upstream, then delivers an assertion that
// answers no request.
func TestIdentityProviderInitiatedLoginIssuesUnsolicitedAssertion(t *testing.T) {
	harness := idpInitiatedBridge(t, nil)

	response := harness.start(t)
	if response.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, harness.serviceProvider.AcsURL.String()) {
		t.Errorf("auto-submitted form does not post to the service provider ACS; body=%s", body)
	}
	if got, want := hiddenFormValue(t, body, "RelayState"), "cmVzb3VyY2UxX29tYWRhMQ=="; got != want {
		t.Errorf("RelayState = %q, want %q", got, want)
	}

	assertion := harness.parseAssertion(t, body)
	for _, confirmation := range assertion.Subject.SubjectConfirmations {
		if confirmation.SubjectConfirmationData == nil {
			continue
		}
		if got := confirmation.SubjectConfirmationData.InResponseTo; got != "" {
			t.Errorf("unsolicited assertion carries InResponseTo %q, want none", got)
		}
	}
	if got, want := strings.Join(attributeValues(assertion, "username"), ","), "alice"; got != want {
		t.Errorf("username attribute = %q, want %q", got, want)
	}
	if got, want := strings.Join(attributeValues(assertion, "usergroup_name"), ","), "omada-admins"; got != want {
		t.Errorf("usergroup_name attribute = %q, want %q", got, want)
	}
	if got, want := strings.Join(attributeValues(assertion, "resource_attribute"), ","), "resource1"; got != want {
		t.Errorf("resource_attribute = %q, want %q", got, want)
	}
	if got, want := strings.Join(attributeValues(assertion, "omada_attribute"), ","), "omada1"; got != want {
		t.Errorf("omada_attribute = %q, want %q", got, want)
	}
}

// TestIdentityProviderInitiatedLoginCanBeRepeated guards the replay window.
// There is no AuthnRequest to spend here, so the single-use request guard must
// not fire; otherwise every login after the first one fails.
func TestIdentityProviderInitiatedLoginCanBeRepeated(t *testing.T) {
	harness := idpInitiatedBridge(t, nil)

	for attempt := 1; attempt <= 2; attempt++ {
		response := harness.start(t)
		if response.Code != http.StatusOK {
			t.Fatalf("start attempt %d status = %d, want %d; body=%s",
				attempt, response.Code, http.StatusOK, response.Body.String())
		}
		if hiddenFormValue(t, response.Body.String(), "SAMLResponse") == "" {
			t.Fatalf("start attempt %d produced no SAMLResponse", attempt)
		}
	}
}

// TestGroupAllowlistNarrowsTheAssertionToOneGroup documents why the allowlist
// exists: a service provider that resolves exactly one group per assertion
// cannot be handed several.
func TestGroupAllowlistNarrowsTheAssertionToOneGroup(t *testing.T) {
	harness := idpInitiatedBridge(t, func(config *Config) {
		config.GroupAllowlist = []string{"omada-viewers", "omada-admins"}
	})

	response := harness.start(t)
	if response.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	assertion := harness.parseAssertion(t, response.Body.String())
	groups := attributeValues(assertion, "usergroup_name")
	if len(groups) != 1 || groups[0] != "omada-admins" {
		t.Errorf("usergroup_name = %v, want exactly [omada-admins]", groups)
	}
}

// TestGroupAllowlistRefusesAnUnlistedUser keeps authorization at the bridge:
// a user holding no accepted group never receives an assertion at all.
func TestGroupAllowlistRefusesAnUnlistedUser(t *testing.T) {
	harness := idpInitiatedBridge(t, func(config *Config) {
		config.GroupAllowlist = []string{"omada-operators"}
	})

	response := harness.start(t)
	if response.Code != http.StatusForbidden {
		t.Fatalf("start status = %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "SAMLResponse") {
		t.Error("refused login still emitted a SAML response")
	}
}

func TestIdentityProviderInitiatedEndpointRejectsNonGET(t *testing.T) {
	harness := idpInitiatedBridge(t, nil)
	request := httptest.NewRequest(http.MethodPost, "https://bridge.example.test/saml/start", nil)
	request.AddCookie(harness.sessionCookie)
	response := httptest.NewRecorder()
	harness.bridge.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

type idpInitiatedTestBridge struct {
	bridge          http.Handler
	serviceProvider *saml.ServiceProvider
	sessionCookie   *http.Cookie
}

// start replays the entry point with an established session, which is the state
// a browser is in once it returns from the upstream.
func (h idpInitiatedTestBridge) start(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/saml/start", nil)
	request.AddCookie(h.sessionCookie)
	response := httptest.NewRecorder()
	h.bridge.ServeHTTP(response, request)
	return response
}

func (h idpInitiatedTestBridge) parseAssertion(t *testing.T, body string) *saml.Assertion {
	t.Helper()
	form := url.Values{
		"SAMLResponse": {hiddenFormValue(t, body, "SAMLResponse")},
		"RelayState":   {hiddenFormValue(t, body, "RelayState")},
	}
	request := httptest.NewRequest(http.MethodPost, h.serviceProvider.AcsURL.String(), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	// No request IDs exist for an unsolicited assertion.
	assertion, err := h.serviceProvider.ParseResponse(request, nil)
	if err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) {
			t.Fatalf("service provider rejected SAML response: %v", invalid.PrivateErr)
		}
		t.Fatalf("service provider rejected SAML response: %v", err)
	}
	return assertion
}

// idpInitiatedBridge builds a bridge and drives one browser through the
// upstream, stopping with an established session and nothing spent.
func idpInitiatedBridge(t *testing.T, configure func(*Config)) idpInitiatedTestBridge {
	t.Helper()
	key, certificate := testKeyPair(t, "bridge.example.test")
	serviceProvider := testServiceProvider(t)
	// The real service provider does not correlate a request it never made;
	// the library's own parser needs to be told that explicitly.
	serviceProvider.AllowIDPInitiated = true
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
	config := Config{
		PublicURL:               *mustURL(t, "https://bridge.example.test"),
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: serviceProviderMetadata,
		TransactionTTL:          5 * time.Minute,
		SessionTTL:              8 * time.Hour,
		RelayState:              "cmVzb3VyY2UxX29tYWRhMQ==",
		ExtraAttributes: map[string]string{
			"resource_attribute": "resource1",
			"omada_attribute":    "omada1",
		},
	}
	if configure != nil {
		configure(&config)
	}
	bridge, err := New(config, oidc)
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider.IDPMetadata = fetchIDPMetadata(t, bridge)

	// A first visit has no session, so it must hand the browser to the upstream.
	startRequest := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/saml/start", nil)
	startResponse := httptest.NewRecorder()
	bridge.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusFound {
		t.Fatalf("unauthenticated start status = %d, want %d", startResponse.Code, http.StatusFound)
	}
	authorizationURL := mustURL(t, startResponse.Header().Get("Location"))
	upstream.Nonce = authorizationURL.Query().Get("nonce")
	upstream.PKCEChallenge = authorizationURL.Query().Get("code_challenge")

	callbackRequest := httptest.NewRequest(http.MethodGet,
		"https://bridge.example.test/oidc/callback?state="+
			url.QueryEscape(authorizationURL.Query().Get("state"))+"&code=authorization-code", nil)
	callbackRequest.AddCookie(namedCookie(t, startResponse.Result().Cookies(), transactionCookieName))
	callbackResponse := httptest.NewRecorder()
	bridge.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want %d; body=%s",
			callbackResponse.Code, http.StatusSeeOther, callbackResponse.Body.String())
	}
	// The entry point is also the return address, so the browser resumes there.
	if got, want := callbackResponse.Header().Get("Location"), "/saml/start"; got != want {
		t.Fatalf("callback returned to %q, want %q", got, want)
	}
	return idpInitiatedTestBridge{
		bridge:          bridge,
		serviceProvider: serviceProvider,
		sessionCookie:   namedCookie(t, callbackResponse.Result().Cookies(), sessionCookieName),
	}
}
