package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestMetadataPublishesConfiguredIdentityProvider(t *testing.T) {
	key, certificate := newTestKeyPair(t)
	publicURL, err := url.Parse("https://bridge.example.test")
	if err != nil {
		t.Fatal(err)
	}

	provider, err := New(Config{
		PublicURL:   *publicURL,
		Key:         key,
		Certificate: certificate,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://bridge.example.test/saml/metadata", nil)
	response := httptest.NewRecorder()
	provider.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q, want application/samlmetadata+xml", got)
	}

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("metadata is not valid XML: %v", err)
	}
	if got, want := metadata.EntityID, "https://bridge.example.test/saml/metadata"; got != want {
		t.Errorf("entity ID = %q, want %q", got, want)
	}
	if len(metadata.IDPSSODescriptors) != 1 {
		t.Fatalf("IdP descriptors = %d, want 1", len(metadata.IDPSSODescriptors))
	}

	descriptor := metadata.IDPSSODescriptors[0]
	if !hasEndpoint(descriptor.SingleSignOnServices, saml.HTTPRedirectBinding, "https://bridge.example.test/saml/sso") {
		t.Error("metadata does not publish the HTTP-Redirect SSO endpoint")
	}
	for _, endpoint := range descriptor.SingleSignOnServices {
		if endpoint.Binding == saml.HTTPPostBinding {
			t.Error("metadata advertises unsupported incoming HTTP-POST SSO")
		}
	}
	if len(descriptor.KeyDescriptors) == 0 || len(descriptor.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates) == 0 {
		t.Fatal("metadata does not publish a signing certificate")
	}
	if got, want := descriptor.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data, base64.StdEncoding.EncodeToString(certificate.Raw); got != want {
		t.Error("metadata signing certificate does not match configured certificate")
	}
}

func hasEndpoint(endpoints []saml.Endpoint, binding, location string) bool {
	for _, endpoint := range endpoints {
		if endpoint.Binding == binding && endpoint.Location == location {
			return true
		}
	}
	return false
}

func newTestKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bridge.example.test"},
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
