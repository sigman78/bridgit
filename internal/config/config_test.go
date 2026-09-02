package config

import (
	"testing"
	"time"
)

func TestLoadAcceptsCompleteProductionEnvironmentAndAppliesDefaults(t *testing.T) {
	environment := map[string]string{
		"BRIDGIT_PUBLIC_URL":            "https://bridge.example.test",
		"BRIDGIT_OIDC_ISSUER":           "https://id.example.test",
		"BRIDGIT_OIDC_CLIENT_ID":        "client-id",
		"BRIDGIT_OIDC_CLIENT_SECRET":    "client-secret",
		"BRIDGIT_SAML_CERT_FILE":        "./secrets/saml.crt",
		"BRIDGIT_SAML_KEY_FILE":         "./secrets/saml.key",
		"BRIDGIT_SAML_SP_METADATA_FILE": "./config/omada.xml",
	}

	settings, err := Load(func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := settings.ListenAddr, ":8080"; got != want {
		t.Errorf("listen address = %q, want %q", got, want)
	}
	if got, want := settings.OIDCRedirectURL, "https://bridge.example.test/oidc/callback"; got != want {
		t.Errorf("OIDC redirect URL = %q, want %q", got, want)
	}
	if got, want := settings.UsernameClaim, "preferred_username"; got != want {
		t.Errorf("username claim = %q, want %q", got, want)
	}
	if got, want := settings.GroupsClaim, "groups"; got != want {
		t.Errorf("groups claim = %q, want %q", got, want)
	}
	if got, want := settings.TransactionTTL, time.Minute; got != want {
		t.Errorf("transaction TTL = %s, want %s", got, want)
	}
	if got, want := settings.SessionTTL, 8*time.Hour; got != want {
		t.Errorf("session TTL = %s, want %s", got, want)
	}
}

func TestLoadRejectsTransactionLongerThanSAMLRequestValidity(t *testing.T) {
	environment := map[string]string{
		"BRIDGIT_PUBLIC_URL":            "https://bridge.example.test",
		"BRIDGIT_OIDC_ISSUER":           "https://id.example.test",
		"BRIDGIT_OIDC_CLIENT_ID":        "client-id",
		"BRIDGIT_OIDC_CLIENT_SECRET":    "client-secret",
		"BRIDGIT_SAML_CERT_FILE":        "saml.crt",
		"BRIDGIT_SAML_KEY_FILE":         "saml.key",
		"BRIDGIT_SAML_SP_METADATA_FILE": "omada.xml",
		"BRIDGIT_TRANSACTION_TTL":       "2m",
	}
	_, err := Load(func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	})
	if err == nil {
		t.Fatal("Load() accepted a transaction that outlives Crewjam's SAML request validity")
	}
}

func TestLoadRejectsInsecurePublicURL(t *testing.T) {
	environment := map[string]string{
		"BRIDGIT_PUBLIC_URL":            "http://bridge.example.test",
		"BRIDGIT_OIDC_ISSUER":           "https://id.example.test",
		"BRIDGIT_OIDC_CLIENT_ID":        "client-id",
		"BRIDGIT_OIDC_CLIENT_SECRET":    "client-secret",
		"BRIDGIT_SAML_CERT_FILE":        "saml.crt",
		"BRIDGIT_SAML_KEY_FILE":         "saml.key",
		"BRIDGIT_SAML_SP_METADATA_FILE": "omada.xml",
	}

	_, err := Load(func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	})
	if err == nil {
		t.Fatal("Load() succeeded with an insecure public URL")
	}
}
