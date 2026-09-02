package config

import (
	"testing"
	"time"

	"github.com/sigman78/bridgit/internal/identity"
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

func TestLoadParsesIdentityProviderInitiatedSettings(t *testing.T) {
	environment := baseEnvironment()
	environment["BRIDGIT_SAML_RELAY_STATE"] = "cmVzb3VyY2UxX29tYWRhMQ=="
	environment["BRIDGIT_SAML_EXTRA_ATTRIBUTES"] = "resource_attribute=resource1, omada_attribute=omada1"
	environment["BRIDGIT_SAML_GROUPS"] = "omada_admins=omada-admins, omada-viewers"

	settings, err := Load(lookupFrom(environment))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := settings.SAMLRelayState, "cmVzb3VyY2UxX29tYWRhMQ=="; got != want {
		t.Errorf("relay state = %q, want %q", got, want)
	}
	if got, want := settings.SAMLExtraAttributes["resource_attribute"], "resource1"; got != want {
		t.Errorf("resource_attribute = %q, want %q", got, want)
	}
	if got, want := settings.SAMLExtraAttributes["omada_attribute"], "omada1"; got != want {
		t.Errorf("omada_attribute = %q, want %q", got, want)
	}
	// Order is the administrator's stated precedence, so it must survive; the
	// bare form means the two namespaces agree on the name.
	got := settings.SAMLGroupAllowlist
	if len(got) != 2 ||
		got[0] != (identity.GroupRule{Match: "omada_admins", Emit: "omada-admins"}) ||
		got[1] != (identity.GroupRule{Match: "omada-viewers", Emit: "omada-viewers"}) {
		t.Errorf("group allowlist = %v", got)
	}
}

func TestLoadDefaultsIdentityProviderInitiatedSettingsToUnset(t *testing.T) {
	settings, err := Load(lookupFrom(baseEnvironment()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if settings.SAMLRelayState != "" {
		t.Errorf("relay state = %q, want empty", settings.SAMLRelayState)
	}
	if settings.SAMLExtraAttributes != nil {
		t.Errorf("extra attributes = %v, want nil", settings.SAMLExtraAttributes)
	}
	if settings.SAMLGroupAllowlist != nil {
		t.Errorf("group allowlist = %v, want nil", settings.SAMLGroupAllowlist)
	}
}

func TestLoadRejectsANonHTTPSACSOverride(t *testing.T) {
	for name, value := range map[string]string{
		"plain http": "http://omada.example.test/sso/saml/login",
		"no host":    "https:///sso/saml/login",
		"not a URL":  "::not a url::",
	} {
		t.Run(name, func(t *testing.T) {
			environment := baseEnvironment()
			environment["BRIDGIT_SAML_ACS_URL"] = value
			if _, err := Load(lookupFrom(environment)); err == nil {
				t.Fatalf("Load() accepted %q", value)
			}
		})
	}
}

func TestLoadRejectsMalformedExtraAttributes(t *testing.T) {
	for name, value := range map[string]string{
		"missing separator": "resource_attribute",
		"empty value":       "resource_attribute=",
		"empty name":        "=resource1",
		"duplicate name":    "resource_attribute=a, resource_attribute=b",
	} {
		t.Run(name, func(t *testing.T) {
			environment := baseEnvironment()
			environment["BRIDGIT_SAML_EXTRA_ATTRIBUTES"] = value
			if _, err := Load(lookupFrom(environment)); err == nil {
				t.Fatalf("Load() accepted %q", value)
			}
		})
	}
}

func TestLoadRejectsMalformedGroupRules(t *testing.T) {
	for name, value := range map[string]string{
		"empty provider group": "omada_admins=",
		"empty upstream group": "=omada-admins",
		"duplicate upstream":   "a=x, a=y",
	} {
		t.Run(name, func(t *testing.T) {
			environment := baseEnvironment()
			environment["BRIDGIT_SAML_GROUPS"] = value
			if _, err := Load(lookupFrom(environment)); err == nil {
				t.Fatalf("Load() accepted %q", value)
			}
		})
	}
}

func baseEnvironment() map[string]string {
	return map[string]string{
		"BRIDGIT_PUBLIC_URL":            "https://bridge.example.test",
		"BRIDGIT_OIDC_ISSUER":           "https://id.example.test",
		"BRIDGIT_OIDC_CLIENT_ID":        "client-id",
		"BRIDGIT_OIDC_CLIENT_SECRET":    "client-secret",
		"BRIDGIT_SAML_CERT_FILE":        "./secrets/saml.crt",
		"BRIDGIT_SAML_KEY_FILE":         "./secrets/saml.key",
		"BRIDGIT_SAML_SP_METADATA_FILE": "./config/omada.xml",
	}
}

func lookupFrom(environment map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	}
}
