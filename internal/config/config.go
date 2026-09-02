package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// LookupEnv matches os.LookupEnv and makes configuration behavior testable.
type LookupEnv func(string) (string, bool)

// Settings is Bridgit's validated process configuration.
type Settings struct {
	PublicURL           url.URL
	ListenAddr          string
	OIDCIssuer          string
	OIDCClientID        string
	OIDCClientSecret    string
	OIDCRedirectURL     string
	UsernameClaim       string
	GroupsClaim         string
	SAMLCertificateFile string
	SAMLKeyFile         string
	SPMetadataFile      string
	SAMLACSURL          string
	SAMLRelayState      string
	SAMLExtraAttributes map[string]string
	SAMLGroupAllowlist  []string
	TransactionTTL      time.Duration
	SessionTTL          time.Duration
	LogLevel            string
}

// Load reads, defaults, and validates all environment-backed settings.
func Load(lookup LookupEnv) (Settings, error) {
	var settings Settings
	if lookup == nil {
		return settings, errors.New("environment lookup function is required")
	}

	publicURLValue, err := required(lookup, "BRIDGIT_PUBLIC_URL")
	if err != nil {
		return settings, err
	}
	publicURL, err := url.Parse(publicURLValue)
	if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" || publicURL.User != nil || publicURL.Path != "" || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return settings, errors.New("BRIDGIT_PUBLIC_URL must be an HTTPS origin without a path, query, fragment, or user information")
	}
	settings.PublicURL = *publicURL
	settings.OIDCRedirectURL = publicURL.String() + "/oidc/callback"

	settings.OIDCIssuer, err = required(lookup, "BRIDGIT_OIDC_ISSUER")
	if err != nil {
		return Settings{}, err
	}
	issuerURL, parseErr := url.Parse(settings.OIDCIssuer)
	if parseErr != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return Settings{}, errors.New("BRIDGIT_OIDC_ISSUER must be an HTTPS URL without query, fragment, or user information")
	}
	settings.OIDCClientID, err = required(lookup, "BRIDGIT_OIDC_CLIENT_ID")
	if err != nil {
		return Settings{}, err
	}
	settings.OIDCClientSecret, err = requiredUntrimmed(lookup, "BRIDGIT_OIDC_CLIENT_SECRET")
	if err != nil {
		return Settings{}, err
	}
	settings.SAMLCertificateFile, err = required(lookup, "BRIDGIT_SAML_CERT_FILE")
	if err != nil {
		return Settings{}, err
	}
	settings.SAMLKeyFile, err = required(lookup, "BRIDGIT_SAML_KEY_FILE")
	if err != nil {
		return Settings{}, err
	}
	settings.SPMetadataFile, err = required(lookup, "BRIDGIT_SAML_SP_METADATA_FILE")
	if err != nil {
		return Settings{}, err
	}

	settings.SAMLACSURL = optional(lookup, "BRIDGIT_SAML_ACS_URL", "")
	if settings.SAMLACSURL != "" {
		acsURL, parseErr := url.Parse(settings.SAMLACSURL)
		if parseErr != nil || acsURL.Scheme != "https" || acsURL.Host == "" {
			return Settings{}, errors.New("BRIDGIT_SAML_ACS_URL must be an absolute HTTPS URL")
		}
	}
	settings.SAMLRelayState = optional(lookup, "BRIDGIT_SAML_RELAY_STATE", "")
	settings.SAMLExtraAttributes, err = attributes(lookup, "BRIDGIT_SAML_EXTRA_ATTRIBUTES")
	if err != nil {
		return Settings{}, err
	}
	settings.SAMLGroupAllowlist = list(lookup, "BRIDGIT_SAML_GROUPS")

	settings.ListenAddr = optional(lookup, "BRIDGIT_LISTEN_ADDR", ":8080")
	settings.UsernameClaim = optional(lookup, "BRIDGIT_USERNAME_CLAIM", "preferred_username")
	settings.GroupsClaim = optional(lookup, "BRIDGIT_GROUPS_CLAIM", "groups")
	settings.LogLevel = optional(lookup, "BRIDGIT_LOG_LEVEL", "info")
	settings.TransactionTTL, err = duration(lookup, "BRIDGIT_TRANSACTION_TTL", time.Minute)
	if err != nil {
		return Settings{}, err
	}
	if settings.TransactionTTL > 90*time.Second {
		return Settings{}, errors.New("BRIDGIT_TRANSACTION_TTL cannot exceed the 90s SAML request validity window")
	}
	settings.SessionTTL, err = duration(lookup, "BRIDGIT_SESSION_TTL", 8*time.Hour)
	if err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func required(lookup LookupEnv, name string) (string, error) {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func requiredUntrimmed(lookup LookupEnv, name string) (string, error) {
	value, ok := lookup(name)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func optional(lookup LookupEnv, name, fallback string) string {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return fallback
	}
	return value
}

// list reads a comma-separated setting, preserving the administrator's order
// and dropping empty entries.
func list(lookup LookupEnv, name string) []string {
	raw, ok := lookup(name)
	if !ok {
		return nil
	}
	var values []string
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			values = append(values, entry)
		}
	}
	return values
}

// attributes reads "name=value" pairs, comma-separated. Values may contain "="
// so that opaque provider identifiers survive unaltered.
func attributes(lookup LookupEnv, name string) (map[string]string, error) {
	entries := list(lookup, name)
	if len(entries) == 0 {
		return nil, nil
	}
	parsed := make(map[string]string, len(entries))
	for _, entry := range entries {
		attributeName, value, found := strings.Cut(entry, "=")
		attributeName = strings.TrimSpace(attributeName)
		value = strings.TrimSpace(value)
		if !found || attributeName == "" || value == "" {
			return nil, fmt.Errorf("%s entries must be name=value", name)
		}
		if _, duplicate := parsed[attributeName]; duplicate {
			return nil, fmt.Errorf("%s repeats attribute %q", name, attributeName)
		}
		parsed[attributeName] = value
	}
	return parsed, nil
}

func duration(lookup LookupEnv, name string, fallback time.Duration) (time.Duration, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return parsed, nil
}
