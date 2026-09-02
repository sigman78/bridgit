package oidcclient

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigman78/bridgit/internal/identity"
	"golang.org/x/oauth2"
)

// Config identifies the upstream OIDC provider and this confidential client.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	UsernameClaim string
	GroupsClaim   string
	HTTPClient    *http.Client
}

// Client starts and completes OIDC authorization-code flows.
type Client struct {
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	usernameClaim string
	groupsClaim   string
	httpClient    *http.Client
}

// New discovers the configured provider and prepares a reusable OIDC client.
func New(ctx context.Context, config Config) (*Client, error) {
	if config.Issuer == "" {
		return nil, errors.New("OIDC issuer is required")
	}
	if config.ClientID == "" {
		return nil, errors.New("OIDC client ID is required")
	}
	if config.ClientSecret == "" {
		return nil, errors.New("OIDC client secret is required")
	}
	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil || !redirectURL.IsAbs() {
		return nil, errors.New("OIDC redirect URL must be absolute")
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	discoveryContext := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(discoveryContext, config.Issuer)
	if err != nil {
		return nil, err
	}
	usernameClaim := config.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}
	groupsClaim := config.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	return &Client{
		oauth2Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		usernameClaim: usernameClaim,
		groupsClaim:   groupsClaim,
		httpClient:    httpClient,
	}, nil
}

// Complete exchanges an authorization code, verifies the returned ID token,
// validates its nonce, and translates its claims into a Principal.
func (c *Client) Complete(ctx context.Context, code, pkceVerifier, expectedNonce string) (identity.Principal, error) {
	var principal identity.Principal
	if code == "" {
		return principal, errors.New("OIDC authorization code is required")
	}

	requestContext := oidc.ClientContext(ctx, c.httpClient)
	oauthToken, err := c.oauth2Config.Exchange(requestContext, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return principal, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return principal, errors.New("OIDC token response did not contain an ID token")
	}
	idToken, err := c.verifier.Verify(requestContext, rawIDToken)
	if err != nil {
		return principal, fmt.Errorf("verify OIDC ID token: %w", err)
	}

	claims := map[string]json.RawMessage{}
	if err := idToken.Claims(&claims); err != nil {
		return principal, fmt.Errorf("decode OIDC ID token claims: %w", err)
	}
	nonce, err := stringClaim(claims, "nonce")
	if err != nil || subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return principal, errors.New("OIDC ID token nonce did not match the authorization transaction")
	}

	principal.Subject, err = requiredStringClaim(claims, "sub")
	if err != nil {
		return identity.Principal{}, err
	}
	principal.Username, err = requiredStringClaim(claims, c.usernameClaim)
	if err != nil {
		return identity.Principal{}, err
	}
	principal.Groups, err = requiredStringSliceClaim(claims, c.groupsClaim)
	if err != nil {
		return identity.Principal{}, err
	}
	principal.Email, _ = stringClaim(claims, "email")
	principal.DisplayName, _ = stringClaim(claims, "name")
	principal.GivenName, _ = stringClaim(claims, "given_name")
	principal.FamilyName, _ = stringClaim(claims, "family_name")
	return principal, nil
}

func requiredStringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	value, err := stringClaim(claims, name)
	if err != nil || value == "" {
		return "", fmt.Errorf("OIDC ID token requires non-empty string claim %q", name)
	}
	return value, nil
}

func stringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	raw, ok := claims[name]
	if !ok {
		return "", fmt.Errorf("OIDC ID token is missing claim %q", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("OIDC ID token claim %q is not a string", name)
	}
	return value, nil
}

func requiredStringSliceClaim(claims map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := claims[name]
	if !ok {
		return nil, fmt.Errorf("OIDC ID token is missing claim %q", name)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("OIDC ID token requires non-empty string-array claim %q", name)
	}
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("OIDC ID token claim %q contains an empty value", name)
		}
	}
	return values, nil
}

// AuthorizationURL returns the Pocket ID URL for one protected authorization
// transaction.
func (c *Client) AuthorizationURL(state, nonce, pkceVerifier string) string {
	return c.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
}
