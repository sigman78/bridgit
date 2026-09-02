package oidcclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestAuthorizationURLProtectsTheOIDCRequest(t *testing.T) {
	issuer := newDiscoveryServer(t)
	client, err := New(context.Background(), Config{
		Issuer:       issuer.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const (
		state    = "random-state"
		nonce    = "random-nonce"
		verifier = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~"
	)
	authorizationURL, err := url.Parse(client.AuthorizationURL(state, nonce, verifier))
	if err != nil {
		t.Fatal(err)
	}
	query := authorizationURL.Query()

	wants := map[string]string{
		"client_id":             "pocket-id-client",
		"redirect_uri":          "https://bridge.example.test/oidc/callback",
		"response_type":         "code",
		"scope":                 "openid profile email groups",
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge_method": "S256",
		"code_challenge":        oauth2.S256ChallengeFromVerifier(verifier),
	}
	for name, want := range wants {
		if got := query.Get(name); got != want {
			t.Errorf("authorization parameter %s = %q, want %q", name, got, want)
		}
	}
}

func TestCompleteVerifiesTokenAndMapsPocketIDClaims(t *testing.T) {
	issuer := newTokenServer(t, tokenClaims{
		Nonce:             "expected-nonce",
		Subject:           "pocket-id-subject",
		PreferredUsername: "alice",
		Email:             "alice@example.test",
		Name:              "Alice Example",
		GivenName:         "Alice",
		FamilyName:        "Example",
		Groups:            []string{"omada-admins", "network-operators"},
	})
	client, err := New(context.Background(), Config{
		Issuer:       issuer.URL,
		ClientID:     "pocket-id-client",
		ClientSecret: "client-secret",
		RedirectURL:  "https://bridge.example.test/oidc/callback",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	principal, err := client.Complete(context.Background(), "authorization-code", "pkce-verifier", "expected-nonce")
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if got, want := principal.Subject, "pocket-id-subject"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	if got, want := principal.Username, "alice"; got != want {
		t.Errorf("username = %q, want %q", got, want)
	}
	if got, want := principal.Email, "alice@example.test"; got != want {
		t.Errorf("email = %q, want %q", got, want)
	}
	if got, want := principal.DisplayName, "Alice Example"; got != want {
		t.Errorf("display name = %q, want %q", got, want)
	}
	if got, want := strings.Join(principal.Groups, ","), "omada-admins,network-operators"; got != want {
		t.Errorf("groups = %q, want %q", got, want)
	}
}

func TestCompleteRejectsNonceMismatchAndMissingOmadaGroups(t *testing.T) {
	tests := []struct {
		name          string
		claims        tokenClaims
		expectedNonce string
	}{
		{
			name: "nonce mismatch",
			claims: tokenClaims{
				Nonce: "different-nonce", Subject: "subject", PreferredUsername: "alice", Groups: []string{"omada-admins"},
			},
			expectedNonce: "expected-nonce",
		},
		{
			name: "no Omada group",
			claims: tokenClaims{
				Nonce: "expected-nonce", Subject: "subject", PreferredUsername: "alice",
			},
			expectedNonce: "expected-nonce",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := newTokenServer(t, test.claims)
			client, err := New(context.Background(), Config{
				Issuer:       issuer.URL,
				ClientID:     "pocket-id-client",
				ClientSecret: "client-secret",
				RedirectURL:  "https://bridge.example.test/oidc/callback",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Complete(context.Background(), "authorization-code", "pkce-verifier", test.expectedNonce); err == nil {
				t.Fatal("Complete() accepted invalid identity claims")
			}
		})
	}
}

func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
			"response_types_supported": []string{
				"code",
			},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

type tokenClaims struct {
	Nonce             string
	Subject           string
	PreferredUsername string
	Email             string
	Name              string
	GivenName         string
	FamilyName        string
	Groups            []string
}

func newTokenServer(t *testing.T, claims tokenClaims) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                server.URL,
				"authorization_endpoint":                server.URL + "/authorize",
				"token_endpoint":                        server.URL + "/token",
				"jwks_uri":                              server.URL + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []any{map[string]any{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token request: %v", err)
			}
			if got := r.Form.Get("code_verifier"); got != "pkce-verifier" {
				t.Errorf("code_verifier = %q, want pkce-verifier", got)
			}
			now := time.Now()
			payload := map[string]any{
				"iss":                server.URL,
				"sub":                claims.Subject,
				"aud":                "pocket-id-client",
				"exp":                now.Add(time.Hour).Unix(),
				"iat":                now.Unix(),
				"nonce":              claims.Nonce,
				"preferred_username": claims.PreferredUsername,
				"email":              claims.Email,
				"name":               claims.Name,
				"given_name":         claims.GivenName,
				"family_name":        claims.FamilyName,
				"groups":             claims.Groups,
			}
			writeJSON(t, w, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     signJWT(t, key, payload),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
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

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
