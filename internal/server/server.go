package server

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/sigman78/bridgit/internal/oidcclient"
	"github.com/sigman78/bridgit/internal/samlidp"
	"github.com/sigman78/bridgit/internal/session"
)

const oidcCallbackPath = "/oidc/callback"

// Config contains the already-loaded protocol configuration for the HTTP app.
type Config struct {
	PublicURL               url.URL
	SAMLKey                 crypto.Signer
	SAMLCertificate         *x509.Certificate
	ServiceProviderMetadata []byte
	TransactionTTL          time.Duration
	SessionTTL              time.Duration
}

// Server orchestrates the browser flow between the two protocol adapters.
type Server struct {
	oidc           *oidcclient.Client
	state          *session.Memory
	transactionTTL time.Duration
	sessionTTL     time.Duration
	handler        http.Handler
}

// New constructs the complete Bridgit HTTP handler.
func New(config Config, oidc *oidcclient.Client) (*Server, error) {
	if oidc == nil {
		return nil, errors.New("OIDC client is required")
	}
	if config.TransactionTTL <= 0 {
		return nil, errors.New("transaction TTL must be positive")
	}
	if config.SessionTTL <= 0 {
		return nil, errors.New("session TTL must be positive")
	}
	registry, err := samlidp.NewRegistry(config.ServiceProviderMetadata)
	if err != nil {
		return nil, err
	}

	bridge := &Server{
		oidc:           oidc,
		state:          session.NewMemory(time.Now),
		transactionTTL: config.TransactionTTL,
		sessionTTL:     config.SessionTTL,
	}
	provider, err := samlidp.New(samlidp.Config{
		PublicURL:        config.PublicURL,
		Key:              config.SAMLKey,
		Certificate:      config.SAMLCertificate,
		ServiceProviders: registry,
		Sessions:         bridge,
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/saml/", provider.Handler())
	mux.HandleFunc(oidcCallbackPath, bridge.handleOIDCCallback)
	mux.HandleFunc("/healthz", bridge.handleHealth)
	mux.HandleFunc("/readyz", bridge.handleHealth)
	mux.HandleFunc("/logout", bridge.handleLogout)
	bridge.handler = mux
	return bridge, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie("__Host-bridgit_session"); err == nil {
		s.state.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-bridgit_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	transaction, err := s.state.TakeTransaction(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	principal, err := s.oidc.Complete(r.Context(), r.URL.Query().Get("code"), transaction.PKCEVerifier, transaction.Nonce)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	sessionID, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	expiresAt := now.Add(s.sessionTTL)
	if err := s.state.PutSession(sessionID, session.BridgeSession{
		Principal: principal,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-bridgit_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(s.sessionTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, transaction.ReturnURL, http.StatusSeeOther)
}

// ServeHTTP serves Bridgit's public endpoints.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// GetSession implements crewjam/saml.SessionProvider. The first visit creates
// an OIDC transaction; a later slice resolves an established bridge session.
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request, authnRequest *saml.IdpAuthnRequest) *saml.Session {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil
	}
	if cookie, err := r.Cookie("__Host-bridgit_session"); err == nil {
		if bridgeSession, ok := s.state.GetSession(cookie.Value); ok {
			if !s.state.UseSAMLRequest(authnRequest.Request.ID, time.Now().Add(saml.MaxIssueDelay)) {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return nil
			}
			return samlSession(cookie.Value, bridgeSession)
		}
	}
	state, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	nonce, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	pkceVerifier, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if err := s.state.PutTransaction(state, session.Transaction{
		ReturnURL:    r.URL.RequestURI(),
		Nonce:        nonce,
		PKCEVerifier: pkceVerifier,
		ExpiresAt:    time.Now().Add(s.transactionTTL),
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil
	}
	http.Redirect(w, r, s.oidc.AuthorizationURL(state, nonce, pkceVerifier), http.StatusFound)
	return nil
}

func samlSession(id string, bridgeSession session.BridgeSession) *saml.Session {
	principal := bridgeSession.Principal
	groupValues := make([]saml.AttributeValue, 0, len(principal.Groups))
	for _, group := range principal.Groups {
		groupValues = append(groupValues, saml.AttributeValue{Type: "xs:string", Value: group})
	}
	return &saml.Session{
		ID:           id,
		CreateTime:   bridgeSession.CreatedAt,
		ExpireTime:   bridgeSession.ExpiresAt,
		Index:        id,
		NameID:       principal.Subject,
		NameIDFormat: string(saml.PersistentNameIDFormat),
		CustomAttributes: []saml.Attribute{
			{
				FriendlyName: "username",
				Name:         "username",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values:       []saml.AttributeValue{{Type: "xs:string", Value: principal.Username}},
			},
			{
				FriendlyName: "usergroup_name",
				Name:         "usergroup_name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values:       groupValues,
			},
		},
	}
}

func randomString(byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
