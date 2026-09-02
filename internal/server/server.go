package server

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/crewjam/saml"
	"github.com/sigman78/bridgit/internal/oidcclient"
	"github.com/sigman78/bridgit/internal/samlidp"
	"github.com/sigman78/bridgit/internal/session"
)

const (
	oidcCallbackPath      = "/oidc/callback"
	sessionCookieName     = "__Host-bridgit_session"
	transactionCookieName = "__Host-bridgit_txn"
)

// Config contains the already-loaded protocol configuration for the HTTP app.
type Config struct {
	PublicURL               url.URL
	SAMLKey                 crypto.Signer
	SAMLCertificate         *x509.Certificate
	ServiceProviderMetadata []byte
	TransactionTTL          time.Duration
	SessionTTL              time.Duration
	// RelayState accompanies every identity-provider-initiated assertion.
	RelayState string
	// ExtraAttributes are constant assertion attributes that identify this
	// bridge to the service provider, beside the per-user attributes.
	ExtraAttributes map[string]string
	// ACSURL, when set, overrides the assertion consumer service address the
	// service-provider metadata advertises.
	ACSURL string
	// GroupAllowlist, when set, is the ordered set of groups this service
	// provider accepts. The first entry the user holds becomes their single
	// group; a user holding none is refused. Empty passes every group through.
	GroupAllowlist []string
}

// Server orchestrates the browser flow between the two protocol adapters.
type Server struct {
	oidc            *oidcclient.Client
	state           *session.Memory
	transactionTTL  time.Duration
	sessionTTL      time.Duration
	extraAttributes []saml.Attribute
	groupAllowlist  []string
	handler         http.Handler
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
	registry, err := samlidp.NewRegistry(config.ServiceProviderMetadata, config.ACSURL)
	if err != nil {
		return nil, err
	}

	bridge := &Server{
		oidc:            oidc,
		state:           session.NewMemory(time.Now),
		transactionTTL:  config.TransactionTTL,
		sessionTTL:      config.SessionTTL,
		extraAttributes: staticAttributes(config.ExtraAttributes),
		groupAllowlist:  append([]string(nil), config.GroupAllowlist...),
	}
	provider, err := samlidp.New(samlidp.Config{
		PublicURL:         config.PublicURL,
		Key:               config.SAMLKey,
		Certificate:       config.SAMLCertificate,
		ServiceProviders:  registry,
		Sessions:          bridge,
		ServiceProviderID: registry.EntityID(),
		RelayState:        config.RelayState,
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
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.state.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
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
	// Resolve the browser binding before consuming the transaction, so that a
	// request from a browser which never started this login cannot burn it.
	binding, err := r.Cookie(transactionCookieName)
	if err != nil || binding.Value == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	transaction, err := s.state.TakeTransaction(r.URL.Query().Get("state"))
	clearTransactionCookie(w)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	presented := sha256.Sum256([]byte(binding.Value))
	if subtle.ConstantTimeCompare(presented[:], transaction.BindingHash[:]) != 1 {
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
	// The service provider receives this value in every assertion and normally
	// retains it, so it must not be the browser's session cookie.
	samlSessionIndex, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	expiresAt := now.Add(s.sessionTTL)
	if err := s.state.PutSession(sessionID, session.BridgeSession{
		Principal:        principal,
		SAMLSessionIndex: samlSessionIndex,
		CreatedAt:        now,
		ExpiresAt:        expiresAt,
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
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
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if bridgeSession, ok := s.state.GetSession(cookie.Value); ok {
			// An identity-provider-initiated login has no AuthnRequest, so
			// there is no request ID to spend. Replay protection applies to
			// the service-provider-initiated path, which does have one.
			if authnRequest.Request.ID != "" &&
				!s.state.UseSAMLRequest(authnRequest.Request.ID, time.Now().Add(saml.MaxIssueDelay)) {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return nil
			}
			samlAssertionSession := s.samlSession(bridgeSession)
			if samlAssertionSession == nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return nil
			}
			return samlAssertionSession
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
	bindingSecret, err := randomString(32)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if err := s.state.PutTransaction(state, session.Transaction{
		ReturnURL:    r.URL.RequestURI(),
		Nonce:        nonce,
		PKCEVerifier: pkceVerifier,
		BindingHash:  sha256.Sum256([]byte(bindingSecret)),
		ExpiresAt:    time.Now().Add(s.transactionTTL),
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil
	}
	// Only the browser holding this secret may complete the transaction. A
	// second login started in the same browser replaces it, abandoning the
	// first; that is the same outcome the single-use transaction already had.
	http.SetCookie(w, &http.Cookie{
		Name:     transactionCookieName,
		Value:    bindingSecret,
		Path:     "/",
		MaxAge:   cookieSeconds(s.transactionTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, s.oidc.AuthorizationURL(state, nonce, pkceVerifier), http.StatusFound)
	return nil
}

func clearTransactionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     transactionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// cookieSeconds converts a TTL to a Max-Age, never rounding a positive lifetime
// down to zero, which would make the cookie last for the whole browser session.
func cookieSeconds(ttl time.Duration) int {
	seconds := int(ttl / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

// samlSession renders a bridge session as an assertion session, or nil when
// the user holds no group this service provider accepts.
func (s *Server) samlSession(bridgeSession session.BridgeSession) *saml.Session {
	principal := bridgeSession.Principal
	groups := selectGroups(principal.Groups, s.groupAllowlist)
	if groups == nil {
		return nil
	}
	groupValues := make([]saml.AttributeValue, 0, len(groups))
	for _, group := range groups {
		groupValues = append(groupValues, saml.AttributeValue{Type: "xs:string", Value: group})
	}
	return &saml.Session{
		ID:           bridgeSession.SAMLSessionIndex,
		CreateTime:   bridgeSession.CreatedAt,
		ExpireTime:   bridgeSession.ExpiresAt,
		Index:        bridgeSession.SAMLSessionIndex,
		NameID:       principal.Subject,
		NameIDFormat: string(saml.PersistentNameIDFormat),
		CustomAttributes: append([]saml.Attribute{
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
		}, s.extraAttributes...),
	}
}

// selectGroups reduces the user's groups to the one this service provider
// should see. A provider that resolves exactly one group per assertion fails
// its lookup when handed several, so an allowlist both authorizes the login
// and makes precedence explicit: earlier entries win.
func selectGroups(groups, allowlist []string) []string {
	if len(allowlist) == 0 {
		return groups
	}
	for _, allowed := range allowlist {
		for _, group := range groups {
			if group == allowed {
				return []string{group}
			}
		}
	}
	return nil
}

// staticAttributes renders constant attributes in a stable order, so that two
// assertions for the same user differ only where they are meant to.
func staticAttributes(values map[string]string) []saml.Attribute {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	attributes := make([]saml.Attribute, 0, len(names))
	for _, name := range names {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: name,
			Name:         name,
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: values[name]}},
		})
	}
	return attributes
}

func randomString(byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
