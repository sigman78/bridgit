package samlidp

import (
	"crypto"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	metadataPath = "/saml/metadata"
	ssoPath      = "/saml/sso"
	startPath    = "/saml/start"
)

// Config contains the stable public identity and signing material of the SAML
// identity provider.
type Config struct {
	PublicURL        url.URL
	Key              crypto.Signer
	Certificate      *x509.Certificate
	ServiceProviders saml.ServiceProviderProvider
	Sessions         saml.SessionProvider
	// ServiceProviderID names the provider that /saml/start logs in to.
	ServiceProviderID string
	// RelayState is passed to that provider verbatim beside the assertion.
	// Some providers carry their own routing identifiers in it rather than a
	// return URL, so Bridgit never interprets the value.
	RelayState string
}

// Provider exposes Bridgit's SAML identity-provider endpoints.
type Provider struct {
	idp               *saml.IdentityProvider
	serviceProviderID string
	relayState        string
}

// New constructs a SAML identity provider rooted at Config.PublicURL.
func New(config Config) (*Provider, error) {
	if config.PublicURL.Scheme == "" || config.PublicURL.Host == "" {
		return nil, errors.New("SAML public URL must be absolute")
	}
	if config.Key == nil {
		return nil, errors.New("SAML signing key is required")
	}
	if config.Certificate == nil {
		return nil, errors.New("SAML signing certificate is required")
	}

	metadataURL := endpointURL(config.PublicURL, metadataPath)
	ssoURL := endpointURL(config.PublicURL, ssoPath)
	idp := &saml.IdentityProvider{
		Key:                     config.Key,
		Signer:                  config.Key,
		Certificate:             config.Certificate,
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		ServiceProviderProvider: config.ServiceProviders,
		SessionProvider:         config.Sessions,
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		Logger:                  logger.DefaultLogger,
	}

	return &Provider{
		idp:               idp,
		serviceProviderID: config.ServiceProviderID,
		relayState:        config.RelayState,
	}, nil
}

// Handler serves the IdP metadata and SSO endpoints.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(metadataPath, p.serveMetadata)
	mux.HandleFunc(ssoPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		p.idp.ServeSSO(w, r)
	})
	mux.HandleFunc(startPath, p.serveIDPInitiated)
	return mux
}

// serveIDPInitiated begins a login that the service provider cannot begin
// itself. Providers whose SAML support is identity-provider-initiated only
// have no endpoint that emits an AuthnRequest, so this endpoint is the entry
// point: it establishes the bridge session, then delivers an unsolicited
// assertion by auto-submitting form POST.
func (p *Provider) serveIDPInitiated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if p.serviceProviderID == "" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	p.idp.ServeIDPInitiated(w, r, p.serviceProviderID, p.relayState)
}

// MetadataXML returns the same metadata document served by the HTTP endpoint.
func (p *Provider) MetadataXML() ([]byte, error) {
	metadata, err := xml.MarshalIndent(p.metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), metadata...), nil
}

// metadata narrows the library's generic descriptor to what Bridgit actually
// does: HTTP-Redirect SSO only, and persistent name identifiers only.
func (p *Provider) metadata() *saml.EntityDescriptor {
	metadata := p.idp.Metadata()
	for descriptorIndex := range metadata.IDPSSODescriptors {
		services := metadata.IDPSSODescriptors[descriptorIndex].SingleSignOnServices
		redirectOnly := services[:0]
		for _, service := range services {
			if service.Binding == saml.HTTPRedirectBinding {
				redirectOnly = append(redirectOnly, service)
			}
		}
		metadata.IDPSSODescriptors[descriptorIndex].SingleSignOnServices = redirectOnly
		metadata.IDPSSODescriptors[descriptorIndex].NameIDFormats = []saml.NameIDFormat{saml.PersistentNameIDFormat}
	}
	return metadata
}

func (p *Provider) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	metadata, err := p.MetadataXML()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(metadata); err != nil {
		p.idp.Logger.Printf("failed to write SAML metadata: %s", err)
	}
}

func endpointURL(base url.URL, path string) url.URL {
	base.Path = path
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base
}
