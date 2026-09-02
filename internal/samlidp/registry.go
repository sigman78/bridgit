package samlidp

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
)

// Registry is an immutable allowlist of SAML service providers.
type Registry struct {
	providers map[string]*saml.EntityDescriptor
}

// NewRegistry parses and validates one service-provider metadata document.
func NewRegistry(metadataXML []byte) (*Registry, error) {
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataXML, &metadata); err != nil {
		return nil, fmt.Errorf("parse SAML service-provider metadata: %w", err)
	}
	if metadata.EntityID == "" {
		return nil, errors.New("SAML service-provider metadata has no entity ID")
	}
	if len(metadata.SPSSODescriptors) == 0 {
		return nil, errors.New("SAML service-provider metadata has no SP SSO descriptor")
	}
	acsCount := 0
	for _, descriptor := range metadata.SPSSODescriptors {
		for _, endpoint := range descriptor.AssertionConsumerServices {
			location, err := url.Parse(endpoint.Location)
			if err != nil || !location.IsAbs() {
				return nil, fmt.Errorf("SAML ACS location %q must be an absolute URL", endpoint.Location)
			}
			acsCount++
		}
	}
	if acsCount == 0 {
		return nil, errors.New("SAML service-provider metadata has no assertion consumer service")
	}
	return &Registry{providers: map[string]*saml.EntityDescriptor{metadata.EntityID: &metadata}}, nil
}

// GetServiceProvider returns metadata only for an explicitly registered entity.
func (r *Registry) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	metadata, ok := r.providers[entityID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return metadata, nil
}
