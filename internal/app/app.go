package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sigman78/bridgit/internal/config"
	"github.com/sigman78/bridgit/internal/oidcclient"
	"github.com/sigman78/bridgit/internal/server"
	"github.com/sigman78/bridgit/internal/signing"
)

const maxMetadataBytes = 2 << 20

// New loads administrator-controlled protocol material and assembles Bridgit.
func New(ctx context.Context, settings config.Settings) (*server.Server, error) {
	key, certificate, err := signing.Load(settings.SAMLCertificateFile, settings.SAMLKeyFile, time.Now())
	if err != nil {
		return nil, err
	}
	metadata, err := readLimitedFile(settings.SPMetadataFile, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("load SAML service-provider metadata: %w", err)
	}
	oidc, err := oidcclient.New(ctx, oidcclient.Config{
		Issuer:        settings.OIDCIssuer,
		ClientID:      settings.OIDCClientID,
		ClientSecret:  settings.OIDCClientSecret,
		RedirectURL:   settings.OIDCRedirectURL,
		UsernameClaim: settings.UsernameClaim,
		GroupsClaim:   settings.GroupsClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize OIDC provider: %w", err)
	}
	return server.New(server.Config{
		PublicURL:               settings.PublicURL,
		SAMLKey:                 key,
		SAMLCertificate:         certificate,
		ServiceProviderMetadata: metadata,
		TransactionTTL:          settings.TransactionTTL,
		SessionTTL:              settings.SessionTTL,
		ACSURL:                  settings.SAMLACSURL,
		RelayState:              settings.SAMLRelayState,
		ExtraAttributes:         settings.SAMLExtraAttributes,
		GroupAllowlist:          settings.SAMLGroupAllowlist,
	}, oidc)
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}
