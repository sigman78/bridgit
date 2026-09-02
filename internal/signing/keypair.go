package signing

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Load validates a persistent RSA keypair for SAML assertion signing.
func Load(certificateFile, keyFile string, now time.Time) (*rsa.PrivateKey, *x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load SAML signing keypair: %w", err)
	}
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("SAML signing key must be RSA")
	}
	if key.N.BitLen() < 2048 {
		return nil, nil, errors.New("SAML RSA signing key must be at least 2048 bits")
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, errors.New("SAML signing certificate chain is empty")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse SAML signing certificate: %w", err)
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, nil, errors.New("SAML signing certificate is not currently valid")
	}
	return key, certificate, nil
}
