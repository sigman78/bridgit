package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestMetadataCommandBootstrapsOmadaWithoutSPConfiguration(t *testing.T) {
	certificateFile, keyFile := writeCommandKeyPair(t)
	environment := map[string]string{
		"BRIDGIT_PUBLIC_URL":     "https://bridge.example.test",
		"BRIDGIT_SAML_CERT_FILE": certificateFile,
		"BRIDGIT_SAML_KEY_FILE":  keyFile,
	}
	var output bytes.Buffer

	if err := runMetadata(func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	}, &output); err != nil {
		t.Fatalf("runMetadata() error = %v", err)
	}
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(output.Bytes(), &metadata); err != nil {
		t.Fatalf("metadata output is invalid: %v", err)
	}
	if got, want := metadata.EntityID, "https://bridge.example.test/saml/metadata"; got != want {
		t.Errorf("entity ID = %q, want %q", got, want)
	}
}

func writeCommandKeyPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bridge.example.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "saml.crt")
	keyFile := filepath.Join(directory, "saml.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, keyFile
}
