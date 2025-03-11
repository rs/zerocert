package tlsutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Load EC private key from bytes
func LoadECPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode EC private key")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// ParseKeyPair parses a PEM-encoded certificate and private key form the same
// PEM. It takes the output of a os.ReadFile or io.ReadAll call as input and
// passes its error down if non-nil.
func ParseKeyPair(pem []byte, err error) (*tls.Certificate, error) {
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pem, pem)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// EncodeKeyPair encodes a tls.Certificate into a single PEM block that contains
// both the certificate and private key.
func EncodeKeyPair(cert *tls.Certificate) ([]byte, error) {
	var buf bytes.Buffer

	// Encode certificate chain
	for _, certBytes := range cert.Certificate {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		}); err != nil {
			return nil, fmt.Errorf("failed to encode certificate: %w", err)
		}
	}

	// Encode private key
	var keyBytes []byte
	var keyType string

	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		var err error
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		keyType = "EC PRIVATE KEY"
	case []byte:
		// Raw PKCS8 key
		keyBytes = key
		keyType = "PRIVATE KEY"
	default:
		// Try PKCS8 marshaling for other types
		var err error
		keyBytes, err = x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("unsupported private key type: %T", cert.PrivateKey)
		}
		keyType = "PRIVATE KEY"
	}

	// Encode the key
	if err := pem.Encode(&buf, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return buf.Bytes(), nil
}
