package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ValidateClientCert checks if the provided client certificate is signed by the given CA certificate.
func ValidateClientCert(clientCert *x509.Certificate, caCert *x509.Certificate) error {
	if clientCert == nil {
		return errors.New("client certificate is nil")
	}
	if caCert == nil {
		return errors.New("CA certificate is nil")
	}

	// Create a cert pool with the CA certificate
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Create verification options
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Verify the certificate
	_, err := clientCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	return nil
}

// ValidateClientCertFromTLS checks if the TLS connection's peer certificate is signed by the given CA certificate.
func ValidateClientCertFromTLS(tc tls.ConnectionState, caCert *x509.Certificate) error {
	// Check if client provided a certificate
	if len(tc.PeerCertificates) == 0 {
		return errors.New("no client certificate provided")
	}

	// Validate the client certificate against the CA
	return ValidateClientCert(tc.PeerCertificates[0], caCert)
}
