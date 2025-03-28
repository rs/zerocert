package tlsutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateDeterministicCA deterministically generates a CA certificate from
// privateKey so the client and the server can perform an mTLS handshake with
// only a private key shared.
func GenerateDeterministicCA(privateKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	// Generate a deterministic serial number from the private key
	hashedKey := sha256.Sum256(privateKey.D.Bytes())
	serialNumber := new(big.Int).SetBytes(hashedKey[:])

	// Use fixed dates for deterministic output
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(100 * 365 * 24 * time.Hour) // 100-year validity

	caTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Deterministic CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	return caCert, nil
}

// GenerateCertificate generates a client or server certificate signed by the
// caCert and caKey.
func GenerateCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, domain string, isServer bool) (tls.Certificate, error) {
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2), // Fixed serial for reproducibility
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isServer {
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %v", err)
	}

	var pemBuf bytes.Buffer

	if err = pem.Encode(&pemBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode certificate: %v", err)
	}

	if err = pem.Encode(&pemBuf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode private key: %v", err)
	}

	pemBytes := pemBuf.Bytes()
	return tls.X509KeyPair(pemBytes, pemBytes)
}

func LatestCertificate(certs []*tls.Certificate) (*tls.Certificate, error) {
	var errs []error
	var latest *tls.Certificate
	var latestNotAfter time.Time
	for _, cert := range certs {
		if latest == nil {
			latest = cert
			continue
		}
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if x509Cert.NotAfter.After(latestNotAfter) {
			latest = cert
		}
	}

	if latest == nil && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return latest, nil
}
