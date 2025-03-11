package cache

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"

	"github.com/rs/zerocert/internal/tlsutil"
)

// File is a cache that stores certificates in a file.
type File string

func (c File) Get(ctx context.Context) (*tls.Certificate, error) {
	return tlsutil.ParseKeyPair(os.ReadFile(string(c)))
}

func (c File) Put(ctx context.Context, cert *tls.Certificate) error {
	pem, err := tlsutil.EncodeKeyPair(cert)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Base(string(c)), 0700); err != nil {
		return err
	}
	return os.WriteFile(string(c), pem, 0600)
}
