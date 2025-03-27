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
	b, err := os.ReadFile(string(c))
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return nil, err
	}
	return tlsutil.ParseKeyPair(b, nil)
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
