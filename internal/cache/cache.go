package cache

import (
	"context"
	"crypto/tls"
)

type Cache interface {
	Get(ctx context.Context) (*tls.Certificate, error)
	Put(ctx context.Context, cert *tls.Certificate) error
}
