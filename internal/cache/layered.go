package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"log"

	"github.com/rs/zerocert/internal/tlsutil"
)

// Layered is a cache that handle certificates in multiple caches.
type Layered []Cache

// Get returns the most recent certificate returned by the layered caches.
func (c Layered) Get(ctx context.Context) (*tls.Certificate, error) {
	var certs []*tls.Certificate
	var errs []error
	for _, cache := range c {
		crt, err := cache.Get(ctx)
		if crt != nil {
			certs = append(certs, crt)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(certs) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(certs) == 0 {
		log.Printf("cache fetch non-fatal error: %v", errs)
	}
	return tlsutil.LatestCertificate(certs)
}

// Put stores the certificate in all caches.
func (c Layered) Put(ctx context.Context, cert *tls.Certificate) error {
	var errs []error
	for _, cache := range c {
		if err := cache.Put(ctx, cert); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
