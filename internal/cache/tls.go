package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/rs/zerocert/internal/tlsutil"
)

// TLS is a cache that fetches certificates from multiple TLS servers in
// parallel and keep the most recent one. This cache does not implement storage.
// Use a layered cache with a cache that implements storage to store the
// certificate.
type TLS struct {
	// Port to connect to, the default is 443.
	Port string

	// GetIPs is a function that returns the IP addresses of the TLS servers.
	GetIPs func(ctx context.Context) ([]net.IP, error)

	TLSDialer *tls.Dialer
}

var defaultTLSDialer = &tls.Dialer{}

func (c TLS) Get(ctx context.Context) (*tls.Certificate, error) {
	if c.GetIPs == nil {
		return nil, errors.New("GetIPs is not set")
	}

	ips, err := c.GetIPs(ctx)
	if err != nil {
		return nil, err
	}

	type result struct {
		cert *tls.Certificate
		err  error
	}
	var results = make(chan result, len(ips))

	for _, ip := range ips {
		go func(ip net.IP) {
			cert, err := c.fetchCertificate(ctx, ip)
			results <- result{cert, err}
		}(ip)
	}

	var certs []*tls.Certificate
	var errs []error
	for i := 0; i < len(ips); i++ {
		r := <-results
		certs = append(certs, r.cert)
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
	}

	if len(certs) == 0 {
		return nil, errors.Join(errs...)
	}

	return tlsutil.LatestCertificate(certs)
}

func (c TLS) fetchCertificate(ctx context.Context, ip net.IP) (*tls.Certificate, error) {
	port := c.Port
	if port == "" {
		port = "443"
	}
	d := c.TLSDialer
	if d == nil {
		d = defaultTLSDialer
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return tlsutil.ParseKeyPair(io.ReadAll(conn))
}

func (c TLS) Put(ctx context.Context, cert *tls.Certificate) error {
	return nil // not implemented with this cache
}
