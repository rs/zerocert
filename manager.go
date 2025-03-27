package zerocert

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/rs/zerocert/internal/cache"
	"github.com/rs/zerocert/internal/dns01"
	"github.com/rs/zerocert/internal/glue"
	"github.com/rs/zerocert/internal/tlsutil"
)

const mTLSDomain = "zerocert"
const tlsProto = "zerocert"

type Manager struct {
	// Email is the ACME account's email address.
	Email string

	// Reg is the ACME account's registration URI.
	Reg string

	// Key is the ACME account's private key.
	Key []byte

	// Domain is the domain to obtain a certificate for.
	Domain string

	// CacheFile is the file to store the certificate and key.
	CacheFile string

	// TLSConfig serves as a base configuration for the TLS server.
	TLSConfig *tls.Config

	dns01Provider dns01.MemoryProvider
	dns01Server   dns01.Server

	// Cache is the cache to store the certificate and key.
	cache cache.Cache

	clientTLSConfig *tls.Config
	serverTLSConfig *tls.Config
	caCert          *x509.Certificate

	client *lego.Client

	initOnce sync.Once

	certMu sync.RWMutex
	cert   *tls.Certificate
}

type legoConfig struct {
	*Manager
}

func (c legoConfig) GetEmail() string {
	return c.Email
}

func (c legoConfig) GetRegistration() *registration.Resource {
	return &registration.Resource{
		URI: c.Reg,
	}
}

func (c legoConfig) GetPrivateKey() crypto.PrivateKey {
	privateKey, _ := tlsutil.LoadECPrivateKey(c.Key)
	return privateKey
}

func (m *Manager) init() error {
	privateKey, err := tlsutil.LoadECPrivateKey(m.Key)
	if err != nil {
		return fmt.Errorf("loading ACME key: %w", err)
	}
	caCert, caCertPEM, err := tlsutil.GenerateDeterministicCA(privateKey)
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	clientCert, err := tlsutil.GenerateCertificate(caCert, privateKey, mTLSDomain, false)
	if err != nil {
		return fmt.Errorf("generate client cert: %w", err)
	}
	serverCert, err := tlsutil.GenerateCertificate(caCert, privateKey, mTLSDomain, false)
	if err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	m.clientTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		NextProtos:   []string{tlsProto},
	}

	mtlsTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{tlsProto},
	}

	var serveTLSConfig *tls.Config
	if m.TLSConfig != nil {
		serveTLSConfig = m.TLSConfig.Clone()
	} else {
		serveTLSConfig = &tls.Config{}
	}
	serveTLSConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.GetCertificate(), nil
	}
	m.serverTLSConfig = &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if chi.ServerName == mTLSDomain {
				// Connections on the mTLS domain are handled by the mTLS TLS
				// config.
				return mtlsTLSConfig, nil
			}
			// Other connections are handled by the serve TLS config that
			// includes the certificate obtained via ACME protocol.
			return serveTLSConfig, nil
		},
	}

	m.dns01Server = dns01.Server{
		dns01.IPsChallenger{
			GetIPs: glue.RetreiveIPs,
		},
		&m.dns01Provider,
	}

	config := lego.NewConfig(legoConfig{m})
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("create ACME client: %v", err)
	}
	err = client.Challenge.SetDNS01Provider(&m.dns01Provider)
	if err != nil {
		return fmt.Errorf("set DNS01 provider: %v", err)
	}
	m.client = client
	return nil
}

// LoadOrRefresh loads the certificate from the cache if it is not expired.
// Otherwise, it obtains a new certificate from the ACME server and saves it to
// the cache.
func (m *Manager) LoadOrRefresh() (err error) {
	m.initOnce.Do(func() {
		if err = m.init(); err != nil {
			err = fmt.Errorf("init: %v", err)
		}
	})
	if err != nil {
		return err
	}

	if !m.needsRefresh() {
		return
	}

	if err = m.loadCache(); err != nil {
		return fmt.Errorf("loadCache: %v", err)
	}

	if !m.needsRefresh() {
		return
	}

	if err = m.obtain(); err != nil {
		return fmt.Errorf("obtain: %v", err)
	}

	if err := m.saveCache(); err != nil {
		return fmt.Errorf("saveCache: %v", err)
	}

	return nil
}

// NewTLSListener returns a new TLS listener that wraps l in order to provide a
// TLS server connection with the certificate obtained certificate. If l is nil,
// a default TCP listener on port 443 is created.
//
// It does also automatically handle mTLS connection performed between members
// of the same cluster to share the certificate and key. Those connections are
// are hidden to the user of the listener.
func (m *Manager) NewTLSListener(l net.Listener) net.Listener {
	if l == nil {
		l, _ = net.Listen("tcp", ":443")
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	m.cache = cache.Layered{
		cache.TLS{
			Port: port,
			GetIPs: func(ctx context.Context) ([]net.IP, error) {
				return glue.RetreiveIPs(ctx, m.Domain)
			},
			TLSDialer: &tls.Dialer{
				Config: m.clientTLSConfig,
			},
		},
		cache.File(m.CacheFile),
	}
	return &tlsListener{Listener: l, m: m}
}

type dnsListener struct {
	net.PacketConn
	m   *Manager
	buf []byte
}

func (l dnsListener) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := l.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if n > len(b) {
			return 0, addr, fmt.Errorf("buffer too small")
		}

		if n2 := l.m.dns01Server.ServeDNS(b[:n], l.buf); n2 > 0 {
			_, err = l.WriteTo(l.buf[:n2], addr)
			if err != nil {
				return 0, addr, err
			}
		} else {
			return n, addr, nil
		}
	}
}

// NewDNSListener returns a new DNS listener that wraps the given packet
// connection. Packets received are intercepted if they are DNS queries for the
// DNS-01 challenge. In that case, the listener responds with the challenge to
// the client.
func (m *Manager) NewDNSListener(pc net.PacketConn) net.PacketConn {
	return dnsListener{pc, m, make([]byte, 512)}
}

func (m *Manager) loadCache() error {
	if m.cache == nil {
		return nil
	}

	cert, err := m.cache.Get(context.Background())
	if err != nil {
		return err
	}

	m.certMu.Lock()
	defer m.certMu.Unlock()
	m.cert = cert
	return nil
}

func (m *Manager) saveCache() error {
	if m.cache == nil {
		return nil
	}

	m.certMu.RLock()
	defer m.certMu.RUnlock()
	return m.cache.Put(context.Background(), m.cert)
}

func (m *Manager) needsRefresh() bool {
	m.certMu.RLock()
	defer m.certMu.RUnlock()

	if m.cert == nil {
		return true
	}

	x509Cert, err := x509.ParseCertificate(m.cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Since(x509Cert.NotAfter) > -30*24*time.Hour
}

func (m *Manager) obtain() error {
	request := certificate.ObtainRequest{
		Domains: []string{"*" + m.Domain, m.Domain},
		Bundle:  true,
	}
	res, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return err
	}

	m.certMu.Lock()
	defer m.certMu.Unlock()
	m.cert = &cert
	return nil
}

func (c *Manager) GetCertificate() *tls.Certificate {
	c.certMu.RLock()
	defer c.certMu.RUnlock()
	return c.cert
}
