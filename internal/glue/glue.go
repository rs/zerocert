package glue

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var rootServers = func() []string {
	var servers []string
	for i := 0; i < 13; i++ {
		servers = append(servers, string([]byte{'a' + byte(i)})+".root-servers.net")
	}
	return servers
}()

type Client struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips        []net.IP
	validUntil time.Time
}

func (c *Client) getCached(fqdn string) ([]net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, found := c.cache[fqdn]
	if !found {
		return nil, false
	}
	if e.validUntil.After(time.Now()) {
		return e.ips, true
	}
	return nil, false
}

func (c *Client) saveCache(fqdn string, ips []net.IP, ttl uint32) {
	if ttl < 30 {
		ttl = 30
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]cacheEntry)
	}
	c.cache[fqdn] = cacheEntry{
		ips:        ips,
		validUntil: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// RetreiveIPs returns the glue IP addresses for given FQDN by performing a
// manual recursion.
func (c *Client) RetreiveIPs(ctx context.Context, fqdn string) ([]net.IP, error) {
	ips, ok := c.getCached(fqdn)
	if ok {
		return ips, nil
	}
	var cl dns.Client
	var m dns.Msg
	qname := dns.Fqdn(fqdn)
	m.SetQuestion(qname, dns.TypeA)

	// Start with the root nameservers
	auths := rootServers

	for {
		// Query the nameserver for NS records
		var response *dns.Msg
		var err error
		for _, auth := range auths {
			response, _, err = cl.ExchangeContext(ctx, &m, net.JoinHostPort(auth, "53"))
			if err == nil && response.Rcode == dns.RcodeSuccess {
				break
			}
		}
		if err != nil {
			return nil, err
		}

		var minTTL uint32
		nsEqQname := false
		var newAuths []string
		for _, ans := range response.Ns {
			if ns, ok := ans.(*dns.NS); ok {
				if ns.Header().Name == qname {
					nsEqQname = true
				}
				resolved := false
				for _, extra := range response.Extra {
					if extra.Header().Name != ns.Ns {
						continue
					}
					if a, ok := extra.(*dns.A); ok {
						newAuths = append(newAuths, a.A.String())
						resolved = true
					} else if aaaa, ok := extra.(*dns.AAAA); ok {
						newAuths = append(newAuths, aaaa.AAAA.String())
						resolved = true
					}
					if ttl := extra.Header().Header().Ttl; ttl > minTTL {
						minTTL = ttl
					}
				}
				if !resolved {
					newAuths = append(newAuths, ns.Ns)
				}
			}
		}

		if nsEqQname {
			// We have reached the authoritative nameserver for the FQDN
			auths = newAuths
			newAuths = newAuths[:0]
		}

		if len(newAuths) == 0 {
			// No more NS records to resolve, we are at the parent auth
			glues := make([]net.IP, 0, len(auths))
			for _, glue := range auths {
				if ip := net.ParseIP(glue); ip != nil {
					glues = append(glues, ip)
				}
			}
			c.saveCache(fqdn, glues, minTTL)
			return glues, nil
		}

		auths = newAuths
	}
}
