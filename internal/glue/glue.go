package glue

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

var rootServers = func() []string {
	var servers []string
	for i := 0; i < 13; i++ {
		servers = append(servers, string([]byte{'a' + byte(i)})+".root-servers.net")
	}
	return servers
}()

// RetreiveIPs returns the glue IP addresses for given FQDN by performing a
// manual recursion.
func RetreiveIPs(ctx context.Context, fqdn string) ([]net.IP, error) {
	var cl dns.Client
	var m dns.Msg
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)

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

		var newAuths []string
		for _, ans := range response.Ns {
			if ns, ok := ans.(*dns.NS); ok {
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
				}
				if !resolved {
					newAuths = append(newAuths, ns.Ns)
				}
			}
		}

		if len(newAuths) == 0 {
			// No more NS records to resolve, we are at the parent auth
			glues := make([]net.IP, 0, len(auths))
			for _, glue := range auths {
				if ip := net.ParseIP(glue); ip != nil {
					glues = append(glues, ip)
				}
			}
			return glues, nil
		}

		auths = newAuths
	}
}
