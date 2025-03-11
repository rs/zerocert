package dns01

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

type IPsChallenger struct {
	GetIPs func(context.Context, string) ([]net.IP, error)
}

func (c IPsChallenger) Challenge(ctx context.Context, fqdn string) ([]string, error) {
	var cl dns.Client
	var m dns.Msg
	ips, err := c.GetIPs(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	type response struct {
		challenges []string
		err        error
	}
	ch := make(chan response, len(ips))
	for _, ip := range ips {
		go func(ip net.IP) {
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = false
			r, _, err := cl.ExchangeContext(ctx, &m, net.JoinHostPort(ip.String(), "53"))
			if err != nil {
				ch <- response{err: err}
				return
			}
			ch <- response{challenges: r.Answer[0].(*dns.TXT).Txt}
		}(ip)
	}

	var challenges []string
	var errs []error
	for i := 0; i < len(ips); i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		challenges = append(challenges, r.challenges...)
	}
	if len(challenges) == 0 {
		return nil, errors.Join(errs...)
	}
	return challenges, nil
}
