package dns01

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

type IPsChallenger struct {
	GetIPs func(context.Context, string) ([]net.IP, error)
}

func (c IPsChallenger) Challenge(ctx context.Context, fqdn string) ([]string, error) {
	var cl dns.Client
	cl.Timeout = 5 * time.Second
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
			var m dns.Msg
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = false
			r, _, err := cl.ExchangeContext(ctx, &m, net.JoinHostPort(ip.String(), "53"))
			if err != nil {
				ch <- response{err: err}
				return
			}
			var values []string
			for _, ans := range r.Answer {
				if txt, ok := ans.(*dns.TXT); ok {
					values = append(values, txt.Txt...)
				}
			}
			ch <- response{challenges: values}
		}(ip)
	}

	var challenges []string
	var errs []error
	for range ips {
		select {
		case <-ctx.Done():
			break
		case r := <-ch:
			if r.err != nil {
				errs = append(errs, r.err)
				continue
			}
			challenges = append(challenges, r.challenges...)
		}
	}
	if len(challenges) == 0 {
		return nil, errors.Join(errs...)
	}
	return challenges, nil
}
