package dns01

import (
	"context"
	"log"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Challenger interface {
	Challenge(ctx context.Context, fqdn string) ([]string, error)
}

type Server []Challenger

// ServeDNS handles a msg DNS query and writes a DNS response to wbuf (if large
// enough) if the query is a DNS-01 challenge query and returns the size of the
// response. If the query is not a DNS-01 challenge, it returns 0.
func (s Server) ServeDNS(msg, wbuf []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return wbuf[:0]
	}
	if h.Response {
		return wbuf[:0]
	}
	q, err := p.Question()
	if err != nil {
		return wbuf[:0]
	}
	if q.Type != dnsmessage.TypeTXT {
		return wbuf[:0]
	}
	fqdn := q.Name.String()

	w := dnsmessage.NewBuilder(wbuf, dnsmessage.Header{
		ID:               h.ID,
		Response:         true,
		Authoritative:    true,
		CheckingDisabled: h.CheckingDisabled,
		RecursionDesired: h.RecursionDesired,
		RCode:            dnsmessage.RCodeSuccess,
	})
	w.EnableCompression()

	if err := w.StartQuestions(); err != nil {
		return wbuf[:0]
	}
	if err := w.Question(q); err != nil {
		return wbuf[:0]
	}
	if err := w.StartAnswers(); err != nil {
		return wbuf[:0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if challenges, found := s.Challenges(ctx, fqdn); found {
		for _, c := range challenges {
			if err := w.TXTResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeTXT,
				Class:  dnsmessage.ClassINET,
				TTL:    120,
				Length: uint16(len(c)),
			}, dnsmessage.TXTResource{
				TXT: []string{c},
			}); err != nil {
				return wbuf[:0]
			}
		}
	}

	wbuf, _ = w.Finish()
	return wbuf
}

func (s Server) Challenges(ctx context.Context, fqdn string) (challenges []string, found bool) {
	for _, c := range s {
		cls, err := c.Challenge(ctx, fqdn)
		if err != nil {
			log.Printf("DNS-01 %T challenge: %v", cls, err)
			continue
		}
		challenges = append(challenges, cls...)
		found = true
	}
	return challenges, found
}
