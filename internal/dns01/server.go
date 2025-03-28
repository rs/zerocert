package dns01

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type Challenger interface {
	Challenge(ctx context.Context, fqdn string) ([]string, error)
}

type Server struct {
	Zone                  string
	GetNSIPs              func(ctx context.Context, fqdn string) ([]net.IP, error)
	DistributedChallenger Challenger
	LocalChallenger       Challenger
}

// ServeDNS handles a msg DNS query and writes a DNS response to w if the query
// is a DNS-01 challenge query and returns true. If the query is not a DNS-01
// challenge, it returns false.
func (s Server) ServeDNS(msg []byte, w io.Writer) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return false
	}
	if h.Response {
		return false
	}
	q, err := p.Question()
	if err != nil {
		return false
	}
	fqdn := strings.ToLower(q.Name.String())
	if q.Type == dnsmessage.TypeSOA && dns.Fqdn(s.Zone) == dns.Fqdn(q.Name.String()) {
		writeSOA(w, h, q)
		return true
	}
	if !strings.HasPrefix(fqdn, "_acme-challenge.") && !strings.HasPrefix(fqdn, "_local_acme-challenge.") {
		return false
	}

	go s.handleChanlenge(h, q, w)
	return true
}

func (s Server) handleChanlenge(h dnsmessage.Header, q dnsmessage.Question, w io.Writer) {
	fqdn := strings.ToLower(q.Name.String())
	challenge := fqdn
	var c Challenger
	if strings.HasPrefix(fqdn, "_acme-challenge.") {
		c = s.DistributedChallenger
		challenge = "_local" + challenge
	} else if strings.HasPrefix(fqdn, "_local_acme-challenge.") {
		c = s.LocalChallenger
		challenge = strings.TrimPrefix(challenge, "_local")
	} else {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var challenges []string
	if q.Type == dnsmessage.TypeTXT && c != nil {
		var err error
		if challenges, err = c.Challenge(ctx, challenge); err != nil {
			log.Printf("Error getting challenges for %s: %v", fqdn, err)
		}
	}
	log.Printf("DNS-01 %s %s: %v", strings.TrimPrefix(q.Type.String(), "Type"), fqdn, challenges)

	rcode := dnsmessage.RCodeNameError
	if len(challenges) > 0 {
		rcode = dnsmessage.RCodeSuccess
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               h.ID,
		Response:         true,
		Authoritative:    true,
		CheckingDisabled: h.CheckingDisabled,
		RecursionDesired: h.RecursionDesired,
		RCode:            rcode,
	})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return
	}
	if err := b.Question(q); err != nil {
		return
	}
	if err := b.StartAnswers(); err != nil {
		return
	}

	for _, txt := range challenges {
		_ = b.TXTResource(dnsmessage.ResourceHeader{
			Name:   q.Name,
			Type:   dnsmessage.TypeTXT,
			Class:  dnsmessage.ClassINET,
			TTL:    60,
			Length: uint16(len(txt)),
		}, dnsmessage.TXTResource{
			TXT: []string{txt},
		})
	}

	wbuf, err := b.Finish()
	if err != nil {
		return
	}
	if _, err := w.Write(wbuf); err != nil {
		return
	}
}

func writeSOA(w io.Writer, h dnsmessage.Header, q dnsmessage.Question) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               h.ID,
		Response:         true,
		Authoritative:    true,
		CheckingDisabled: h.CheckingDisabled,
		RecursionDesired: h.RecursionDesired,
		RCode:            dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return
	}
	if err := b.Question(q); err != nil {
		return
	}
	if err := b.StartAnswers(); err != nil {
		return
	}

	nsName, err := dnsmessage.NewName("ns." + q.Name.String())
	if err != nil {
		return
	}
	if err := b.SOAResource(dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  dnsmessage.TypeSOA,
		Class: dnsmessage.ClassINET,
		TTL:   300,
	}, dnsmessage.SOAResource{
		NS:      nsName,
		MBox:    nsName,
		Refresh: 1200,
		Retry:   300,
		Expire:  1209600,
		MinTTL:  300,
	}); err != nil {
		return
	}

	wbuf, err := b.Finish()
	if err != nil {
		return
	}
	if _, err := w.Write(wbuf); err != nil {
		return
	}
}
