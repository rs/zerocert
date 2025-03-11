package dns01

import (
	"context"
	"sync"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

type MemoryProvider struct {
	mu         sync.RWMutex
	challenges map[string][]string
}

func (p *MemoryProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.challenges == nil {
		p.challenges = map[string][]string{}
	}
	p.challenges[fqdn] = append(p.challenges[fqdn], value)
	return nil
}

func (p *MemoryProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.challenges[fqdn]
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] == value {
			values = append(values[:i], values[i+1:]...)
		}
	}
	if len(values) > 0 {
		p.challenges[fqdn] = values
	} else {
		delete(p.challenges, fqdn)
	}
	return nil
}

func (p *MemoryProvider) Challenge(ctx context.Context, fqdn string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.challenges[fqdn], nil
}
