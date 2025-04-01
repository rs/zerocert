package zerocert

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerocert/internal/tlsutil"
)

type tlsListener struct {
	net.Listener
	m *Manager

	initOnce sync.Once
	c        chan connRes
}

type connRes struct {
	conn net.Conn
	err  error
}

func (l *tlsListener) Accept() (net.Conn, error) {
	l.initOnce.Do(l.init)
	res := <-l.c
	return res.conn, res.err
}

func (l *tlsListener) init() {
	l.c = make(chan connRes)
	go l.acceptLoop()
}

func (l *tlsListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.c <- connRes{nil, err}
			return
		}
		tc := tls.Server(c, l.m.serverTLSConfig)
		go l.handleConn(tc)
	}
}

func (l *tlsListener) handleConn(tc *tls.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in handleConn: %v\n%s", r, debug.Stack())
			tc.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tc.HandshakeContext(ctx); err != nil {
		// Let upstream handle the handshake error.
		l.c <- connRes{tc, nil}
		return
	}

	state := tc.ConnectionState()
	if state.ServerName != mTLSDomain || state.NegotiatedProtocol != tlsProto {
		// Non-mTLS and non-zerocert proto connection are sent upstream.
		l.c <- connRes{tc, nil}
		return
	}

	defer tc.Close()

	// Ensure the client certificate is valid and signed by the private CA.
	if err := tlsutil.ValidateClientCertFromTLS(state, l.m.caCert); err != nil {
		log.Printf("cert request: client auth failed: %v", err)
		return
	}

	// Send cert/key pair encoded as PEM
	if cert := l.m.GetCertificate(); cert == nil {
		log.Println("cert request: no certificate")
		return
	}

	b, err := tlsutil.EncodeKeyPair(l.m.GetCertificate())
	if err != nil {
		log.Printf("cert request: encoding: %v", err)
		return
	}

	if _, err = tc.Write(b); err != nil {
		log.Printf("cert request: write: %v", err)
	}
}
