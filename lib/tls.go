package lib

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
)

// ClientTLSConfig returns the TLS configuration a client uses for the control
// connection to a server. The server's certificate chain is verified against
// the system trust store and must be valid for serverName, even though the
// client dials the server by IPv4 address. The bearer token and the server's
// WireGuard public key travel over this connection, so it must never be
// unauthenticated.
func ClientTLSConfig(serverName string) *tls.Config {
	if serverName == "" {
		panic("vprox: ClientTLSConfig requires a server name")
	}
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// ServerTLSConfig returns the TLS configuration a server uses for control
// connections, serving the PEM certificate chain and private key at the given
// paths. The files are loaded once up front, so a bad path or mismatched pair
// fails at startup, and then reloaded whenever either file changes, so that
// certificate renewal takes effect without restarting the server.
func ServerTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return &tls.Config{GetCertificate: r.getCertificate, MinVersion: tls.VersionTLS12}, nil
}

// certReloader serves a certificate from files, reloading it when they change.
type certReloader struct {
	certPath, keyPath string

	mu              sync.Mutex
	certPEM, keyPEM []byte
	cert            *tls.Certificate
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := r.reload()
	if err != nil {
		// Renewal tools may replace the certificate and key in two steps, so a
		// transiently mismatched pair is expected; keep serving the last good
		// certificate and retry on the next handshake.
		log.Printf("warning: keeping previous TLS certificate: %v", err)
	}
	return cert, nil
}

// reload loads the certificate if either file's contents changed since the
// last load. Contents rather than metadata are compared because renewal can
// preserve modification times and sizes; the files are small and read only
// on handshakes. It returns the current certificate, which is the previous
// one on error.
func (r *certReloader) reload() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certPEM, err := os.ReadFile(r.certPath)
	if err != nil {
		return r.cert, fmt.Errorf("failed to read TLS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(r.keyPath)
	if err != nil {
		return r.cert, fmt.Errorf("failed to read TLS key: %w", err)
	}
	if r.cert != nil && bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM) {
		return r.cert, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return r.cert, fmt.Errorf("failed to load TLS certificate %s and key %s: %w", r.certPath, r.keyPath, err)
	}
	r.cert, r.certPEM, r.keyPEM = &cert, certPEM, keyPEM
	log.Printf("loaded TLS certificate for %v, valid until %v", cert.Leaf.DNSNames, cert.Leaf.NotAfter)
	return r.cert, nil
}
