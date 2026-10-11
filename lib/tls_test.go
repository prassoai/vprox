package lib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testCA is a certificate authority that issues leaf certificates for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vprox test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{cert, key}
}

func (ca testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// issue returns PEM-encoded certificate and key for a leaf valid for dnsName.
func (ca testCA) issue(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func tlsCertificate(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

// gateway is a fake control server that records the bearer tokens it receives.
type gateway struct {
	addr   string
	tokens chan string
}

func startGateway(t *testing.T, cfg *tls.Config) gateway {
	t.Helper()
	gw := gateway{tokens: make(chan string, 1)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gw.tokens <- r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(connectResponse{AssignedAddr: "240.1.0.2/16", ServerListenPort: 50227})
	}))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	gw.addr = ln.Addr().String()
	return gw
}

// connectClient returns a Client that dials gw by IPv4 address, as the vprox
// CLI does, verifying the server with tlsConfig.
func connectClient(t *testing.T, gw gateway, tlsConfig *tls.Config) *Client {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return &Client{
		Key:      key,
		ServerIp: netip.MustParseAddr("127.0.0.1"),
		Token:    "secret-token",
		Http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, gw.addr)
				},
			},
		},
	}
}

// clientTLSConfigTrusting is the production client configuration with the
// test CA standing in for the system trust store.
func clientTLSConfigTrusting(ca testCA, serverName string) *tls.Config {
	cfg := ClientTLSConfig(serverName)
	cfg.RootCAs = ca.pool()
	return cfg
}

func assertNoTokenSent(t *testing.T, gw gateway) {
	t.Helper()
	select {
	case token := <-gw.tokens:
		t.Fatalf("impostor gateway received bearer token %q", token)
	default:
	}
}

// An impostor gateway with a self-signed certificate must be rejected during
// the TLS handshake, before the client sends its bearer token or accepts a
// WireGuard key from it. This uses the unmodified client configuration, so
// the impostor is checked against the real system trust store.
func TestClientTLS_RejectsUntrustedGatewayBeforeSendingToken(t *testing.T) {
	certPEM, keyPEM := newTestCA(t).issue(t, "vprox.test")
	gw := startGateway(t, &tls.Config{Certificates: []tls.Certificate{tlsCertificate(t, certPEM, keyPEM)}})

	_, err := connectClient(t, gw, ClientTLSConfig("vprox.test")).sendConnectionRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
	assertNoTokenSent(t, gw)
}

// A certificate issued by a trusted CA for a different hostname must not
// authenticate the gateway: a trusted certificate for any domain the attacker
// controls would otherwise let them impersonate ours.
func TestClientTLS_RejectsTrustedCertificateForOtherHostname(t *testing.T) {
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, "attacker.test")
	gw := startGateway(t, &tls.Config{Certificates: []tls.Certificate{tlsCertificate(t, certPEM, keyPEM)}})

	_, err := connectClient(t, gw, clientTLSConfigTrusting(ca, "vprox.test")).sendConnectionRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vprox.test")
	assertNoTokenSent(t, gw)
}

// The client dials the gateway by IPv4 address but verifies the certificate
// against the configured hostname, so a gateway with a certificate for that
// name receives the token and its tunnel configuration is accepted.
func TestClientTLS_AcceptsGatewayCertificateForServerNameWhenDialingIP(t *testing.T) {
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, "vprox.test")
	gw := startGateway(t, &tls.Config{Certificates: []tls.Certificate{tlsCertificate(t, certPEM, keyPEM)}})

	resp, err := connectClient(t, gw, clientTLSConfigTrusting(ca, "vprox.test")).sendConnectionRequest()
	require.NoError(t, err)
	assert.Equal(t, "240.1.0.2/16", resp.AssignedAddr)
	assert.Equal(t, "Bearer secret-token", <-gw.tokens)
}

// A client without a server name has nothing to verify the gateway against;
// that is a programming error, not a configuration to tolerate.
func TestClientTLSConfig_RequiresServerName(t *testing.T) {
	assert.Panics(t, func() { ClientTLSConfig("") })
}

// writeKeyPair writes PEM files and advances their modification time, so that
// successive writes within the filesystem's timestamp granularity still count
// as changes.
func writeKeyPair(t *testing.T, dir string, certPEM, keyPEM []byte, modTime time.Time) (certPath, keyPath string) {
	t.Helper()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, data := range map[string][]byte{certPath: certPEM, keyPath: keyPEM} {
		if data == nil {
			continue
		}
		require.NoError(t, os.WriteFile(path, data, 0o600))
		require.NoError(t, os.Chtimes(path, modTime, modTime))
	}
	return certPath, keyPath
}

// servedSerial returns the serial number of the leaf certificate the gateway
// presents to a client that trusts ca.
func servedSerial(t *testing.T, gw gateway, ca testCA) *big.Int {
	t.Helper()
	conn, err := tls.Dial("tcp", gw.addr, clientTLSConfigTrusting(ca, "vprox.test"))
	require.NoError(t, err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber
}

func serialOf(t *testing.T, certPEM []byte) *big.Int {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert.SerialNumber
}

// The gateway serves the certificate chain from the configured files, and
// picks up a renewed certificate on the next handshake without a restart, so
// that infrastructure-managed renewal never lets the certificate expire.
func TestServerTLSConfig_ServesAndReloadsRenewedCertificate(t *testing.T) {
	ca, dir, now := newTestCA(t), t.TempDir(), time.Now()
	certPEM, keyPEM := ca.issue(t, "vprox.test")
	cfg, err := ServerTLSConfig(writeKeyPair(t, dir, certPEM, keyPEM, now))
	require.NoError(t, err)
	gw := startGateway(t, cfg)
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, gw, ca))

	renewedCert, renewedKey := ca.issue(t, "vprox.test")
	writeKeyPair(t, dir, renewedCert, renewedKey, now.Add(time.Minute))
	assert.Equal(t, serialOf(t, renewedCert), servedSerial(t, gw, ca))
}

// Renewal can preserve file metadata, e.g. copying with preserved timestamps
// over files whose renewed contents happen to be the same size. The gateway
// must still notice the new contents rather than serve the old certificate
// until it expires.
func TestServerTLSConfig_ReloadsRenewalWithUnchangedMetadata(t *testing.T) {
	ca, dir, now := newTestCA(t), t.TempDir(), time.Now()
	certPEM, keyPEM := ca.issue(t, "vprox.test")
	cfg, err := ServerTLSConfig(writeKeyPair(t, dir, certPEM, keyPEM, now))
	require.NoError(t, err)
	gw := startGateway(t, cfg)

	renewedCert, renewedKey := ca.issue(t, "vprox.test")
	for len(renewedCert) != len(certPEM) || len(renewedKey) != len(keyPEM) {
		renewedCert, renewedKey = ca.issue(t, "vprox.test")
	}
	writeKeyPair(t, dir, renewedCert, renewedKey, now)
	assert.Equal(t, serialOf(t, renewedCert), servedSerial(t, gw, ca))
}

// Renewal tools may replace the certificate before the key. While the files
// hold a mismatched pair, the gateway keeps serving the last good certificate
// instead of failing handshakes, and switches once the key catches up.
func TestServerTLSConfig_KeepsServingDuringPartialRenewal(t *testing.T) {
	ca, dir, now := newTestCA(t), t.TempDir(), time.Now()
	certPEM, keyPEM := ca.issue(t, "vprox.test")
	cfg, err := ServerTLSConfig(writeKeyPair(t, dir, certPEM, keyPEM, now))
	require.NoError(t, err)
	gw := startGateway(t, cfg)

	renewedCert, renewedKey := ca.issue(t, "vprox.test")
	writeKeyPair(t, dir, renewedCert, nil, now.Add(time.Minute))
	assert.Equal(t, serialOf(t, certPEM), servedSerial(t, gw, ca))

	writeKeyPair(t, dir, nil, renewedKey, now.Add(2*time.Minute))
	assert.Equal(t, serialOf(t, renewedCert), servedSerial(t, gw, ca))
}

// A gateway whose certificate cannot be loaded must fail at startup rather
// than accept connections it can never complete.
func TestServerTLSConfig_FailsFastOnBadFiles(t *testing.T) {
	ca, dir := newTestCA(t), t.TempDir()
	certPEM, _ := ca.issue(t, "vprox.test")
	_, otherKey := ca.issue(t, "vprox.test")

	_, err := ServerTLSConfig(filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing-key.pem"))
	assert.Error(t, err)

	_, err = ServerTLSConfig(writeKeyPair(t, dir, certPEM, otherKey, time.Now()))
	assert.ErrorContains(t, err, "failed to load TLS certificate")
}
