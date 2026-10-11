package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

// testKeyPair generates a fresh RSA key pair for testing.
func testKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// b64url encodes bytes as unpadded base64url.
func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// signJWT creates a signed RS256 JWT from the given header, claims, and private key.
func signJWT(t *testing.T, header jwtHeader, claims ModalClaims, key *rsa.PrivateKey) string {
	t.Helper()

	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	payload := b64url(hdrJSON) + "." + b64url(claimsJSON)
	h := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	require.NoError(t, err)

	return payload + "." + b64url(sig)
}

// serveJWKS starts a test HTTP server that serves a JWKS endpoint and an OIDC
// discovery endpoint for the given public keys. Returns the server and the
// issuer URL to use.
func serveJWKS(t *testing.T, keys map[string]*rsa.PublicKey) (*httptest.Server, string) {
	t.Helper()

	jwksKeys := make([]jwkKey, 0, len(keys))
	for kid, pub := range keys {
		jwksKeys = append(jwksKeys, jwkKey{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   b64url(pub.N.Bytes()),
			E:   b64url(big.NewInt(int64(pub.E)).Bytes()),
		})
	}

	jwksResp := jwksResponse{Keys: jwksKeys}
	jwksBytes, err := json.Marshal(jwksResp)
	require.NoError(t, err)

	// We need a mux so we can serve both discovery and JWKS.
	mux := http.NewServeMux()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))

	issuer := srv.URL

	discovery := oidcDiscovery{
		Issuer:  issuer,
		JWKSURI: issuer + "/jwks",
	}
	discoveryBytes, err := json.Marshal(discovery)
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(discoveryBytes)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBytes)
	})

	t.Cleanup(srv.Close)
	return srv, issuer
}

// buildOIDCAuthenticator sets up a full OIDC authenticator backed by a test
// JWKS server. Returns the authenticator, the issuer URL, and the private key.
func buildOIDCAuthenticator(t *testing.T, configFn func(cfg *OIDCConfig)) (*Authenticator, string, *rsa.PrivateKey) {
	t.Helper()

	priv := testKeyPair(t)
	pub := &priv.PublicKey
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"test-key-1": pub})

	cfg := &OIDCConfig{
		IssuerURL: issuer,
	}
	if configFn != nil {
		configFn(cfg)
	}

	auth, err := NewOIDCModalAuthenticator(cfg)
	require.NoError(t, err)
	return auth, issuer, priv
}

func defaultHeader() jwtHeader {
	return jwtHeader{Alg: "RS256", Kid: "test-key-1", Typ: "JWT"}
}

func defaultClaims(issuer string) ModalClaims {
	now := time.Now().Unix()
	return ModalClaims{
		Sub:             "ws-abc123:main:my-app:my-func",
		Aud:             "",
		Exp:             now + 3600,
		Iat:             now,
		Iss:             issuer,
		Jti:             "jti-random",
		WorkspaceID:     "ws-abc123",
		EnvironmentID:   "env-def456",
		EnvironmentName: "main",
		AppID:           "app-ghi789",
		AppName:         "my-app",
		FunctionID:      "fn-jkl012",
		FunctionName:    "my-func",
		ContainerID:     "ctr-mno345",
	}
}

// --- Password auth tests ---

func TestPasswordAuth_Success(t *testing.T) {
	auth := NewPasswordAuthenticator("secret-pass")

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer secret-pass")

	err := auth.Authenticate(req)
	assert.NoError(t, err)
}

func TestPasswordAuth_WrongPassword(t *testing.T) {
	auth := NewPasswordAuthenticator("secret-pass")

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer wrong-pass")

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

func TestPasswordAuth_MissingHeader(t *testing.T) {
	auth := NewPasswordAuthenticator("secret-pass")

	req := httptest.NewRequest("GET", "/connect", nil)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or malformed")
}

func TestPasswordAuth_BasicScheme(t *testing.T) {
	auth := NewPasswordAuthenticator("secret-pass")

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or malformed")
}

func TestPasswordAuth_Mode(t *testing.T) {
	auth := NewPasswordAuthenticator("pw")
	assert.Equal(t, AuthModePassword, auth.Mode())
}

// --- OIDC auth tests ---

func TestOIDCAuth_ValidToken(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	token := signJWT(t, defaultHeader(), defaultClaims(issuer), priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.NoError(t, err)
}

func TestOIDCAuth_ExpiredToken(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims(issuer)
	claims.Exp = time.Now().Unix() - 100 // expired 100 seconds ago

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}

func TestOIDCAuth_FutureIat(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims(issuer)
	claims.Iat = time.Now().Unix() + 3600 // issued 1 hour in the future

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issued in the future")
}

func TestOIDCAuth_WrongIssuer(t *testing.T) {
	auth, _, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims("https://evil.example.com")

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer mismatch")
}

func TestOIDCAuth_AudienceCheck(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.Audience = "my-service"
	})

	// Token without audience should fail.
	claims := defaultClaims(issuer)
	claims.Aud = ""

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")

	// Token with correct audience should succeed.
	claims.Aud = "my-service"
	token = signJWT(t, defaultHeader(), claims, priv)
	req = httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err = auth.Authenticate(req)
	assert.NoError(t, err)

	// Token with wrong audience should fail.
	claims.Aud = "other-service"
	token = signJWT(t, defaultHeader(), claims, priv)
	req = httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err = auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestOIDCAuth_AllowedWorkspaceIDs(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.AllowedWorkspaceIDs = []string{"ws-allowed1", "ws-allowed2"}
	})

	// Allowed workspace.
	claims := defaultClaims(issuer)
	claims.WorkspaceID = "ws-allowed1"
	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	assert.NoError(t, auth.Authenticate(req))

	// Also allowed.
	claims.WorkspaceID = "ws-allowed2"
	token = signJWT(t, defaultHeader(), claims, priv)
	req = httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	assert.NoError(t, auth.Authenticate(req))

	// Disallowed workspace.
	claims.WorkspaceID = "ws-evil"
	token = signJWT(t, defaultHeader(), claims, priv)
	req = httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workspace")
	assert.Contains(t, err.Error(), "not in the allowed list")
}

func TestOIDCAuth_WrongSignature(t *testing.T) {
	auth, issuer, _ := buildOIDCAuthenticator(t, nil)

	// Sign with a different key that the JWKS server doesn't know about.
	otherKey := testKeyPair(t)
	token := signJWT(t, defaultHeader(), defaultClaims(issuer), otherKey)

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestOIDCAuth_UnknownKid(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	header := defaultHeader()
	header.Kid = "unknown-key-id"

	token := signJWT(t, header, defaultClaims(issuer), priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestOIDCAuth_UnsupportedAlgorithm(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	header := defaultHeader()
	header.Alg = "HS256"

	token := signJWT(t, header, defaultClaims(issuer), priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported JWT algorithm")
}

func TestOIDCAuth_MalformedToken(t *testing.T) {
	auth, _, _ := buildOIDCAuthenticator(t, nil)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
		{"four parts", "a.b.c.d"},
		{"garbage", "not-a-jwt-at-all!!!"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/connect", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			err := auth.Authenticate(req)
			assert.Error(t, err)
		})
	}
}

func TestOIDCAuth_MissingHeader(t *testing.T) {
	auth, _, _ := buildOIDCAuthenticator(t, nil)

	req := httptest.NewRequest("GET", "/connect", nil)
	err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or malformed")
}

func TestOIDCAuth_Mode(t *testing.T) {
	auth, _, _ := buildOIDCAuthenticator(t, nil)
	assert.Equal(t, AuthModeOIDCModal, auth.Mode())
}

func TestOIDCAuth_NoAudienceCheck_WhenNotConfigured(t *testing.T) {
	// When audience is empty in config, any audience should be accepted.
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims(issuer)
	claims.Aud = "anything-goes"
	token := signJWT(t, defaultHeader(), claims, priv)

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	assert.NoError(t, auth.Authenticate(req))
}

func TestOIDCAuth_NoWorkspaceCheck_WhenNotConfigured(t *testing.T) {
	// When no workspace IDs are configured, any workspace should be accepted.
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims(issuer)
	claims.WorkspaceID = "ws-any-workspace"
	token := signJWT(t, defaultHeader(), claims, priv)

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	assert.NoError(t, auth.Authenticate(req))
}

func TestOIDCAuth_NoEnvironmentCheck_WhenNotConfigured(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	claims := defaultClaims(issuer)
	claims.EnvironmentName = "any-env"
	token := signJWT(t, defaultHeader(), claims, priv)

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	assert.NoError(t, auth.Authenticate(req))
}

// --- JWK conversion tests ---

func TestJWKToRSAPublicKey(t *testing.T) {
	priv := testKeyPair(t)
	pub := &priv.PublicKey

	jwk := jwkKey{
		Kty: "RSA",
		N:   b64url(pub.N.Bytes()),
		E:   b64url(big.NewInt(int64(pub.E)).Bytes()),
	}

	result, err := jwkToRSAPublicKey(jwk)
	require.NoError(t, err)
	assert.Equal(t, pub.N.Cmp(result.N), 0)
	assert.Equal(t, pub.E, result.E)
}

func TestJWKToRSAPublicKey_BadModulus(t *testing.T) {
	_, err := jwkToRSAPublicKey(jwkKey{
		Kty: "RSA",
		N:   "!!!invalid-base64!!!",
		E:   b64url(big.NewInt(65537).Bytes()),
	})
	assert.Error(t, err)
}

func TestJWKToRSAPublicKey_BadExponent(t *testing.T) {
	priv := testKeyPair(t)
	_, err := jwkToRSAPublicKey(jwkKey{
		Kty: "RSA",
		N:   b64url(priv.PublicKey.N.Bytes()),
		E:   "!!!invalid!!!",
	})
	assert.Error(t, err)
}

// --- JWKS Cache tests ---

func TestJWKSCache_FetchesKeys(t *testing.T) {
	priv := testKeyPair(t)
	pub := &priv.PublicKey
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"k1": pub})

	cache := NewJWKSCache(issuer + "/jwks")
	require.NoError(t, cache.Prefetch())

	// Sign some data and verify.
	msg := []byte("hello, world")
	h := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	require.NoError(t, err)

	err = cache.VerifyRS256("k1", msg, sig)
	assert.NoError(t, err)
}

func TestJWKSCache_UnknownKid(t *testing.T) {
	priv := testKeyPair(t)
	pub := &priv.PublicKey
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"k1": pub})

	cache := NewJWKSCache(issuer + "/jwks")
	require.NoError(t, cache.Prefetch())

	msg := []byte("hello")
	h := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	require.NoError(t, err)

	err = cache.VerifyRS256("nonexistent", msg, sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestJWKSCache_InvalidSignature(t *testing.T) {
	priv := testKeyPair(t)
	pub := &priv.PublicKey
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"k1": pub})

	cache := NewJWKSCache(issuer + "/jwks")
	require.NoError(t, cache.Prefetch())

	err := cache.VerifyRS256("k1", []byte("hello"), []byte("bad-signature"))
	assert.Error(t, err)
}

func TestJWKSCache_MultipleKeys(t *testing.T) {
	priv1 := testKeyPair(t)
	priv2 := testKeyPair(t)

	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{
		"key-a": &priv1.PublicKey,
		"key-b": &priv2.PublicKey,
	})

	cache := NewJWKSCache(issuer + "/jwks")
	require.NoError(t, cache.Prefetch())

	msg := []byte("test message")
	h := sha256.Sum256(msg)

	sig1, err := rsa.SignPKCS1v15(rand.Reader, priv1, crypto.SHA256, h[:])
	require.NoError(t, err)
	sig2, err := rsa.SignPKCS1v15(rand.Reader, priv2, crypto.SHA256, h[:])
	require.NoError(t, err)

	assert.NoError(t, cache.VerifyRS256("key-a", msg, sig1))
	assert.NoError(t, cache.VerifyRS256("key-b", msg, sig2))

	// Cross-verification should fail.
	assert.Error(t, cache.VerifyRS256("key-a", msg, sig2))
	assert.Error(t, cache.VerifyRS256("key-b", msg, sig1))
}

// --- OIDC Discovery tests ---

func TestDiscoverJWKSURL(t *testing.T) {
	expected := "https://oidc.example.com/jwks"
	discovery := oidcDiscovery{
		Issuer:  "https://oidc.example.com",
		JWKSURI: expected,
	}
	body, _ := json.Marshal(discovery)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	url, err := discoverJWKSURL(srv.URL)
	require.NoError(t, err)
	assert.Equal(t, expected, url)
}

func TestDiscoverJWKSURL_MissingJWKSURI(t *testing.T) {
	discovery := oidcDiscovery{Issuer: "https://oidc.example.com"}
	body, _ := json.Marshal(discovery)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	_, err := discoverJWKSURL(srv.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing jwks_uri")
}

func TestDiscoverJWKSURL_ServerDown(t *testing.T) {
	_, err := discoverJWKSURL("http://127.0.0.1:1") // nothing listening
	assert.Error(t, err)
}

// --- NewOIDCModalAuthenticator error cases ---

func TestNewOIDCModalAuthenticator_EmptyIssuer(t *testing.T) {
	_, err := NewOIDCModalAuthenticator(&OIDCConfig{IssuerURL: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer URL is required")
}

func TestNewOIDCModalAuthenticator_BadIssuer(t *testing.T) {
	_, err := NewOIDCModalAuthenticator(&OIDCConfig{IssuerURL: "http://127.0.0.1:1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to discover JWKS")
}

func TestNewOIDCModalAuthenticator_TrailingSlashNormalized(t *testing.T) {
	priv := testKeyPair(t)
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"k": &priv.PublicKey})

	// Pass issuer with trailing slash — it should be trimmed.
	auth, err := NewOIDCModalAuthenticator(&OIDCConfig{IssuerURL: issuer + "/"})
	require.NoError(t, err)

	claims := defaultClaims(issuer) // claims use the issuer without trailing slash
	token := signJWT(t, defaultHeader(), claims, priv)

	// Hack: the JWKS cache was set up via the server, and the kid we use
	// is "test-key-1" in our default header, but the JWKS server above only
	// has kid "k". So use kid "k" here.
	header := jwtHeader{Alg: "RS256", Kid: "k", Typ: "JWT"}
	token = signJWT(t, header, claims, priv)

	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err = auth.Authenticate(req)
	assert.NoError(t, err)
}

// --- Integration-style: full round-trip with all claim checks ---

func TestOIDCAuth_FullClaimValidation(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.Audience = "vprox-server"
		cfg.AllowedWorkspaceIDs = []string{"ws-prod"}
	})

	claims := defaultClaims(issuer)
	claims.Aud = "vprox-server"
	claims.WorkspaceID = "ws-prod"

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("POST", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.NoError(t, err)
}

func TestOIDCAuth_FullClaimValidation_FailEach(t *testing.T) {
	makeAuth := func(t *testing.T) (*Authenticator, string, *rsa.PrivateKey) {
		return buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
			cfg.Audience = "vprox-server"
			cfg.AllowedWorkspaceIDs = []string{"ws-prod"}
		})
	}

	tests := []struct {
		name    string
		mutate  func(c *ModalClaims)
		errPart string
	}{
		{"wrong audience", func(c *ModalClaims) { c.Aud = "other" }, "audience mismatch"},
		{"wrong workspace", func(c *ModalClaims) { c.WorkspaceID = "ws-other" }, "workspace"},
		{"expired", func(c *ModalClaims) { c.Exp = time.Now().Unix() - 10 }, "expired"},
		{"wrong issuer", func(c *ModalClaims) { c.Iss = "https://evil.example.com" }, "issuer mismatch"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth, issuer, priv := makeAuth(t)

			claims := defaultClaims(issuer)
			claims.Aud = "vprox-server"
			claims.WorkspaceID = "ws-prod"
			tc.mutate(&claims)

			token := signJWT(t, defaultHeader(), claims, priv)
			req := httptest.NewRequest("POST", "/connect", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			err := auth.Authenticate(req)
			assert.Error(t, err, "expected error for case: %s", tc.name)
			assert.Contains(t, err.Error(), tc.errPart)
		})
	}
}

// --- splitCSV tests (from env.go) ---

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"a,b,c", []string{"a", "b", "c"}},
		{"  a , b , c  ", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"a,,b", []string{"a", "b"}},
		{",,,", nil},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			result := splitCSV(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// --- Clock skew tolerance ---

func TestOIDCAuth_ClockSkewTolerance(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, nil)

	// Token issued 30 seconds in the future should still be accepted
	// (within the 60-second skew tolerance).
	claims := defaultClaims(issuer)
	claims.Iat = time.Now().Unix() + 30

	token := signJWT(t, defaultHeader(), claims, priv)
	req := httptest.NewRequest("GET", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err := auth.Authenticate(req)
	assert.NoError(t, err)
}

// --- Verify RS256 directly ---

func TestVerifyRS256Signature(t *testing.T) {
	priv := testKeyPair(t)
	msg := []byte("test message for signing")

	h := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	require.NoError(t, err)

	// Correct signature.
	err = verifyRS256Signature(&priv.PublicKey, msg, sig)
	assert.NoError(t, err)

	// Tampered message.
	err = verifyRS256Signature(&priv.PublicKey, []byte("different message"), sig)
	assert.Error(t, err)

	// Tampered signature.
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	err = verifyRS256Signature(&priv.PublicKey, msg, badSig)
	assert.Error(t, err)
}

// --- Modal claims parsing ---

func TestModalClaims_AllFieldsParsed(t *testing.T) {
	raw := `{
		"sub": "ws-123:main:app:fn",
		"aud": "my-aud",
		"exp": 1700000000,
		"iat": 1699999000,
		"iss": "https://oidc.modal.com",
		"jti": "some-jti",
		"workspace_id": "ws-123",
		"environment_id": "env-456",
		"environment_name": "main",
		"app_id": "app-789",
		"app_name": "my-app",
		"function_id": "fn-012",
		"function_name": "my-func",
		"container_id": "ctr-345"
	}`

	var claims ModalClaims
	err := json.Unmarshal([]byte(raw), &claims)
	require.NoError(t, err)

	assert.Equal(t, "ws-123:main:app:fn", claims.Sub)
	assert.Equal(t, "my-aud", claims.Aud)
	assert.Equal(t, int64(1700000000), claims.Exp)
	assert.Equal(t, int64(1699999000), claims.Iat)
	assert.Equal(t, "https://oidc.modal.com", claims.Iss)
	assert.Equal(t, "some-jti", claims.Jti)
	assert.Equal(t, "ws-123", claims.WorkspaceID)
	assert.Equal(t, "env-456", claims.EnvironmentID)
	assert.Equal(t, "main", claims.EnvironmentName)
	assert.Equal(t, "app-789", claims.AppID)
	assert.Equal(t, "my-app", claims.AppName)
	assert.Equal(t, "fn-012", claims.FunctionID)
	assert.Equal(t, "my-func", claims.FunctionName)
	assert.Equal(t, "ctr-345", claims.ContainerID)
}

// --- Edge case: token with extra whitespace in Bearer prefix ---

func TestAuth_BearerPrefixVariants(t *testing.T) {
	auth := NewPasswordAuthenticator("pw")

	// "Bearer  pw" (double space) should fail - we require exact "Bearer " prefix.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer  pw")
	err := auth.Authenticate(req)
	assert.Error(t, err, "double space after Bearer should be treated as part of the token")

	// Lowercase "bearer" should fail.
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "bearer pw")
	err = auth.Authenticate(req)
	assert.Error(t, err, "lowercase bearer should be rejected")
}

// Verify that the JWT we build in tests really has 3 dot-separated parts.
func TestSignJWT_Format(t *testing.T) {
	priv := testKeyPair(t)
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"k": &priv.PublicKey})

	token := signJWT(t, defaultHeader(), defaultClaims(issuer), priv)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3, "JWT should have exactly 3 parts")

	for i, part := range parts {
		assert.NotEmpty(t, part, "JWT part %d should not be empty", i)
	}
}

// --- Identity claim allowlists ---

// authenticateClaims signs claims with priv and runs them through auth.
func authenticateClaims(t *testing.T, auth *Authenticator, claims ModalClaims, priv *rsa.PrivateKey) error {
	t.Helper()
	req := httptest.NewRequest("POST", "/connect", nil)
	req.Header.Set("Authorization", "Bearer "+signJWT(t, defaultHeader(), claims, priv))
	return auth.Authenticate(req)
}

// Each identity claim allowlist must reject a signed token whose claim is
// outside the list, so a gateway can admit one environment/app of a shared
// workspace rather than every workload in it.
func TestOIDCAuth_IdentityClaimAllowlists(t *testing.T) {
	tests := []struct {
		claim     string
		configure func(cfg *OIDCConfig)
		mutate    func(c *ModalClaims)
	}{
		{"environment_id", func(cfg *OIDCConfig) { cfg.AllowedEnvironmentIDs = []string{"env-def456"} }, func(c *ModalClaims) { c.EnvironmentID = "env-other" }},
		{"environment_name", func(cfg *OIDCConfig) { cfg.AllowedEnvironmentNames = []string{"main"} }, func(c *ModalClaims) { c.EnvironmentName = "staging" }},
		{"app_id", func(cfg *OIDCConfig) { cfg.AllowedAppIDs = []string{"app-ghi789"} }, func(c *ModalClaims) { c.AppID = "app-other" }},
		{"app_name", func(cfg *OIDCConfig) { cfg.AllowedAppNames = []string{"my-app"} }, func(c *ModalClaims) { c.AppName = "other-app" }},
		{"function_id", func(cfg *OIDCConfig) { cfg.AllowedFunctionIDs = []string{"fn-jkl012"} }, func(c *ModalClaims) { c.FunctionID = "fn-other" }},
		{"function_name", func(cfg *OIDCConfig) { cfg.AllowedFunctionNames = []string{"my-func"} }, func(c *ModalClaims) { c.FunctionName = "other-func" }},
	}

	for _, tc := range tests {
		t.Run(tc.claim, func(t *testing.T) {
			auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
				cfg.AllowedWorkspaceIDs = []string{"ws-abc123"}
				tc.configure(cfg)
			})

			assert.NoError(t, authenticateClaims(t, auth, defaultClaims(issuer), priv))

			claims := defaultClaims(issuer)
			tc.mutate(&claims)
			err := authenticateClaims(t, auth, claims, priv)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.claim)
		})
	}
}

// A token that omits a restricted claim must be rejected, not treated as a
// wildcard: an empty claim value never matches a configured allowlist.
func TestOIDCAuth_IdentityClaimAllowlist_MissingClaim(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.AllowedWorkspaceIDs = []string{"ws-abc123"}
		cfg.AllowedAppNames = []string{"my-app"}
	})

	claims := defaultClaims(issuer)
	claims.AppName = ""
	err := authenticateClaims(t, auth, claims, priv)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app_name")
}

// Allowlists combine with AND across claims and OR within a claim, so an
// operator can admit several environments while still pinning one app.
func TestOIDCAuth_IdentityClaimAllowlists_Combine(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.AllowedWorkspaceIDs = []string{"ws-abc123"}
		cfg.AllowedEnvironmentNames = []string{"murmur-nonprod", "murmur-prod"}
		cfg.AllowedAppNames = []string{"murmur-vms"}
	})

	for _, env := range []string{"murmur-nonprod", "murmur-prod"} {
		claims := defaultClaims(issuer)
		claims.EnvironmentName = env
		claims.AppName = "murmur-vms"
		assert.NoError(t, authenticateClaims(t, auth, claims, priv), env)
	}

	claims := defaultClaims(issuer)
	claims.EnvironmentName = "murmur-prod"
	claims.AppName = "other-app"
	assert.ErrorContains(t, authenticateClaims(t, auth, claims, priv), "app_name")

	claims = defaultClaims(issuer)
	claims.EnvironmentName = "main"
	claims.AppName = "murmur-vms"
	assert.ErrorContains(t, authenticateClaims(t, auth, claims, priv), "environment_name")
}

// Names are only unique within a workspace, and any Modal user can obtain a
// signed token for an environment, app, or function of any name in their own
// workspace. A name allowlist without a workspace allowlist would therefore
// admit strangers, so construction must fail rather than serve.
func TestNewOIDCModalAuthenticator_NameAllowlistRequiresWorkspace(t *testing.T) {
	for _, tc := range []struct {
		claim string
		cfg   OIDCConfig
	}{
		{"environment_name", OIDCConfig{AllowedEnvironmentNames: []string{"murmur-prod"}}},
		{"app_name", OIDCConfig{AllowedAppNames: []string{"murmur-vms"}}},
		{"function_name", OIDCConfig{AllowedFunctionNames: []string{"f"}}},
	} {
		t.Run(tc.claim, func(t *testing.T) {
			tc.cfg.IssuerURL = "http://127.0.0.1:1"
			_, err := NewOIDCModalAuthenticator(&tc.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.claim)
			assert.Contains(t, err.Error(), "workspace_id")
		})
	}
}

// ID allowlists are globally unique, so they stand on their own without a
// workspace allowlist.
func TestOIDCAuth_IDAllowlistWithoutWorkspace(t *testing.T) {
	auth, issuer, priv := buildOIDCAuthenticator(t, func(cfg *OIDCConfig) {
		cfg.AllowedEnvironmentIDs = []string{"env-def456"}
		cfg.AllowedAppIDs = []string{"app-ghi789"}
	})

	assert.NoError(t, authenticateClaims(t, auth, defaultClaims(issuer), priv))
}

// An empty allowlist entry would match a signed token that omits the claim
// entirely, silently disabling the restriction, so construction must fail.
func TestNewOIDCModalAuthenticator_RejectsEmptyAllowlistEntry(t *testing.T) {
	_, err := NewOIDCModalAuthenticator(&OIDCConfig{
		IssuerURL:           "http://127.0.0.1:1",
		AllowedWorkspaceIDs: []string{"ws-abc123"},
		AllowedAppIDs:       []string{"app-ghi789", ""},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app_id")
	assert.Contains(t, err.Error(), "empty")
}
