package lib

import (
	"crypto/rsa"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOIDCAllowedWorkspaceIDs_Wildcard(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "*")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Nil(t, result, "wildcard '*' should return nil (allow all)")
}

func TestGetOIDCAllowedWorkspaceIDs_WildcardWithWhitespace(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "  *  ")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Nil(t, result, "wildcard ' * ' with whitespace should return nil (allow all)")
}

func TestGetOIDCAllowedWorkspaceIDs_CommaSeparated(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc,ws-def")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Equal(t, []string{"ws-abc", "ws-def"}, result)
}

func TestGetOIDCAllowedWorkspaceIDs_Empty(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Nil(t, result, "empty string should return nil")
}

func TestGetOIDCAllowedWorkspaceIDs_Unset(t *testing.T) {
	os.Unsetenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Nil(t, result, "unset env should return nil")
}

func TestGetOIDCAllowedWorkspaceIDs_WildcardIsNotSpecialInList(t *testing.T) {
	// A "*" mixed with other values is NOT treated as a wildcard;
	// it is treated as a literal workspace ID entry.
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc,*,ws-def")
	result := mustAllowlist(t, "VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	assert.Equal(t, []string{"ws-abc", "*", "ws-def"}, result)
}

func TestGetAuthMode_Defaults(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetAuthMode_OIDCModal(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	assert.Equal(t, AuthModeOIDCModal, GetAuthMode())
}

func TestGetAuthMode_OIDCModalCaseInsensitive(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "OIDC-MODAL")
	assert.Equal(t, AuthModeOIDCModal, GetAuthMode())
}

func TestGetAuthMode_UnknownFallsBackToPassword(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "bogus")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetAuthMode_PlainOIDCFallsBackToPassword(t *testing.T) {
	// "oidc" alone is not a valid mode; must be "oidc-modal".
	t.Setenv("VPROX_AUTH_MODE", "oidc")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetOIDCIssuerURL_Default(t *testing.T) {
	t.Setenv("VPROX_OIDC_ISSUER", "")
	assert.Equal(t, "https://oidc.modal.com", GetOIDCIssuerURL())
}

func TestGetOIDCIssuerURL_Custom(t *testing.T) {
	t.Setenv("VPROX_OIDC_ISSUER", "https://custom.issuer.example.com")
	assert.Equal(t, "https://custom.issuer.example.com", GetOIDCIssuerURL())
}

func TestGetOIDCToken_Set(t *testing.T) {
	t.Setenv("VPROX_OIDC_TOKEN", "eyJhbGciOiJSUzI1NiJ9.test.sig")
	token, err := GetOIDCToken()
	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.test.sig", token)
}

func TestGetOIDCToken_Unset(t *testing.T) {
	os.Unsetenv("VPROX_OIDC_TOKEN")
	_, err := GetOIDCToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VPROX_OIDC_TOKEN")
}

func TestGetClientToken_Password(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "password")
	t.Setenv("VPROX_PASSWORD", "s3cret")
	token, err := GetClientToken()
	assert.NoError(t, err)
	assert.Equal(t, "s3cret", token)
}

func TestGetClientToken_OIDCModal(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	t.Setenv("VPROX_OIDC_TOKEN", "eyJhbGciOiJSUzI1NiJ9.test.sig")
	token, err := GetClientToken()
	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.test.sig", token)
}

func TestGetClientToken_OIDCModal_MissingToken(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	os.Unsetenv("VPROX_OIDC_TOKEN")
	_, err := GetClientToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VPROX_OIDC_TOKEN")
}

// Every identity claim allowlist is read from its own environment variable and
// threaded into the authenticator, so a misnamed or unwired variable would
// silently leave the claim unchecked.
func TestGetAuthenticator_IdentityClaimAllowlists(t *testing.T) {
	priv := testKeyPair(t)
	_, issuer := serveJWKS(t, map[string]*rsa.PublicKey{"test-key-1": &priv.PublicKey})

	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	t.Setenv("VPROX_OIDC_ISSUER", issuer)
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc123")

	for _, tc := range []struct {
		envVar string
		claim  string
		mutate func(c *ModalClaims)
	}{
		{"VPROX_OIDC_ALLOWED_ENVIRONMENT_IDS", "environment_id", func(c *ModalClaims) { c.EnvironmentID = "env-other" }},
		{"VPROX_OIDC_ALLOWED_ENVIRONMENT_NAMES", "environment_name", func(c *ModalClaims) { c.EnvironmentName = "other" }},
		{"VPROX_OIDC_ALLOWED_APP_IDS", "app_id", func(c *ModalClaims) { c.AppID = "app-other" }},
		{"VPROX_OIDC_ALLOWED_APP_NAMES", "app_name", func(c *ModalClaims) { c.AppName = "other" }},
		{"VPROX_OIDC_ALLOWED_FUNCTION_IDS", "function_id", func(c *ModalClaims) { c.FunctionID = "fn-other" }},
		{"VPROX_OIDC_ALLOWED_FUNCTION_NAMES", "function_name", func(c *ModalClaims) { c.FunctionName = "other" }},
	} {
		t.Run(tc.envVar, func(t *testing.T) {
			claims := defaultClaims(issuer)
			allowed := map[string]string{
				"environment_id":   claims.EnvironmentID,
				"environment_name": claims.EnvironmentName,
				"app_id":           claims.AppID,
				"app_name":         claims.AppName,
				"function_id":      claims.FunctionID,
				"function_name":    claims.FunctionName,
			}[tc.claim]
			t.Setenv(tc.envVar, "unrelated, "+allowed)

			auth, err := GetAuthenticator()
			require.NoError(t, err)
			assert.NoError(t, authenticateClaims(t, auth, claims, priv))

			tc.mutate(&claims)
			assert.ErrorContains(t, authenticateClaims(t, auth, claims, priv), tc.claim)
		})
	}
}

// A name allowlist configured without a workspace allowlist must stop the
// server at startup instead of admitting same-named workloads from any
// workspace.
func TestGetAuthenticator_NameAllowlistWithoutWorkspaceFails(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	t.Setenv("VPROX_OIDC_ISSUER", "http://127.0.0.1:1")
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "*")
	t.Setenv("VPROX_OIDC_ALLOWED_APP_NAMES", "murmur-vms")

	_, err := GetAuthenticator()
	assert.ErrorContains(t, err, "workspace_id")
}

// mustAllowlist reads a well-formed allowlist variable.
func mustAllowlist(t *testing.T, envVar string) []string {
	t.Helper()
	list, err := GetOIDCAllowlist(envVar)
	require.NoError(t, err)
	return list
}

func TestGetOIDCAllowlist(t *testing.T) {
	t.Setenv("VPROX_TEST_ALLOWLIST", " a, b ,,c ")
	assert.Equal(t, []string{"a", "b", "c"}, mustAllowlist(t, "VPROX_TEST_ALLOWLIST"))
	t.Setenv("VPROX_TEST_ALLOWLIST", " * ")
	assert.Nil(t, mustAllowlist(t, "VPROX_TEST_ALLOWLIST"))
	t.Setenv("VPROX_TEST_ALLOWLIST", "")
	assert.Nil(t, mustAllowlist(t, "VPROX_TEST_ALLOWLIST"))
}

// A set allowlist that parses to no entries is a typo, not a request to leave
// the claim unchecked; treating it as unchecked would silently admit every
// workload the other restrictions allow.
func TestGetOIDCAllowlist_RejectsSettingWithNoEntries(t *testing.T) {
	for _, raw := range []string{" ", " , , ", ","} {
		t.Setenv("VPROX_TEST_ALLOWLIST", raw)
		_, err := GetOIDCAllowlist("VPROX_TEST_ALLOWLIST")
		assert.ErrorContains(t, err, "VPROX_TEST_ALLOWLIST", "value %q", raw)
	}
}

// Every OIDC allowlist variable, including the workspace list, must stop the
// server at startup when it parses to no entries.
func TestGetAuthenticator_RejectsAllowlistWithNoEntries(t *testing.T) {
	for _, envVar := range []string{
		"VPROX_OIDC_ALLOWED_WORKSPACE_IDS",
		"VPROX_OIDC_ALLOWED_ENVIRONMENT_IDS",
		"VPROX_OIDC_ALLOWED_ENVIRONMENT_NAMES",
		"VPROX_OIDC_ALLOWED_APP_IDS",
		"VPROX_OIDC_ALLOWED_APP_NAMES",
		"VPROX_OIDC_ALLOWED_FUNCTION_IDS",
		"VPROX_OIDC_ALLOWED_FUNCTION_NAMES",
	} {
		t.Run(envVar, func(t *testing.T) {
			t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
			t.Setenv("VPROX_OIDC_ISSUER", "http://127.0.0.1:1")
			t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc123")
			t.Setenv(envVar, " , , ")

			_, err := GetAuthenticator()
			require.Error(t, err)
			assert.Contains(t, err.Error(), envVar)
			assert.Contains(t, err.Error(), "no entries")
		})
	}
}
