package lib

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

func GetVproxPassword() (string, error) {
	password := os.Getenv("VPROX_PASSWORD")
	if password == "" {
		return "", errors.New("VPROX_PASSWORD environment variable is not set")
	}
	return password, nil
}

// GetAuthMode returns the configured auth mode from the VPROX_AUTH_MODE
// environment variable. Defaults to "password" if not set.
func GetAuthMode() AuthMode {
	mode := os.Getenv("VPROX_AUTH_MODE")
	switch strings.ToLower(mode) {
	case "oidc-modal":
		return AuthModeOIDCModal
	case "password", "":
		return AuthModePassword
	default:
		// Fall back to password mode for unknown values.
		return AuthModePassword
	}
}

// GetOIDCIssuerURL returns the OIDC issuer URL from the VPROX_OIDC_ISSUER
// environment variable. Defaults to "https://oidc.modal.com" if not set.
// Useful for testing Modal OIDC endpoints other than default.
func GetOIDCIssuerURL() string {
	issuer := os.Getenv("VPROX_OIDC_ISSUER")
	if issuer == "" {
		return "https://oidc.modal.com"
	}
	return issuer
}

// GetOIDCAudience returns the expected OIDC audience from the
// VPROX_OIDC_AUDIENCE environment variable. If empty, audience is not checked.
func GetOIDCAudience() string {
	return os.Getenv("VPROX_OIDC_AUDIENCE")
}

// GetOIDCAllowlist returns the comma-separated allowlist in the named
// environment variable. Unset or empty leaves the claim unchecked (returns
// nil), and "*" explicitly allows all values (returns nil) with a warning
// logged at startup. Any other value must contain at least one entry: a
// setting such as " , " is a mistake, and treating it as unchecked would
// silently lift the restriction the operator meant to impose.
func GetOIDCAllowlist(envVar string) ([]string, error) {
	raw := os.Getenv(envVar)
	switch {
	case raw == "":
		return nil, nil
	case strings.TrimSpace(raw) == "*":
		log.Printf("WARNING: %s is set to '*', allowing ALL values. This should only be used for testing!", envVar)
		return nil, nil
	}
	list := splitCSV(raw)
	if len(list) == 0 {
		return nil, fmt.Errorf("%s is set to %q, which contains no entries; unset it to leave the claim unchecked or set it to '*' to allow all values", envVar, raw)
	}
	return list, nil
}

// GetOIDCConfig reads the OIDC configuration from environment variables.
func GetOIDCConfig() (*OIDCConfig, error) {
	config := &OIDCConfig{IssuerURL: GetOIDCIssuerURL(), Audience: GetOIDCAudience()}
	var errs []error
	for _, allowlist := range []struct {
		envVar string
		dst    *[]string
	}{
		{"VPROX_OIDC_ALLOWED_WORKSPACE_IDS", &config.AllowedWorkspaceIDs},
		{"VPROX_OIDC_ALLOWED_ENVIRONMENT_IDS", &config.AllowedEnvironmentIDs},
		{"VPROX_OIDC_ALLOWED_ENVIRONMENT_NAMES", &config.AllowedEnvironmentNames},
		{"VPROX_OIDC_ALLOWED_APP_IDS", &config.AllowedAppIDs},
		{"VPROX_OIDC_ALLOWED_APP_NAMES", &config.AllowedAppNames},
		{"VPROX_OIDC_ALLOWED_FUNCTION_IDS", &config.AllowedFunctionIDs},
		{"VPROX_OIDC_ALLOWED_FUNCTION_NAMES", &config.AllowedFunctionNames},
	} {
		list, err := GetOIDCAllowlist(allowlist.envVar)
		*allowlist.dst = list
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return config, nil
}

// GetOIDCToken returns the OIDC identity token from the VPROX_OIDC_TOKEN
// environment variable.
func GetOIDCToken() (string, error) {
	token := os.Getenv("VPROX_OIDC_TOKEN")
	if token == "" {
		return "", errors.New("VPROX_OIDC_TOKEN environment variable is not set")
	}
	return token, nil
}

// GetAuthenticator creates the appropriate Authenticator based on environment
// configuration. This is used by the server.
func GetAuthenticator() (*Authenticator, error) {
	mode := GetAuthMode()

	switch mode {
	case AuthModeOIDCModal:
		config, err := GetOIDCConfig()
		if err != nil {
			return nil, err
		}
		auth, err := NewOIDCModalAuthenticator(config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC authenticator: %v", err)
		}
		return auth, nil

	case AuthModePassword:
		password, err := GetVproxPassword()
		if err != nil {
			return nil, err
		}
		return NewPasswordAuthenticator(password), nil

	default:
		return nil, fmt.Errorf("unknown auth mode: %s", mode)
	}
}

// GetClientToken returns the bearer token the client should send to the server,
// based on the current auth mode.
func GetClientToken() (string, error) {
	mode := GetAuthMode()

	switch mode {
	case AuthModeOIDCModal:
		return GetOIDCToken()
	case AuthModePassword:
		return GetVproxPassword()
	default:
		return "", fmt.Errorf("unknown auth mode: %s", mode)
	}
}

// splitCSV splits a comma-separated string into a slice, trimming whitespace
// and filtering out empty strings.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
