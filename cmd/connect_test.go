package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Cobra's required-flag check accepts --server-name="", which would otherwise
// reach TLS configuration with nothing to verify the server against. The
// command must return a configuration error before setting up any resources.
func TestConnect_RejectsEmptyServerName(t *testing.T) {
	for _, value := range []string{"", "  "} {
		ConnectCmd.SetArgs([]string{"1.2.3.4", "--server-name=" + value, "--interface", "vprox-test0"})
		ConnectCmd.SilenceUsage = true
		assert.EqualError(t, ConnectCmd.Execute(), "--server-name must be the hostname the server's TLS certificate is valid for", "--server-name=%q", value)
	}
}
