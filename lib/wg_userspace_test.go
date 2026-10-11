package lib

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kernels without the WireGuard module, such as Modal VM sandboxes, must
// still get a working tunnel. The userspace device has to register through
// the verified TLS control plane, complete a WireGuard handshake with the
// gateway, carry the health-check pings, keep working across a reconnect, and
// leave neither its interface nor its UAPI socket behind.
//
// Creating a TUN interface needs root, so this runs only as root (CI runs it
// with sudo).
func TestUserspaceClient_TunnelsReconnectsAndCleansUp(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a TUN interface")
	}
	const ifname = "vproxtest0"

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	gwKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	port := startWireguardPeer(t, gwKey, clientKey.PublicKey(), "10.213.0.2/32")

	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, "vprox.test")
	gw := startGatewayResponding(t, &tls.Config{Certificates: []tls.Certificate{tlsCertificate(t, certPEM, keyPEM)}}, connectResponse{
		AssignedAddr:     "10.213.0.2/24",
		ServerPublicKey:  gwKey.PublicKey().String(),
		ServerListenPort: port,
	})
	wg, err := wgctrl.New()
	require.NoError(t, err)
	t.Cleanup(func() { wg.Close() })

	client := connectClient(t, gw, clientTLSConfigTrusting(ca, "vprox.test"))
	client.Key = clientKey
	client.Ifname = ifname
	client.WgClient = wg
	client.userspace, err = newUserspaceDevice(ifname)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.DeleteInterface()
		_, err := netlink.LinkByName(ifname)
		assert.ErrorAs(t, err, new(netlink.LinkNotFoundError), "interface removed")
		assert.NoFileExists(t, filepath.Join("/var/run/wireguard", ifname+".sock"))
	})

	ctx := context.Background()
	require.NoError(t, client.Connect())
	assert.Equal(t, "Bearer secret-token", <-gw.tokens)
	assert.True(t, client.CheckConnection(5*time.Second, ctx), "health check over the userspace tunnel")

	dev, err := wg.Device(ifname)
	require.NoError(t, err)
	assert.Equal(t, wgtypes.Userspace, dev.Type)
	require.Len(t, dev.Peers, 1)
	assert.Equal(t, gwKey.PublicKey(), dev.Peers[0].PublicKey)
	assert.False(t, dev.Peers[0].LastHandshakeTime.IsZero(), "handshake with the gateway")

	require.NoError(t, client.Connect())
	assert.True(t, client.CheckConnection(5*time.Second, ctx), "health check after reconnecting")
	require.NoError(t, client.Disconnect())
}

// startWireguardPeer runs an in-memory wireguard-go gateway that accepts
// clientPub from allowedIP and answers ICMP echo requests, returning its UDP
// port.
func startWireguardPeer(t *testing.T, key wgtypes.Key, clientPub wgtypes.Key, allowedIP string) int {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	dev := device.NewDevice(ch.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "gateway: "))
	t.Cleanup(dev.Close)
	require.NoError(t, dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s\n",
		hex.EncodeToString(key[:]), hex.EncodeToString(clientPub[:]), allowedIP)))
	require.NoError(t, dev.Up())

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case packet := <-ch.Inbound:
				if reply, ok := echoReply(packet); ok {
					select {
					case ch.Outbound <- reply:
					case <-done:
						return
					}
				}
			}
		}
	}()

	uapi, err := dev.IpcGet()
	require.NoError(t, err)
	for scanner := bufio.NewScanner(strings.NewReader(uapi)); scanner.Scan(); {
		if v, ok := strings.CutPrefix(scanner.Text(), "listen_port="); ok {
			port, err := strconv.Atoi(v)
			require.NoError(t, err)
			return port
		}
	}
	t.Fatal("gateway device reported no listen port")
	return 0
}

// echoReply turns an IPv4 ICMP echo request into its reply.
func echoReply(packet []byte) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 1 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 || packet[ihl] != 8 {
		return nil, false
	}
	reply := append([]byte(nil), packet...)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	putChecksum(reply[:ihl], 10)
	reply[ihl] = 0
	putChecksum(reply[ihl:], 2)
	return reply, true
}

// putChecksum writes the Internet checksum of b into b[at:at+2].
func putChecksum(b []byte, at int) {
	b[at], b[at+1] = 0, 0
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(b[at:], ^uint16(sum))
}
