package lib

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// userspaceDevice is a wireguard-go device on a TUN interface, used where the
// kernel has no WireGuard module. It serves the standard UAPI socket, so
// wgctrl (and `wg show`) configure and inspect it exactly like a kernel
// WireGuard interface.
type userspaceDevice struct {
	dev  *device.Device
	uapi net.Listener
}

func newUserspaceDevice(ifname string) (*userspaceDevice, error) {
	tunDev, err := tun.CreateTUN(ifname, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("creating TUN interface: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, fmt.Sprintf("wireguard-go(%s): ", ifname)))
	uapi, err := listenUAPI(ifname)
	if err != nil {
		dev.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(conn)
		}
	}()
	return &userspaceDevice{dev, uapi}, nil
}

func listenUAPI(ifname string) (net.Listener, error) {
	file, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, fmt.Errorf("opening UAPI socket: %w", err)
	}
	// UAPIListen duplicates the descriptor.
	defer file.Close()
	uapi, err := ipc.UAPIListen(ifname, file)
	if err != nil {
		return nil, fmt.Errorf("listening on UAPI socket: %w", err)
	}
	return uapi, nil
}

// Close removes the UAPI socket and the TUN interface.
func (d *userspaceDevice) Close() {
	d.uapi.Close()
	d.dev.Close()
}
