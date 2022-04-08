//go:build windows
// +build windows

package wgembed

import (
	"net"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
)

// userspaceInterface represents an userspace wireguard-go
// network interface
type userspaceInterface struct {
	commonInterface
	device *device.Device
	uapi   net.Listener
}

func NewWithOpts(opts Options) (WireGuardInterface, error) {
	logrus.Debug("creating new userspace wireguard-go interface")
	return newUserspaceInterface(opts.InterfaceName)
}

func newUserspaceInterface(interfaceName string) (WireGuardInterface, error) {
	// TODO: https://git.zx2c4.com/wireguard-go/tree/main_windows.go
	logrus.Println("newUserspaceInterface not implemented for Windows")
	return &userspaceInterface{}, nil
}

func (wg *commonInterface) Up() error {
	logrus.Println("wg.Up() is a no-op on windows")
	return nil
}

func (wg *commonInterface) setIP(ip string) error {
	return nil
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api
func (wg *userspaceInterface) Close() error {
	if err := wg.uapi.Close(); err != nil {
		return err
	}
	wg.device.Close()
	wg.client.Close()
	return nil
}
