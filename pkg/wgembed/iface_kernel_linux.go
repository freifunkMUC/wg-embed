//go:build linux
// +build linux

package wgembed

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type kernelInterface struct {
	commonInterface
}

type netlinkWireguard struct {
	netlink.LinkAttrs
}

func newKernelInterface(interfaceName string) (WireGuardInterface, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = interfaceName
	attrs.MTU = device.DefaultMTU
	link := &netlinkWireguard{attrs}

	err := netlink.LinkAdd(link)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wireguard kernel device")
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wg client")
	}

	wg := &kernelInterface{
		commonInterface: commonInterface{
			client: client,
			name:   interfaceName,
		},
	}

	return wg, nil
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api
func (wg *kernelInterface) Close() error {
	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return err
	}
	var firstErr error

	err = netlink.LinkSetDown(link)
	if err != nil {
		firstErr = err
		// Keep trying
	}
	err = netlink.LinkDel(link)
	if err != nil && firstErr == nil {
		firstErr = err
	}
	err = wg.client.Close()
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (wglink *netlinkWireguard) Attrs() *netlink.LinkAttrs {
	return &wglink.LinkAttrs
}

func (wglink *netlinkWireguard) Type() string {
	return "wireguard"
}
