//go:build linux
// +build linux

package wgembed

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
)

// NewWithOpts creates a new network interface, needs to be enabled with WireGuardInterface.Up() afterwards.
// opts.Name is require and must be set to a unique interface name
func NewWithOpts(opts Options) (WireGuardInterface, error) {
	if opts.AllowKernelModule {
		logrus.Debug("creating new kernel interface")
		wg, err := newKernelInterface(opts.InterfaceName)
		if err != nil {
			logrus.Info(errors.Wrap(err, "falling back to embedded Go implementation"))
		} else {
			return wg, nil
		}
	}
	logrus.Debug("creating new userspace wireguard-go interface")
	return newUserspaceInterface(opts.InterfaceName)
}

// Up activates an existing interface created with New() or NewWithOpts()
func (wg *commonInterface) Up() error {
	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return errors.Wrap(err, "failed to find wireguard interface")
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return errors.Wrap(err, "failed to bring wireguard interface up")
	}

	MTU := device.DefaultMTU
	if wg.config.Interface.MTU != nil {
		MTU = *wg.config.Interface.MTU
	}
	if err := netlink.LinkSetMTU(link, MTU); err != nil {
		return errors.Wrap(err, "failed to set wireguard mtu")
	}

	logrus.Debug("interface set up successfully")

	return nil
}

func (wg *commonInterface) setIP(ip string) error {
	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return errors.Wrap(err, "failed to find wireguard interface")
	}

	linkaddr, err := netlink.ParseAddr(ip)
	if err != nil {
		return errors.Wrap(err, "failed to parse wireguard interface ip address")
	}

	if err := netlink.AddrAdd(link, linkaddr); err != nil {
		return errors.Wrap(err, "failed to set ip address of wireguard interface")
	}

	return nil
}
