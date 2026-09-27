//go:build linux
// +build linux

package wgembed

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
)

// NewWithOpts creates a new network interface, needs to be enabled with WireGuardInterface.Up() afterwards.
// opts.Name is require and must be set to a unique interface name
func NewWithOpts(opts Options) (WireGuardInterface, error) {
	// Neither implementation can use a name that is taken: the kernel device
	// fails with "file exists", and the userspace fallback then fails with a
	// misleading "failed to create TUN device: invalid argument". Report the
	// actual cause instead. The existing interface is never removed - it may be
	// a leftover of ours, but it may just as well belong to someone else.
	if _, err := netlink.LinkByName(opts.InterfaceName); err == nil {
		return nil, fmt.Errorf(
			"%w: %q - probably left over from a previous run that did not shut down cleanly; "+
				"if nothing else uses it, remove it with \"ip link delete %s\", otherwise choose another interface name",
			ErrInterfaceExists, opts.InterfaceName, opts.InterfaceName)
	}

	var kernelErr error
	if opts.AllowKernelModule {
		logrus.Debug("creating new kernel interface")
		wg, err := newKernelInterface(opts)
		if err == nil {
			return wg, nil
		}
		kernelErr = err
		logrus.Info(errors.Wrap(err, "falling back to embedded Go implementation"))
	}

	logrus.Debug("creating new userspace wireguard-go interface")
	wg, err := newUserspaceInterface(opts)
	if err != nil {
		if kernelErr != nil {
			// the kernel error is usually the more telling one, so keep both
			return nil, fmt.Errorf("kernel module: %v; embedded Go implementation: %w", kernelErr, err)
		}
		return nil, err
	}
	return wg, nil
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
