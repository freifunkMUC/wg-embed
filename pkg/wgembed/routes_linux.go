//go:build linux

package wgembed

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// syncRoutes brings the kernel routing table in line with what the peers are
// allowed to send. It is called after every change to the peers, and it only
// touches the routes it added itself: an operator who set up a route on this
// interface by hand, or from a lifecycle command, keeps it.
func (wg *commonInterface) syncRoutes() error {
	if !wg.manageRoutes {
		return nil
	}

	// Everything this reads has to be read under the lock, the peers above
	// all. Reading them first and locking afterwards let two peer changes
	// overtake each other: the one that read before the other's peer existed
	// would then remove the route that other one had just added.
	wg.routesMu.Lock()
	defer wg.routesMu.Unlock()

	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return fmt.Errorf("failed to find the wireguard interface: %w", err)
	}

	addresses, err := interfaceAddresses(link)
	if err != nil {
		return err
	}

	peers, err := wg.ListPeers()
	if err != nil {
		return fmt.Errorf("failed to list the peers: %w", err)
	}

	wanted := routesFor(peerNetworks(peers), addresses)

	if wg.routes == nil {
		wg.routes = map[string]bool{}
	}

	keep := make(map[string]bool, len(wanted))
	var firstErr error
	for _, route := range wanted {
		keep[route.String()] = true
		if wg.routes[route.String()] {
			continue
		}
		if err := addRoute(link, route); err != nil {
			// Keep going: one network that cannot be routed must not stop the
			// others, and the next sync tries again.
			logrus.Error(fmt.Errorf("failed to route %s to %s: %w", route, wg.Name(), err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		logrus.Infof("routing %s to %s", route, wg.Name())
		wg.routes[route.String()] = true
	}

	for route := range wg.routes {
		if keep[route] {
			continue
		}
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			// cannot have been added by addRoute, so nothing to remove
			delete(wg.routes, route)
			continue
		}
		if err := delRoute(link, prefix); err != nil {
			logrus.Error(fmt.Errorf("failed to remove the route for %s from %s: %w", route, wg.Name(), err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		logrus.Infof("no longer routing %s to %s", route, wg.Name())
		delete(wg.routes, route)
	}

	return firstErr
}

// interfaceAddresses returns the prefixes the interface's own addresses cover.
// The kernel routes those to the interface itself, which is why the peers
// inside them need no route.
func interfaceAddresses(link netlink.Link) ([]netip.Prefix, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to read the addresses of the wireguard interface: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		if prefix, ok := prefixOf(*addr.IPNet); ok {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

func addRoute(link netlink.Link, prefix netip.Prefix) error {
	err := netlink.RouteAdd(route(link, prefix))
	if errors.Is(err, unix.EEXIST) {
		// Somebody else routes this network here already - a lifecycle command,
		// most likely. Leave it to them, including removing it again.
		logrus.Debugf("%s is already routed to %s", prefix, link.Attrs().Name)
		return nil
	}
	return err
}

func delRoute(link netlink.Link, prefix netip.Prefix) error {
	err := netlink.RouteDel(route(link, prefix))
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		// already gone, which is what we wanted
		return nil
	}
	return err
}

func route(link netlink.Link, prefix netip.Prefix) *netlink.Route {
	r := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		},
	}
	// A route without a gateway is a link scoped one for IPv4; IPv6 has no
	// scopes and the kernel refuses anything but the default there.
	if prefix.Addr().Is4() {
		r.Scope = netlink.SCOPE_LINK
	}
	return r
}
