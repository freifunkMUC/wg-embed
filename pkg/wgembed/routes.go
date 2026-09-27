package wgembed

import (
	"net"
	"net/netip"
	"sort"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// peerNetworks returns the networks the peers are allowed to use, as prefixes.
// What the interface reports is authoritative: it is what the kernel will
// actually accept from the peers, whoever configured it.
func peerNetworks(peers []wgtypes.Peer) []netip.Prefix {
	networks := make([]netip.Prefix, 0, len(peers))
	for _, peer := range peers {
		for _, allowed := range peer.AllowedIPs {
			if prefix, ok := prefixOf(allowed); ok {
				networks = append(networks, prefix)
			}
		}
	}
	return networks
}

// routesFor returns the networks that need a route to the interface: the ones
// the peers are allowed to use, minus what the interface's own addresses
// already reach, and minus default routes.
//
// A default route is left out on purpose. wg-quick installs one for a client
// that tunnels everything, but this interface belongs to a server: a default
// route to it would send the server's own traffic - including the tunnel's own
// packets - into the tunnel.
func routesFor(networks []netip.Prefix, addresses []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	routes := []netip.Prefix{}

	for _, network := range networks {
		if !network.IsValid() {
			continue
		}
		network = network.Masked()
		if network.Bits() == 0 || seen[network] || coveredBy(network, addresses) {
			continue
		}
		seen[network] = true
		routes = append(routes, network)
	}

	// a stable order, so that what is logged from one sync to the next can be
	// compared
	sort.Slice(routes, func(i, j int) bool { return routes[i].String() < routes[j].String() })
	return routes
}

// coveredBy reports whether one of the addresses already reaches the whole
// network - the interface's own address prefixes come with a route each, which
// is why a peer inside the VPN subnet needs no route of its own.
func coveredBy(network netip.Prefix, addresses []netip.Prefix) bool {
	for _, address := range addresses {
		address = address.Masked()
		if address.Bits() <= network.Bits() && address.Contains(network.Addr()) {
			return true
		}
	}
	return false
}

// prefixOf converts a net.IPNet, which is what wgctrl and netlink speak, into
// a prefix. An address that is not one is reported as such rather than
// silently becoming something else.
func prefixOf(ipnet net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := ipnet.Mask.Size()
	if ones == 0 && bits == 0 {
		// a mask that is not contiguous - there is no prefix for it
		return netip.Prefix{}, false
	}
	// A 4-in-6 address carries a 32 bit mask: unmap it, so that 10.0.0.0/8
	// does not turn into a /8 of an IPv6 address.
	if addr.Is4In6() && bits == 32 {
		addr = addr.Unmap()
	}
	prefix := netip.PrefixFrom(addr, ones)
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}
