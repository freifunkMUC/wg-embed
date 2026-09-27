package wgembed

import (
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	parsed := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("parsing %q: %v", value, err)
		}
		parsed = append(parsed, prefix)
	}
	return parsed
}

func routeStrings(routes []netip.Prefix) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, route.String())
	}
	return values
}

func sameStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRoutesFor(t *testing.T) {
	addresses := prefixes(t, "10.44.0.1/24", "fd48:4c4:7aa9::1/64")

	for _, tc := range []struct {
		name     string
		networks []string
		want     []string
	}{
		{
			// the usual case: every peer sits in the VPN subnet, which the
			// interface's own address already routes
			name:     "peers inside the vpn subnet need no route",
			networks: []string{"10.44.0.2/32", "10.44.0.3/32", "fd48:4c4:7aa9::2/128"},
			want:     nil,
		},
		{
			name:     "a network behind a peer gets a route",
			networks: []string{"10.44.0.2/32", "192.168.77.0/24", "2001:db8:1::/48"},
			want:     []string{"192.168.77.0/24", "2001:db8:1::/48"},
		},
		{
			// two peers behind the same site, or one peer listed twice
			name:     "the same network is routed once",
			networks: []string{"192.168.77.0/24", "192.168.77.0/24"},
			want:     []string{"192.168.77.0/24"},
		},
		{
			// a default route here would send the server's own traffic, the
			// tunnel's own packets included, into the tunnel
			name:     "a default route is never added",
			networks: []string{"0.0.0.0/0", "::/0", "192.168.77.0/24"},
			want:     []string{"192.168.77.0/24"},
		},
		{
			// the address is a /24, so anything smaller inside it is reached
			name:     "a part of the vpn subnet needs no route",
			networks: []string{"10.44.0.0/28"},
			want:     nil,
		},
		{
			// ... but a network the address does not cover does
			name:     "a network around the vpn subnet is routed",
			networks: []string{"10.44.0.0/16"},
			want:     []string{"10.44.0.0/16"},
		},
		{
			// a host address of a network, as wgctrl reports allowed IPs
			name:     "an unmasked network is routed as its network address",
			networks: []string{"192.168.77.5/24"},
			want:     []string{"192.168.77.0/24"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := routeStrings(routesFor(prefixes(t, tc.networks...), addresses))
			if !sameStrings(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
				t.Errorf("routesFor = %v, want %v", got, tc.want)
			}
		})
	}
}

// The order has to be the same from one sync to the next, so that what is
// logged can be compared.
func TestRoutesForIsOrdered(t *testing.T) {
	networks := prefixes(t, "192.168.9.0/24", "10.9.0.0/16", "172.16.0.0/12")
	first := routeStrings(routesFor(networks, nil))

	reversed := []netip.Prefix{networks[2], networks[1], networks[0]}
	if second := routeStrings(routesFor(reversed, nil)); !sameStrings(first, second) {
		t.Errorf("routesFor = %v and %v for the same networks in another order", first, second)
	}
}

func TestPeerNetworks(t *testing.T) {
	_, first, err := net.ParseCIDR("192.168.77.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := net.ParseCIDR("10.44.0.2/32")
	if err != nil {
		t.Fatal(err)
	}

	peers := []wgtypes.Peer{
		{AllowedIPs: []net.IPNet{*second, *first}},
		{AllowedIPs: nil},
	}
	got := routeStrings(peerNetworks(peers))
	if want := []string{"10.44.0.2/32", "192.168.77.0/24"}; !sameStrings(got, want) {
		t.Errorf("peerNetworks = %v, want %v", got, want)
	}
}

// netlink and wgctrl report IPv4 addresses as 16 byte slices, which must not
// turn into IPv6 prefixes.
func TestPrefixOfUnmapsIPv4(t *testing.T) {
	ipnet := net.IPNet{IP: net.ParseIP("10.44.0.0"), Mask: net.CIDRMask(24, 32)}
	prefix, ok := prefixOf(ipnet)
	if !ok {
		t.Fatal("prefixOf rejected an IPv4 network")
	}
	if !prefix.Addr().Is4() || prefix.String() != "10.44.0.0/24" {
		t.Errorf("prefixOf = %s, want 10.44.0.0/24 as IPv4", prefix)
	}
}

func TestPrefixOfRejectsWhatIsNotAPrefix(t *testing.T) {
	// a mask with a hole in it describes no prefix
	if _, ok := prefixOf(net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.IPMask{255, 0, 255, 0}}); ok {
		t.Error("prefixOf accepted a non-contiguous mask")
	}
	if _, ok := prefixOf(net.IPNet{}); ok {
		t.Error("prefixOf accepted an empty network")
	}
}
