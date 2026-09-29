//go:build linux

package wgembed

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// routedNetworks returns the networks the kernel sends to the interface.
func routedNetworks(t *testing.T, name string) map[string]bool {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("finding the interface: %v", err)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("listing the routes: %v", err)
	}
	networks := map[string]bool{}
	for _, route := range routes {
		if route.Dst != nil {
			networks[route.Dst.String()] = true
		}
	}
	return networks
}

// A peer may be allowed to use a network that is not the interface's own - a
// site behind it. Without a route the kernel never sends anything there, and
// the peer's allowed IPs are a promise the server cannot keep.
func TestManageRoutesFollowsThePeers(t *testing.T) {
	requireNetAdmin(t)

	for _, allowKernel := range []bool{true, false} {
		t.Run(fmt.Sprintf("AllowKernelModule=%v", allowKernel), func(t *testing.T) {
			name := testInterfaceName(t)
			wg, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: allowKernel, ManageRoutes: true})
			if err != nil {
				t.Fatalf("NewWithOpts: %v", err)
			}
			t.Cleanup(func() { _ = wg.Close() })

			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			port := 51820 + int(time.Now().UnixNano()%1000)
			if err := wg.LoadConfig(&ConfigFile{Interface: IfaceConfig{
				PrivateKey: key.String(),
				ListenPort: &port,
				Address:    []string{"10.123.0.1/24"},
			}}); err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}

			// a route somebody else set up on the interface, as a lifecycle
			// command would
			link, err := netlink.LinkByName(name)
			if err != nil {
				t.Fatal(err)
			}
			_, foreign, err := net.ParseCIDR("10.222.0.0/24")
			if err != nil {
				t.Fatal(err)
			}
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: link.Attrs().Index, Dst: foreign, Scope: netlink.SCOPE_LINK,
			}); err != nil {
				t.Fatalf("adding the foreign route: %v", err)
			}

			peer, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := wg.AddPeer(peer.PublicKey().String(), "", []string{"10.123.0.2/32", "192.168.77.0/24"}); err != nil {
				t.Fatalf("AddPeer: %v", err)
			}

			routed := routedNetworks(t, name)
			if !routed["192.168.77.0/24"] {
				t.Errorf("the network behind the peer is not routed to the interface: %v", routed)
			}
			// the interface's own address already reaches it
			if routed["10.123.0.2/32"] {
				t.Errorf("the peer's address inside the vpn subnet got a route of its own: %v", routed)
			}

			// removing the peer takes its network with it, and leaves what
			// somebody else set up alone
			if err := wg.RemovePeer(peer.PublicKey().String()); err != nil {
				t.Fatalf("RemovePeer: %v", err)
			}
			routed = routedNetworks(t, name)
			if routed["192.168.77.0/24"] {
				t.Errorf("the network is still routed after its peer was removed: %v", routed)
			}
			if !routed["10.222.0.0/24"] {
				t.Errorf("a route that was not ours was removed: %v", routed)
			}
		})
	}
}

// Without the option nothing is routed: an installation that manages its own
// routes must not find new ones appearing.
func TestManageRoutesIsOptIn(t *testing.T) {
	requireNetAdmin(t)

	name := testInterfaceName(t)
	wg, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: true})
	if err != nil {
		t.Fatalf("NewWithOpts: %v", err)
	}
	t.Cleanup(func() { _ = wg.Close() })

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	port := 51820 + int(time.Now().UnixNano()%1000)
	if err := wg.LoadConfig(&ConfigFile{Interface: IfaceConfig{
		PrivateKey: key.String(),
		ListenPort: &port,
		Address:    []string{"10.124.0.1/24"},
	}}); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wg.AddPeer(peer.PublicKey().String(), "", []string{"192.168.78.0/24"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	if routed := routedNetworks(t, name); routed["192.168.78.0/24"] {
		t.Errorf("a route was added although ManageRoutes is off: %v", routed)
	}
}

// Peers change concurrently - two admins, or events from several replicas.
// syncRoutes used to read the peers before taking its lock, so the pass that
// read first could remove the route the other one had just added.
//
// This does not reproduce that ordering reliably: the pass that takes the lock
// last usually read last as well, and then puts everything back. It is here as
// the only test that changes peers concurrently at all, and it would catch a
// sync that drops routes outright.
func TestManageRoutesSurvivesConcurrentPeers(t *testing.T) {
	requireNetAdmin(t)

	name := testInterfaceName(t)
	wg, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: true, ManageRoutes: true})
	if err != nil {
		t.Fatalf("NewWithOpts: %v", err)
	}
	t.Cleanup(func() { _ = wg.Close() })

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	port := 51820 + int(time.Now().UnixNano()%1000)
	if err := wg.LoadConfig(&ConfigFile{Interface: IfaceConfig{
		PrivateKey: key.String(),
		ListenPort: &port,
		Address:    []string{"10.125.0.1/24"},
	}}); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	const peers = 12
	var wgGroup sync.WaitGroup
	errs := make(chan error, peers)
	for i := 0; i < peers; i++ {
		wgGroup.Add(1)
		go func(i int) {
			defer wgGroup.Done()
			peer, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				errs <- err
				return
			}
			errs <- wg.AddPeer(peer.PublicKey().String(), "", []string{
				fmt.Sprintf("10.125.0.%d/32", i+2),
				fmt.Sprintf("192.168.%d.0/24", 100+i),
			})
		}(i)
	}
	wgGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
	}

	routed := routedNetworks(t, name)
	for i := 0; i < peers; i++ {
		network := fmt.Sprintf("192.168.%d.0/24", 100+i)
		if !routed[network] {
			t.Errorf("%s is not routed although its peer was added: %v", network, routed)
		}
	}
}
