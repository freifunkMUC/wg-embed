//go:build linux

package wgembed

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// These tests create network interfaces and need CAP_NET_ADMIN and /dev/net/tun,
// e.g. `docker run --cap-add NET_ADMIN --device /dev/net/tun` or `sudo -E go test`.
func requireNetAdmin(t *testing.T) {
	t.Helper()
	if os.Getenv("WGEMBED_TEST_NETADMIN") == "" {
		t.Skip("WGEMBED_TEST_NETADMIN not set")
	}
}

func testInterfaceName(t *testing.T) string {
	t.Helper()
	// interface names are limited to 15 bytes
	name := fmt.Sprintf("wgt%d", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	return name
}

// An interface left over from a run that was killed - with hostNetwork it
// survives in the host namespace - used to end in a misleading "failed to
// create TUN device: invalid argument". The name may just as well belong to
// something else on the host, so it must be reported, never removed.
func TestNewWithOptsRejectsExistingInterface(t *testing.T) {
	requireNetAdmin(t)

	for _, allowKernel := range []bool{true, false} {
		t.Run(fmt.Sprintf("AllowKernelModule=%v", allowKernel), func(t *testing.T) {
			name := testInterfaceName(t)
			attrs := netlink.NewLinkAttrs()
			attrs.Name = name
			if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
				if errors.Is(err, syscall.EOPNOTSUPP) {
					t.Skipf("the kernel has no dummy link support: %v", err)
				}
				t.Fatalf("creating the occupying dummy link: %v", err)
			}

			wg, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: allowKernel})
			if err == nil {
				_ = wg.Close()
				t.Fatal("NewWithOpts must fail when the interface name is taken")
			}
			if !errors.Is(err, ErrInterfaceExists) {
				t.Errorf("error is not ErrInterfaceExists: %v", err)
			}
			if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "ip link delete") {
				t.Errorf("error should name the interface and how to remove it: %v", err)
			}

			link, lookupErr := netlink.LinkByName(name)
			if lookupErr != nil {
				t.Fatalf("the existing interface was removed: %v", lookupErr)
			}
			if link.Type() != "dummy" {
				t.Errorf("the existing interface was replaced by a %q link", link.Type())
			}
		})
	}
}

func TestNewWithOptsCreatesAndRemovesInterface(t *testing.T) {
	requireNetAdmin(t)

	for _, allowKernel := range []bool{true, false} {
		t.Run(fmt.Sprintf("AllowKernelModule=%v", allowKernel), func(t *testing.T) {
			name := testInterfaceName(t)
			wg, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: allowKernel})
			if err != nil {
				t.Fatalf("NewWithOpts: %v", err)
			}
			if _, err := netlink.LinkByName(name); err != nil {
				t.Fatalf("interface not created: %v", err)
			}

			// configure it for real: for the userspace implementation this goes
			// through the UAPI socket, so a dead configuration listener shows up
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
			peer, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := wg.AddPeer(peer.PublicKey().String(), "", []string{"10.123.0.2/32"}); err != nil {
				t.Fatalf("AddPeer: %v", err)
			}
			peers, err := wg.ListPeers()
			if err != nil || len(peers) != 1 {
				t.Fatalf("ListPeers = %d peers, %v", len(peers), err)
			}
			if got, err := wg.PublicKey(); err != nil || got != key.PublicKey().String() {
				t.Fatalf("PublicKey = %q, %v", got, err)
			}

			// closing twice must be harmless
			if err := wg.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			_ = wg.Close()

			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := netlink.LinkByName(name); err != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("interface still exists after Close")
				}
				time.Sleep(50 * time.Millisecond)
			}

			// the name is free again, so a restart works
			again, err := NewWithOpts(Options{InterfaceName: name, AllowKernelModule: allowKernel})
			if err != nil {
				t.Fatalf("recreating after Close: %v", err)
			}
			_ = again.Close()
		})
	}
}
