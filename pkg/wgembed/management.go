package wgembed

import (
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddPeer adds a new peer to the interface.
// The subnet sizes in addressCIDR should be /32 for IPv4 and /128 for IPv6,
// as the whole subnet will be added to AllowedIPs for this device.
// The presharedKey is optinal and can be omitted with nil
func (wg *commonInterface) AddPeer(publicKey string, presharedKey string, addressCIDR []string) error {
	wgPublicKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("bad public key %v: %w", publicKey, err)
	}

	var wgPresharedKey *wgtypes.Key
	if len(presharedKey) != 0 {
		psk, err := wgtypes.ParseKey(presharedKey)
		if err != nil {
			logrus.WithError(err).Warnf("ignoring bad pre-shared key: %v", presharedKey)
		} else {
			wgPresharedKey = &psk
		}
	}

	parsedAddresses := make([]net.IPNet, 0, len(addressCIDR))
	for _, addr := range addressCIDR {
		_, allowedIPs, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("bad CIDR value for AllowedIPs %q: %w", addr, err)
		}
		// Wrapping a nil error used to make this return nil - the address was
		// then dropped and the caller was told the peer had been added with it.
		if allowedIPs == nil {
			return fmt.Errorf("bad CIDR value for AllowedIPs %q", addr)
		}
		parsedAddresses = append(parsedAddresses, *allowedIPs)
	}

	if err := wg.configure(func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			{
				PublicKey:         wgPublicKey,
				PresharedKey:      wgPresharedKey,
				AllowedIPs:        parsedAddresses,
				ReplaceAllowedIPs: true,
			},
		}
		return nil
	}); err != nil {
		return err
	}

	// The peer may be allowed to use a network that is not the interface's
	// own: without a route the kernel would never send anything there.
	return wg.syncRoutes()
}

func (wg *commonInterface) ListPeers() ([]wgtypes.Peer, error) {
	device, err := wg.Device()
	if err != nil {
		return nil, err
	}
	return device.Peers, nil
}

func (wg *commonInterface) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("bad public key: %w", err)
	}
	if err := wg.configure(func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			{
				Remove:    true,
				PublicKey: key,
			},
		}
		return nil
	}); err != nil {
		return err
	}

	// Whatever was routed here for this peer alone goes with it.
	return wg.syncRoutes()
}

func (wg *commonInterface) HasPeer(publicKey string) bool {
	peers, err := wg.ListPeers()
	if err != nil {
		logrus.Error(fmt.Errorf("failed to list peers: %w", err))
		return false
	}
	for _, peer := range peers {
		if peer.PublicKey.String() == publicKey {
			return true
		}
	}
	return false
}

func (wg *commonInterface) Peer(publicKey string) (*wgtypes.Peer, error) {
	peers, err := wg.ListPeers()
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.PublicKey.String() == publicKey {
			return &peer, nil
		}
	}
	return nil, fmt.Errorf("peer with public key '%s' not found", publicKey)
}

// PublicKey returns the currently configured wireguard public key
func (wg *commonInterface) PublicKey() (string, error) {
	device, err := wg.Device()
	if err != nil {
		return "", err
	}
	return device.PublicKey.String(), nil
}

func (wg *commonInterface) Port() (int, error) {
	device, err := wg.Device()
	if err != nil {
		return 0, err
	}
	return device.ListenPort, nil
}

func (wg *commonInterface) Ping() error {
	if _, err := wg.ListPeers(); err != nil {
		return errors.New("failed to ping wireguard")
	}
	return nil
}

func (wg *commonInterface) configure(cb func(*wgtypes.Config) error) error {
	// TODO: concurrency
	// s.lock.Lock()
	// defer s.lock.Unlock()
	next := wgtypes.Config{}
	if err := cb(&next); err != nil {
		return fmt.Errorf("failed to get next wireguard config: %w", err)
	}
	return wg.client.ConfigureDevice(wg.Name(), next)
}
