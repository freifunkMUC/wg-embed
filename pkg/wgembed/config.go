package wgembed

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

// redactedValue stands in for the private key wherever a configuration is
// rendered as text.
const redactedValue = "<redacted>"

type ConfigFile struct {
	Interface IfaceConfig
	Peers     []PeerConfig    `ini:"Peer,nonunique"`
	wgconfig  *wgtypes.Config `ini:"-"`
}

type IfaceConfig struct {
	PrivateKey string
	Address    []string
	ListenPort *int
	DNS        []string
	MTU        *int
}

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   *string
}

func ReadConfig(path string) (*ConfigFile, error) {

	opts := &ConfigFile{
		Interface: IfaceConfig{
			DNS: []string{},
		},
		Peers: []PeerConfig{},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read wireguard config file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// The file holds a private key. Checking the handle rather than the path
	// describes the file that is actually being read.
	if info, err := file.Stat(); err == nil && readableByOthers(info) {
		logrus.Warnf("%s is readable by other users (mode %04o) although it holds the private key - chmod 600 it",
			path, info.Mode().Perm())
	}

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read wireguard config file: %w", err)
	}

	if err := opts.parse(bytes); err != nil {
		return nil, err
	}

	if err := opts.load(); err != nil {
		return nil, err
	}

	return opts, nil
}

func (c *ConfigFile) parse(config []byte) error {
	opt := ini.LoadOptions{AllowNonUniqueSections: true}
	f, err := ini.LoadSources(opt, config)
	if err != nil {
		return fmt.Errorf("failed to read wireguard config file: %w", err)
	}

	err = f.MapTo(c)
	if err != nil {
		return fmt.Errorf("failed to map wireguard config file: %w", err)
	}

	return nil
}

func (c *ConfigFile) load() error {
	privateKey, err := wgtypes.ParseKey(c.Interface.PrivateKey)
	if err != nil {
		return fmt.Errorf("bad private key: %w", err)
	}

	peers := make([]wgtypes.PeerConfig, 0, len(c.Peers))
	for _, peer := range c.Peers {
		key, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return fmt.Errorf("bad public key: %w", err)
		}

		allowedIPs := make([]net.IPNet, 0, len(peer.AllowedIPs))
		for _, ip := range peer.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				return fmt.Errorf("bad allowed ip: %s: %w", ip, err)
			}
			allowedIPs = append(allowedIPs, *ipnet)
		}

		var endpoint *net.UDPAddr
		if peer.Endpoint != nil {
			udpaddr, err := net.ResolveUDPAddr("udp", *peer.Endpoint)
			if err != nil {
				return fmt.Errorf("failed to parse endpoint address: %w", err)
			}
			endpoint = udpaddr
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:  key,
			AllowedIPs: allowedIPs,
			Endpoint:   endpoint,
		})
	}

	c.wgconfig = &wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: c.Interface.ListenPort,
		Peers:      peers,
	}

	return nil
}

func (c *ConfigFile) Config() (*wgtypes.Config, error) {
	if c.wgconfig == nil {
		if err := c.load(); err != nil {
			return nil, err
		}
	}
	return c.wgconfig, nil
}

// String renders the configuration the way a wg-quick file looks, with the
// private key left out: this is what ends up in a log line or a %v, and the
// key has no business being there. It used to write into a nil *ini.File,
// which panicked before it could get that far.
func (c *ConfigFile) String() string {
	redacted := *c
	if redacted.Interface.PrivateKey != "" {
		redacted.Interface.PrivateKey = redactedValue
	}

	f := ini.Empty(ini.LoadOptions{AllowNonUniqueSections: true})
	if err := ini.ReflectFrom(f, &redacted); err != nil {
		return fmt.Sprintf("<wireguard config that cannot be rendered: %v>", err)
	}

	var out strings.Builder
	if _, err := f.WriteTo(&out); err != nil {
		return fmt.Sprintf("<wireguard config that cannot be rendered: %v>", err)
	}
	return out.String()
}
