package wgembed

import (
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardInterface interface {
	LoadConfig(config *ConfigFile) error
	AddPeer(publicKey string, presharedKey string, addressCIDR []string) error
	ListPeers() ([]wgtypes.Peer, error)
	RemovePeer(publicKey string) error
	PublicKey() (string, error)
	Close() error
	Ping() error
}

// Options contains configuration options for the interface
type Options struct {
	// InterfaceName will be the name of the network interface, this is required
	InterfaceName string
	// AllowKernelModule enables the usage of the WireGuard kernel module.
	// Falls back to userspace if creation fails. No effect on Windows or Darwin
	AllowKernelModule bool
}

// New creates a wireguard interface and starts the userspace
// wireguard configuration api
func New(interfaceName string) (WireGuardInterface, error) {
	return newUserspaceInterface(interfaceName)
}

// commonInterface holds fields that are common across all wgctrl-controlled implementations
type commonInterface struct {
	name   string
	client *wgctrl.Client
	config *ConfigFile
}

// LoadConfigFile reads the given wireguard config file
// and configures the interface
func (wg *commonInterface) LoadConfigFile(path string) error {
	config, err := ReadConfig(path)
	if err != nil {
		return errors.Wrap(err, "failed to load config file")
	}
	return wg.LoadConfig(config)
}

// LoadConfig takes the given wireguard config object
// and configures the interface
func (wg *commonInterface) LoadConfig(config *ConfigFile) error {
	c, err := config.Config()
	if err != nil {
		return errors.Wrap(err, "invalid wireguard config")
	}

	wg.config = config

	if err := wg.client.ConfigureDevice(wg.Name(), *c); err != nil {
		return errors.Wrap(err, "failed to configure wireguard")
	}

	for _, addr := range config.Interface.Address {
		if err := wg.setIP(addr); err != nil {
			return errors.Wrap(err, "failed to set interface ip address")
		}
	}

	if err := wg.Up(); err != nil {
		return errors.Wrap(err, "failed to bring interface up")
	}

	return nil
}

// Config returns the loaded wireguard config file
// can return nil if no config has been loaded
func (wg *commonInterface) Config() *ConfigFile {
	return wg.config
}

// Device returns the wgtypes Device, this type contains
// runtime infomation about the wireguard interface
func (wg *commonInterface) Device() (*wgtypes.Device, error) {
	return wg.client.Device(wg.Name())
}

// Name returns the real wireguard interface name e.g. wg0
func (wg *commonInterface) Name() string {
	return wg.name
}
