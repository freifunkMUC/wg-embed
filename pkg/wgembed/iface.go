package wgembed

import (
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrInterfaceExists is returned by NewWithOpts when a network interface with
// the requested name already exists. It is typically left over from a previous
// run that was killed before it could remove its interface.
var ErrInterfaceExists = errors.New("network interface already exists")

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
	// ManageRoutes keeps the kernel routing table in line with what the peers
	// are allowed to send: every network in a peer's allowed IPs that the
	// interface's own addresses do not already reach gets a route to this
	// interface, the way wg-quick's "Table = auto" does it. Without it a peer
	// may be allowed to use a network the kernel never sends anything to.
	//
	// Only the routes it added itself are ever removed again, so a route set
	// up by hand or by a lifecycle command stays. A default route is never
	// added: on a server that would send its own traffic into the tunnel.
	//
	// Linux only; elsewhere it does nothing.
	ManageRoutes bool
}

// New creates a wireguard interface and starts the userspace
// wireguard configuration api
func New(interfaceName string) (WireGuardInterface, error) {
	return newUserspaceInterface(Options{InterfaceName: interfaceName})
}

// commonInterface holds fields that are common across all wgctrl-controlled implementations
type commonInterface struct {
	name   string
	client *wgctrl.Client
	config *ConfigFile

	// manageRoutes is Options.ManageRoutes; routes holds the networks this
	// interface has a route for, so that only those are removed again. The
	// interface is created fresh on every start - its routes go with it - so
	// remembering them in the process is enough.
	manageRoutes bool
	routesMu     sync.Mutex
	routes       map[string]bool

	closeOnce sync.Once
	closeErr  error
}

// LoadConfigFile reads the given wireguard config file
// and configures the interface
func (wg *commonInterface) LoadConfigFile(path string) error {
	config, err := ReadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config file: %w", err)
	}
	return wg.LoadConfig(config)
}

// LoadConfig takes the given wireguard config object
// and configures the interface
func (wg *commonInterface) LoadConfig(config *ConfigFile) error {
	c, err := config.Config()
	if err != nil {
		return fmt.Errorf("invalid wireguard config: %w", err)
	}

	wg.config = config

	if err := wg.client.ConfigureDevice(wg.Name(), *c); err != nil {
		return fmt.Errorf("failed to configure wireguard: %w", err)
	}

	for _, addr := range config.Interface.Address {
		if err := wg.setIP(addr); err != nil {
			return fmt.Errorf("failed to set interface ip address: %w", err)
		}
	}

	if err := wg.Up(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// A config file may bring peers of its own along with it.
	if err := wg.syncRoutes(); err != nil {
		return fmt.Errorf("failed to set up the routes of the peers: %w", err)
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
