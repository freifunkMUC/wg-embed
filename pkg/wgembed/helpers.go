package wgembed

import (
	"fmt"

	_ "golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// NewKeyPair generates a WireGuard key pair. It used to end the process of
// whoever called it when the system's randomness was unavailable - a decision
// that is not a library's to make.
func NewKeyPair() (KeyPair, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return KeyPair{}, fmt.Errorf("failed to generate key: %w", err)
	}
	return KeyPair{
		PrivateKey: key.String(),
		PublicKey:  key.PublicKey().String(),
	}, nil
}
