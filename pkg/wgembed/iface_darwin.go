//go:build darwin
// +build darwin

package wgembed

import (
	"github.com/sirupsen/logrus"
)

func NewWithOpts(opts Options) (WireGuardInterface, error) {
	logrus.Debug("creating new userspace wireguard-go interface")
	return newUserspaceInterface(opts.InterfaceName)
}

func (wg *commonInterface) Up() error {
	logrus.Println("wg.Up() is a no-op on macos")
	return nil
}

func (wg *commonInterface) setIP(ip string) error {
	return nil
}
