//go:build windows
// +build windows

package wgembed

import "fmt"

// Windows has no interface implementation here. wireguard-go can drive a
// Wintun adapter, but none of the pieces this package needs are wired up for
// it: no TUN device is created, no configuration API is opened, and no wgctrl
// client exists to configure peers with.
//
// It used to return an empty struct and log that it was not implemented, which
// looked like success to every caller: the first call that touched the
// interface - adding a peer, listing them, closing it - dereferenced a nil
// client and took the process down. Saying so here costs a caller nothing it
// had, and it says it at the one place that can still do something about it.

func NewWithOpts(opts Options) (WireGuardInterface, error) {
	return nil, fmt.Errorf("%w: windows", ErrUnsupportedPlatform)
}

func newUserspaceInterface(opts Options) (WireGuardInterface, error) {
	return nil, fmt.Errorf("%w: windows", ErrUnsupportedPlatform)
}

// Up and setIP exist because the code shared with the other platforms names
// them. Nothing on Windows can reach them: an interface is never created.

func (wg *commonInterface) Up() error {
	return fmt.Errorf("%w: windows", ErrUnsupportedPlatform)
}

func (wg *commonInterface) setIP(ip string) error {
	return fmt.Errorf("%w: windows", ErrUnsupportedPlatform)
}
