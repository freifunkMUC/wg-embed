//go:build windows
// +build windows

package wgembed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// What this is about: the constructor used to hand back an empty struct and a
// log line. Every caller took that for an interface, and the first method call
// on it dereferenced a nil client. An error is the only honest answer while
// nothing here creates an interface.
func TestNewRefusesInsteadOfHandingBackSomethingBroken(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func() (WireGuardInterface, error)
	}{
		{"New", func() (WireGuardInterface, error) { return New("wg0") }},
		{"NewWithOpts", func() (WireGuardInterface, error) { return NewWithOpts(Options{InterfaceName: "wg0"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface, err := tc.call()
			if err == nil {
				t.Fatal("an interface was created on a platform that has none")
			}
			if !errors.Is(err, ErrUnsupportedPlatform) {
				t.Errorf("err = %v, want it to be ErrUnsupportedPlatform", err)
			}
			// nil, so that a caller ignoring the error panics at its own call
			// rather than deep inside this package
			if iface != nil {
				t.Errorf("iface = %#v, want nil", iface)
			}
		})
	}
}

// The config file check warns about a mode that says nothing here: Go makes
// the mode up from the read-only attribute, so every file looks world-readable
// and the warning - "chmod 600 it" - names a command this platform does not
// have. It would fire for every config file read.
func TestReadingAConfigDoesNotWarnAboutItsMode(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	path := filepath.Join(t.TempDir(), "wg0.conf")
	// generated here rather than written down, so that no key material lives
	// in the repository - the other tests do the same. A peer section is not
	// optional: mapping the file fails without one.
	contents := "[Interface]\nPrivateKey = " + testKey(t).String() + "\nAddress = 10.44.0.1/24\n\n" +
		"[Peer]\nPublicKey = " + testKey(t).PublicKey().String() + "\nAllowedIPs = 10.44.0.2/32\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadConfig(path); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "readable by other users") {
			t.Errorf("warned about the file mode: %s", entry.Message)
		}
	}
}

// The no-op interface is what a caller on Windows can still use - the tests of
// wg-access-server run on it - so it must not have gone the same way.
func TestNoOpInterfaceStillWorksHere(t *testing.T) {
	iface := NewNoOpInterface()
	if err := iface.AddPeer("key", "", []string{"10.44.0.2/32"}); err != nil {
		t.Errorf("AddPeer: %v", err)
	}
	if _, err := iface.ListPeers(); err != nil {
		t.Errorf("ListPeers: %v", err)
	}
	if err := iface.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
