package wgembed

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A pre-shared key is secret. It used to be logged when it could not be
// parsed, and the peer was then added without it - so the client, which has
// the key, could never complete a handshake, and nothing said why.
func TestAddPeerRejectsABadPresharedKeyWithoutLoggingIt(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	// the interface is never reached: the key is rejected before anything is
	// configured, which is what this test is about
	wg := &commonInterface{name: "wgtest0"}
	badKey := "not-a-key-but-still-a-secret"

	err := wg.AddPeer(testKey(t).PublicKey().String(), badKey, []string{"10.44.0.2/32"})
	if err == nil {
		t.Fatal("a pre-shared key that cannot be parsed was accepted")
	}
	if strings.Contains(err.Error(), badKey) {
		t.Errorf("the error carries the key: %v", err)
	}
	for _, entry := range hook.AllEntries() {
		message, _ := entry.String()
		if strings.Contains(message, badKey) {
			t.Errorf("the key was written to the log: %s", message)
		}
	}
}

// A configuration that is rendered as text ends up in logs and in %v. The
// private key has no business being there - and String() used to panic before
// it could leak anything at all.
func TestConfigFileStringRedactsThePrivateKey(t *testing.T) {
	private := testKey(t)
	peer := testKey(t).PublicKey()
	port := 51820
	config := &ConfigFile{
		Interface: IfaceConfig{
			PrivateKey: private.String(),
			Address:    []string{"10.44.0.1/24"},
			ListenPort: &port,
		},
		Peers: []PeerConfig{{PublicKey: peer.String(), AllowedIPs: []string{"10.44.0.2/32"}}},
	}

	rendered := config.String()

	if strings.Contains(rendered, private.String()) {
		t.Errorf("the private key is part of the rendered config:\n%s", rendered)
	}
	if !strings.Contains(rendered, redactedValue) {
		t.Errorf("the rendered config does not say that something was left out:\n%s", rendered)
	}
	// still useful: everything that is not secret is there
	for _, want := range []string{"10.44.0.1/24", "51820", peer.String()} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the rendered config is missing %q:\n%s", want, rendered)
		}
	}
	// and the config itself is untouched by rendering it
	if config.Interface.PrivateKey != private.String() {
		t.Error("String() changed the configuration it rendered")
	}
}

// wg-quick refuses to work with a config file others can read, because of the
// private key in it. This one says so.
func TestReadConfigWarnsAboutAReadableFile(t *testing.T) {
	// a peer section is not optional: mapping the file fails without one
	contents := "[Interface]\nPrivateKey = " + testKey(t).String() + "\nAddress = 10.44.0.1/24\n\n" +
		"[Peer]\nPublicKey = " + testKey(t).PublicKey().String() + "\nAllowedIPs = 10.44.0.2/32\n"

	for _, tc := range []struct {
		name string
		mode os.FileMode
		warn bool
	}{
		{"only the owner", 0o600, false},
		{"everybody", 0o644, true},
		{"the group", 0o640, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				// chmod there sets the read-only attribute and nothing else,
				// so every file reads back as 0666 - see readableByOthers
				t.Skip("file modes do not say who may read a file on Windows")
			}

			hook := logrustest.NewGlobal()
			defer hook.Reset()

			path := filepath.Join(t.TempDir(), "wg0.conf")
			if err := os.WriteFile(path, []byte(contents), tc.mode); err != nil {
				t.Fatal(err)
			}
			// WriteFile applies the umask, so say it again
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}

			if _, err := ReadConfig(path); err != nil {
				t.Fatalf("ReadConfig: %v", err)
			}

			warned := false
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, path) {
					warned = true
				}
			}
			if warned != tc.warn {
				t.Errorf("warned = %v, want %v for mode %04o", warned, tc.warn, tc.mode)
			}
		})
	}
}

// A library has no business ending the process of whoever called it.
func TestNewKeyPairReportsFailureInstead(t *testing.T) {
	pair, err := NewKeyPair()
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	private, err := wgtypes.ParseKey(pair.PrivateKey)
	if err != nil {
		t.Fatalf("the private key is not one: %v", err)
	}
	if private.PublicKey().String() != pair.PublicKey {
		t.Error("the public key does not belong to the private key")
	}
}
