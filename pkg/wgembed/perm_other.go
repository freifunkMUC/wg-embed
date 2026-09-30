//go:build !windows
// +build !windows

package wgembed

import "io/fs"

// readableByOthers reports whether anybody but the owner may read the file.
// The config holds a private key, so this is worth a word of warning.
func readableByOthers(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o077 != 0
}
