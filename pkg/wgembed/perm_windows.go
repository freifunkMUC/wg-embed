//go:build windows
// +build windows

package wgembed

import "io/fs"

// readableByOthers has no answer on Windows. Who may read a file is decided by
// its ACL; the mode Go reports is made up from the read-only attribute, so
// every file looks like 0666 and a mode check would warn about all of them -
// and tell the reader to run chmod, which is not a thing here. Silence beats a
// warning nobody can act on.
func readableByOthers(fs.FileInfo) bool {
	return false
}
