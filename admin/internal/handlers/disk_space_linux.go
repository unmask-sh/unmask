//go:build linux

package handlers

import "syscall"

// diskFreeBytes returns the bytes available to unprivileged writers on the
// filesystem containing path, or 0 when it cannot be determined.  Feeds the
// retention tab's disk-fill projection (sqlite installs only — the DB file
// lives on a local filesystem there).
func diskFreeBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
