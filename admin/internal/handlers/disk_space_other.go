//go:build !linux

package handlers

// diskFreeBytes: non-Linux stub.  unmask's release targets are Linux; on other
// platforms the retention tab simply omits the disk-free / fill projection.
func diskFreeBytes(string) int64 { return 0 }
