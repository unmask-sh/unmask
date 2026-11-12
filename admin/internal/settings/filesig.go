package settings

import (
	"fmt"
	"os"
	"syscall"

	"gopkg.in/yaml.v3"
)

// FileSignature names the file at path as it is now: its modification time,
// its size and its inode.  A save replaces the file by rename, so the inode
// moves even when a second write lands in the same clock tick with the same
// length; an edit in place moves the time or the size.  "" when the file
// cannot be read (it is gone, or mid-rename on a filesystem that shows the
// gap).  The daemon's config watch compares two of these; nothing is parsed.
func FileSignature(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return ""
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	return fmt.Sprintf("%d:%d:%d", fi.ModTime().UnixNano(), fi.Size(), ino)
}

// SavedYAML is s as Save would write it, without the comments Save carries
// over: the same normalization, then the encoder.  Two settings that give
// the same text here are the same settings -- what the config watch asks
// before it treats a touched or re-commented file as a change.
func SavedYAML(s Settings) (string, error) {
	normalizeDefaults(&s)
	body, err := yaml.Marshal(&s)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
