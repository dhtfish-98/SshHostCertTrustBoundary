package hosttrust

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
)

// FileAudit appends one JSON decision per line. The caller controls the parent
// directory; existing symlinks or files visible to other users are rejected.
type FileAudit struct {
	Path string
	mu   sync.Mutex
}

func (a *FileAudit) Record(d Decision) error {
	if a == nil || a.Path == "" {
		return errors.New("audit path is required")
	}
	line, err := json.Marshal(d)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("audit file must be regular and owner-only")
	}
	n, err := f.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return f.Sync()
}
