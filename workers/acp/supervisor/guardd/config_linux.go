//go:build linux

package guardd

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
)

// ReadBackend consumes only trusted root-owned startup configuration. No Task
// or policy can supply endpoints, key paths, backend order or revision.
func ReadBackend(path string) (*Backend, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, fmt.Errorf("backend configuration must be root-owned and not writable by others")
	}
	var c struct{ Socket, Issuer, DaemonBoot, PrivateKeyFile, ReceiptKeyFile, Name, Revision, NodeID, ObjectDigest, CgroupRoot, StateRoot string }
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("backend config trailing content")
	}
	for _, v := range []string{c.Socket, c.Issuer, c.DaemonBoot, c.PrivateKeyFile, c.ReceiptKeyFile, c.Name, c.Revision, c.NodeID, c.ObjectDigest, c.CgroupRoot, c.StateRoot} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("incomplete backend configuration")
		}
	}
	key, err := readKey(c.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(c.ReceiptKeyFile)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}
	receipt, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Ed25519 receipt key required")
	}
	return &Backend{Connection: Connection{Socket: c.Socket, Issuer: c.Issuer, DaemonBoot: c.DaemonBoot, Private: key, Receipt: receipt}, Name: c.Name, Revision: c.Revision, NodeID: c.NodeID, ObjectDigest: c.ObjectDigest, CgroupRoot: c.CgroupRoot, StateRoot: c.StateRoot}, nil
}
