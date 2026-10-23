//go:build linux

package enforcementunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func ReadBackend(path string) (*Backend, error) { return ReadBackendForInstance(path, "") }

// ReadBackendForInstance adds a durable namespace only when explicitly requested
// in protected operator configuration. Instance is the immutable Pod UID supplied
// by the downward API, never a workload name or execution request.
func ReadBackendForInstance(path, instance string) (*Backend, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 16384 {
		return nil, fmt.Errorf("untrusted enforcer configuration")
	}
	var c struct {
		Socket, Name, Revision, CgroupRoot, CgroupMount, StateRoot string
		NamespaceState                                             bool
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("configuration trailing data")
	}
	for _, v := range []string{c.Socket, c.Name, c.Revision, c.StateRoot} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("incomplete enforcer configuration")
		}
	}
	if (c.CgroupRoot == "") == (c.CgroupMount == "") {
		return nil, fmt.Errorf("choose exactly one cgroup root or delegated mount")
	}
	if c.NamespaceState {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`).MatchString(instance) {
			return nil, fmt.Errorf("immutable state instance required")
		}
		c.StateRoot = filepath.Join(c.StateRoot, instance)
	}
	selectedRoot := c.CgroupRoot
	if c.CgroupMount != "" {
		selectedRoot = c.CgroupMount
	}
	for _, path := range []string{c.Socket, selectedRoot, c.StateRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("clean absolute ownership paths required")
		}
	}
	if c.CgroupMount != "" {
		c.CgroupRoot, err = delegatedCgroup(c.CgroupMount)
		if err != nil {
			return nil, err
		}
	}
	return &Backend{Connection: Connection{Socket: c.Socket}, Name: c.Name, Revision: c.Revision, CgroupRoot: c.CgroupRoot, StateRoot: c.StateRoot}, nil
}

// Resolve the kernel-visible root of this container, not a host sibling. Host
// cgroup paths are discovery data, not identity: compare device/inode and then
// require our own membership. Bounded walk never follows symlinks. The mount is
// a trusted operator projection and is not exposed to governed UID/GIDs.
func delegatedCgroup(mount string) (string, error) {
	if !filepath.IsAbs(mount) || filepath.Clean(mount) != mount {
		return "", fmt.Errorf("absolute cgroup mount required")
	}
	var root, visible unix.Stat_t
	if e := unix.Stat("/sys/fs/cgroup", &visible); e != nil {
		return "", e
	}
	if e := unix.Lstat(mount, &root); e != nil {
		return "", e
	}
	if root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != 0 {
		return "", fmt.Errorf("trusted cgroup mount required")
	}
	var fsstat unix.Statfs_t
	if e := unix.Statfs(mount, &fsstat); e != nil {
		return "", e
	}
	if fsstat.Type != unix.CGROUP2_SUPER_MAGIC {
		return "", fmt.Errorf("cgroup2 mount required")
	}
	var found string
	count := 0
	stop := errors.New("found exact root")
	err := filepath.WalkDir(mount, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > 16384 {
			return fmt.Errorf("cgroup discovery bound exceeded")
		}
		if !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if st.Dev == visible.Dev && st.Ino == visible.Ino {
			found = path
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("container cgroup root not projected")
	}
	raw, e := os.ReadFile(filepath.Join(found, "cgroup.procs"))
	if e != nil {
		return "", e
	}
	member := false
	for _, v := range strings.Fields(string(raw)) {
		if v == strconv.Itoa(os.Getpid()) {
			member = true
		}
	}
	if !member {
		return "", fmt.Errorf("supervisor not in discovered cgroup")
	}
	child := filepath.Join(found, "orka-executions")
	if e = os.Mkdir(child, 0700); e != nil && !os.IsExist(e) {
		return "", e
	}
	var st unix.Stat_t
	if e = unix.Lstat(child, &st); e != nil {
		return "", e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0077 != 0 {
		return "", fmt.Errorf("unsafe delegated execution root")
	}
	return child, nil
}
