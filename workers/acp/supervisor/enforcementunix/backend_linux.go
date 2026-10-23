//go:build linux

package enforcementunix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Backend must be instantiated from trusted supervisor configuration only.
// StateRoot is inside the existing supervisor identity-state directory.
// CgroupRoot must be root-owned cgroup-v2, outside any child-writable subtree.
type Backend struct {
	Connection                            Connection
	Name, Revision, CgroupRoot, StateRoot string
	mu                                    sync.Mutex
	retirement                            *retirementIO // nil uses real filesystem; private fault-injection seam
}

func (b *Backend) Identity() string { return b.Name + "@" + b.Revision }
func (b *Backend) Support(ctx context.Context, r *harnessv2.ExecutionRequirement, target string) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	result, err := b.Connection.call(ctx, "assess", "", requirement(r), nil, nil)
	if err != nil {
		return false, err
	}
	var yes bool
	if err := json.Unmarshal(result["supported"], &yes); err != nil {
		return false, err
	}
	return yes, nil
}

func (b *Backend) Launch(ctx context.Context, r harnessv2.CreateRuntimeSessionRequest) (acp.LaunchEnforcer, error) {
	if r.Requirement == nil {
		return nil, fmt.Errorf("mandatory requirement missing")
	}
	if !filepath.IsAbs(b.CgroupRoot) || !filepath.IsAbs(b.StateRoot) {
		return nil, fmt.Errorf("absolute enforcer ownership roots required")
	}
	// Conservative recovery: unfinished associations are not adopted. A caller
	// must explicitly retire them before creating a fresh governed target.
	if err := os.MkdirAll(b.StateRoot, 0700); err != nil {
		return nil, err
	}
	r.Requirement = r.Requirement.Clone()
	l := &launch{backend: b, request: r}
	l.observe(ctx, "selected", nil)
	return l, nil
}

type launch struct {
	observationMu      sync.Mutex
	observation        acp.LaunchEnforcementStatus
	observationContext context.Context
	observedProcess    *acp.Process
	backend            *Backend
	request            harnessv2.CreateRuntimeSessionRequest
	mu                 sync.Mutex
	generation         uint64
	record             *association
}

// The observation lock is independent of activation/cleanup I/O. Status must
// remain readable while a required backend is blocked or unavailable.
func (l *launch) observe(ctx context.Context, phase string, target map[string]any) {
	identity := ""
	if l.request.Requirement != nil {
		identity = l.request.Requirement.Identity
	}
	status := acp.LaunchEnforcementStatus{Backend: l.backend.Identity(), RequirementIdentity: identity, TargetGeneration: l.generation, Phase: phase}
	if target != nil {
		data, _ := json.Marshal(target) // target consists solely of JSON-safe identity scalars
		sum := sha256.Sum256(data)
		status.TargetIdentity = "sha256:" + hex.EncodeToString(sum[:])
	}
	l.observationMu.Lock()
	l.observation, l.observationContext = status, ctx
	l.observationMu.Unlock()
}
func (l *launch) EnforcementStatus() acp.LaunchEnforcementStatus {
	l.observationMu.Lock()
	defer l.observationMu.Unlock()
	status := l.observation
	released := false
	if status.Phase == "active" && l.observedProcess != nil {
		switch l.observedProcess.LaunchState() {
		case "released":
			released = true
		case "stopping":
			status.Phase = "stopping"
		case "stopped":
			status.Phase = "stopped"
		}
	}
	// Initialization uses a short-lived context, cancelled after a successful
	// handshake. Its later cancellation is not workload cancellation. Before
	// release, however, cancellation must never display current active execution.
	if !released && l.observationContext != nil && l.observationContext.Err() != nil {
		switch status.Phase {
		case "selected", "preparing", "activating", "active":
			status.Phase = "cancelled"
		}
	}
	return status
}

type association struct {
	Backend     string                          `json:"backend"`
	Binding     map[string]any                  `json:"binding"`
	Target      map[string]any                  `json:"target"`
	Requirement *harnessv2.ExecutionRequirement `json:"requirement"`
	Cgroup      string                          `json:"cgroup"`
	Phase       string                          `json:"phase"`
	Evidence    []byte                          `json:"evidence,omitempty"`
	Journal     string                          `json:"-"`
	FD          int                             `json:"-"`
	Retirement  *retirementCheckpoint           `json:"retirement,omitempty"`
}

func persist(a *association) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.Journal+".pending", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(a.Journal+".pending", a.Journal); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(a.Journal))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (l *launch) Prepare(ctx context.Context, cfg *acp.ProcessConfig) (resultErr error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.backend
	if l.record != nil {
		return fmt.Errorf("prior target cleanup unfinished")
	}
	// Invalidate a prior activation before attempting a replacement, even if
	// preparation fails before a new target can be allocated.
	l.generation++
	l.observe(ctx, "preparing", nil)
	defer func() {
		if resultErr != nil {
			l.observe(ctx, "failed", nil)
		}
	}()
	if cfg.UID == 0 || cfg.GID == 0 {
		return fmt.Errorf("governed child must be non-root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	material := fmt.Sprintf("%s/%s/%d/%d", l.request.RuntimeSessionID, l.request.Metadata.OperationID, l.generation, time.Now().UnixNano())
	sum := sha256.Sum256([]byte(material))
	id := hex.EncodeToString(sum[:])
	path := filepath.Join(b.CgroupRoot, id)
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	binding := map[string]any{"operation": id, "request": l.request.Metadata.RequestDigest, "generation": l.generation, "fence": jsonMap(l.request.Metadata.Fence)}
	a := &association{Backend: b.Identity(), Binding: binding, Requirement: l.request.Requirement.Clone(), Cgroup: path, Phase: "preparing", Journal: filepath.Join(b.StateRoot, id+".json"), FD: fd}
	l.record = a
	if err = persist(a); err != nil {
		// Keep record reachable even if durability is unavailable. No process starts.
		return err
	}
	cfg.CgroupFD = fd
	cfg.BeforeExec = func(ctx context.Context, p *acp.Process) (activationErr error) {
		defer func() {
			if activationErr != nil {
				l.observe(ctx, "failed", a.Target)
			}
		}()
		l.observationMu.Lock()
		l.observedProcess = p
		l.observationMu.Unlock()
		p.SetEnforcementCleanup(func(ctx context.Context) error { return l.cleanup(ctx, a) })
		pidfd := p.PidFD()
		if pidfd < 0 {
			return fmt.Errorf("held process pidfd missing")
		}
		pid := p.PID()
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return err
		}
		parts := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
		if len(parts) < 20 {
			return fmt.Errorf("target start unavailable")
		}
		var cg unix.Stat_t
		if err = unix.Fstat(fd, &cg); err != nil {
			return err
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
		if err != nil {
			return err
		}
		var mount uint64
		for _, line := range strings.Split(string(info), "\n") {
			if strings.HasPrefix(line, "mnt_id:") {
				mount, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			}
		}
		ns, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(ns)
		var nsstat unix.Stat_t
		if err = unix.Fstat(ns, &nsstat); err != nil {
			return err
		}
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return err
		}
		a.Target = map[string]any{"pid": pid, "start": parts[19], "boot": strings.TrimSpace(string(boot)), "cgroup": map[string]any{"dev": cg.Dev, "ino": cg.Ino, "mount_id": mount, "cgroup_id": cg.Ino}, "netns": nsstat.Ino, "generation": l.generation}
		a.Phase = "activating"
		l.observe(ctx, "activating", a.Target)
		if err = persist(a); err != nil {
			return err
		}
		result, err := b.Connection.call(ctx, "activate", operation(a), requirement(a.Requirement), a.Target, []int{fd, pidfd, ns})
		if err != nil {
			return err
		}
		if err := exactBound(result, a, "active"); err != nil {
			return err
		}
		a.Evidence, err = json.Marshal(result)
		if err != nil {
			return err
		}
		a.Phase = "active"
		if err = persist(a); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		l.observe(ctx, "active", a.Target)
		// This callback never writes the release pipe. RuntimeSession alone does so.
		return nil
	}
	return nil
}
func (l *launch) cleanup(ctx context.Context, a *association) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observe(context.Background(), "cleanup-pending", a.Target)
	if a.Retirement == nil {
		if a.Phase == "local-retirement" {
			return fmt.Errorf("local retirement proof missing")
		}
		a.Phase = "cleanup-pending"
		if err := persist(a); err != nil {
			return err
		}
		// Capture the retained target handle before enforcement retirement. The
		// checkpoint is never derived from a later pathname lookup.
		checkpoint, err := newRetirementCheckpoint(a)
		if err != nil {
			return err
		}
		if a.Target != nil {
			result, err := l.backend.Connection.call(ctx, "retire", operation(a), requirement(a.Requirement), a.Target, []int{a.FD})
			if err != nil {
				return err
			}
			if err := exactBound(result, a, "retired"); err != nil {
				return err
			}
		}
		a.Retirement = checkpoint
		a.Phase = "local-retirement"
	}
	// Always make the exact-binding proof durable BEFORE removing the target,
	// including retries after a failed checkpoint fsync. It is cleanup-only:
	// neither Prepare nor release consumes this checkpoint as activation proof.
	if err := validateRetirement(a); err != nil {
		return err
	}
	if err := persist(a); err != nil {
		return err
	}
	if err := l.backend.retireLocal(a); err != nil {
		return err
	}

	unix.Close(a.FD)
	l.record = nil
	l.observe(context.Background(), "cleaned", a.Target)
	return nil
}

func (l *launch) AbortPreparation(ctx context.Context) error {
	l.mu.Lock()
	a := l.record
	l.mu.Unlock()
	if a == nil {
		return nil
	}
	return l.cleanup(ctx, a)
}

// RetireUnfinished never adopts an active workload and never releases a helper.
// It uses the durable exact association, verifies the original cgroup inode,
// kills that target recursively and invokes only cleanup. A changed backend or
// changed target leaves the association visible for operator investigation.
func (b *Backend) RetireUnfinished(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries, err := os.ReadDir(b.StateRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return fmt.Errorf("unknown activation association %s", entry.Name())
		}
		journal := filepath.Join(b.StateRoot, entry.Name())
		fd, err := unix.Open(journal, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), journal)
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		if err != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 1<<20 {
			f.Close()
			return fmt.Errorf("untrusted activation association")
		}
		decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		var a association
		err = decoder.Decode(&a)
		if err == nil && decoder.Decode(&struct{}{}) != io.EOF {
			err = fmt.Errorf("activation association trailing data")
		}
		f.Close()
		if err != nil {
			return err
		}
		if a.Backend != b.Identity() || filepath.Dir(a.Cgroup) != b.CgroupRoot {
			return fmt.Errorf("recovery backend or target ownership changed")
		}
		a.Binding = jsonMap(a.Binding)
		if a.Target != nil {
			a.Target = jsonMap(a.Target)
		}
		a.Journal = journal
		a.FD = -1
		if a.Retirement != nil {
			l := &launch{backend: b, record: &a}
			if err = l.cleanup(ctx, &a); err != nil {
				return err
			}
			continue
		}
		if a.Phase == "local-retirement" {
			return fmt.Errorf("local retirement proof missing")
		}
		// A corrupt journal is cleanup uncertainty, not permission to panic,
		// signal compute, or rediscover an association from a reusable name.
		var claimed map[string]any
		if a.Target != nil {
			var ok bool
			claimed, ok = a.Target["cgroup"].(map[string]any)
			if !ok || claimed["dev"] == nil || claimed["ino"] == nil || a.Requirement == nil {
				return fmt.Errorf("incomplete retained target association")
			}
		}
		targetFD, err := unix.Open(a.Cgroup, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("recovery exact target unavailable: %w", err)
		}
		a.FD = targetFD
		if a.Target != nil {
			var cg unix.Stat_t
			err = unix.Fstat(targetFD, &cg)
			if err != nil {
				unix.Close(targetFD)
				return err
			}
			if string(encode(claimed["dev"])) != string(encode(cg.Dev)) || string(encode(claimed["ino"])) != string(encode(cg.Ino)) {
				unix.Close(targetFD)
				return fmt.Errorf("recovery cgroup identity changed")
			}
		}
		killFD, err := unix.Openat(targetFD, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			unix.Close(targetFD)
			return err
		}
		_, err = unix.Write(killFD, []byte("1"))
		unix.Close(killFD)
		if err != nil {
			unix.Close(targetFD)
			return err
		}
		for {
			raw, err := os.ReadFile(a.Cgroup + "/cgroup.events")
			if err != nil {
				unix.Close(targetFD)
				return err
			}
			if strings.Contains(string(raw), "populated 0") {
				break
			}
			select {
			case <-ctx.Done():
				unix.Close(targetFD)
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		l := &launch{backend: b, record: &a}
		if err = l.cleanup(ctx, &a); err != nil {
			unix.Close(targetFD)
			return err
		}
	}
	return nil
}

// retirementCheckpoint records completed enforcement teardown, not authority
// to run. The root-owned journal binds it to the complete immutable association
// and original kernel object. Missing/replaced objects without this proof remain
// uncertain and cannot be discarded during recovery.
type retirementCheckpoint struct {
	Association string `json:"association"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Boot        string `json:"boot"`
}

func retirementIdentity(a *association) string {
	data, _ := json.Marshal(struct {
		Backend         string
		Binding, Target map[string]any
		Requirement     *harnessv2.ExecutionRequirement
		Cgroup          string
	}{a.Backend, a.Binding, a.Target, a.Requirement, a.Cgroup})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func newRetirementCheckpoint(a *association) (*retirementCheckpoint, error) {
	var st unix.Stat_t
	if err := unix.Fstat(a.FD, &st); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	return &retirementCheckpoint{Association: retirementIdentity(a), Device: st.Dev, Inode: st.Ino, Boot: strings.TrimSpace(string(boot))}, nil
}
func validateRetirement(a *association) error {
	c := a.Retirement
	if c == nil || a.Phase != "local-retirement" || c.Association != retirementIdentity(a) || c.Inode == 0 {
		return fmt.Errorf("invalid exact local retirement checkpoint")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != c.Boot {
		return fmt.Errorf("retirement boot identity changed")
	}
	return nil
}

// Only local retirement I/O is injectable. enforcer authentication, target
// validation, checkpoint persistence and release authority are never bypassed.
type retirementIO struct {
	removeJournal func(string) error
	openParent    func(string) (*os.File, error)
	syncParent    func(*os.File) error
}

func (b *Backend) retireLocal(a *association) error {
	// A same-path replacement is NOT ours, even with a completed cleanup proof.
	fd, err := unix.Open(a.Cgroup, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		unix.Close(fd)
		if err != nil {
			return err
		}
		if st.Dev != a.Retirement.Device || st.Ino != a.Retirement.Inode {
			return fmt.Errorf("local retirement target replaced")
		}
		// rmdir independently refuses remaining descendants. Only ENOENT is safe.
		if err = os.Remove(a.Cgroup); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	remove, open, sync := os.Remove, os.Open, (*os.File).Sync
	if b.retirement != nil {
		if b.retirement.removeJournal != nil {
			remove = b.retirement.removeJournal
		}
		if b.retirement.openParent != nil {
			open = b.retirement.openParent
		}
		if b.retirement.syncParent != nil {
			sync = b.retirement.syncParent
		}
	}
	d, err := open(filepath.Dir(a.Journal))
	if err != nil {
		return err
	}
	defer d.Close()
	if err = remove(a.Journal); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = sync(d); err != nil {
		// Re-establish the visible checkpoint after an uncertain unlink commit.
		// Even if restoration fails, the caller retains ownership and reports both
		// errors; a crash with no journal is safe only because all resources are gone.
		return errors.Join(err, persist(a))
	}
	return nil
}
