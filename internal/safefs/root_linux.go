//go:build linux

// Package safefs provides the filesystem boundary and root preflight.
// It accepts only a caller-prepared read-only ext4 copy. It never mounts,
// executes, writes to, or repairs an input.
package safefs

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const MaxFile = 1 << 20
const resolveInside = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV
const requiredMountFlags = unix.ST_RDONLY | unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC

var (
	ErrRoot               = errors.New("invalid_root")
	ErrPrivilege          = errors.New("privileged_execution")
	ErrEnvironment        = errors.New("unsupported_environment")
	ErrMount              = errors.New("unsupported_mount")
	ErrExcluded           = errors.New("policy_excluded")
	ErrSpecial            = errors.New("special_file")
	ErrHardlink           = errors.New("hardlink_excluded")
	ErrPermission         = errors.New("permission_denied")
	ErrTargetChanged      = errors.New("target_changed")
	ErrEnvironmentChanged = errors.New("environment_changed")
	ErrLimit              = errors.New("file_size_limit")
	ErrInvariant          = errors.New("security_invariant_failed")
	ErrIO                 = errors.New("io_error")
)

type snapshot struct {
	stat unix.Statx_t
	fs   unix.Statfs_t
}

// kernelCalls is a single injection seam at the agreed safefs/OS boundary.
// There is no public injection option or permissive mount-validation switch.
type kernelCalls struct {
	openat2  func(int, string, *unix.OpenHow) (int, error)
	reopen   func(int, int, int) (int, error)
	snapshot func(int) (snapshot, error)
	read     func(int, []byte) (int, error)
}

func realCalls() kernelCalls {
	return kernelCalls{
		openat2: unix.Openat2,
		reopen: func(dir, pinned, flags int) (int, error) {
			return unix.Openat(dir, strconv.Itoa(pinned), flags|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
		},
		snapshot: inspect,
		read:     unix.Read,
	}
}

// Root owns its root/proc descriptors. Read and Close are serialized so a pin
// cannot be closed or reused while a read is in progress.
type Root struct {
	mu      sync.Mutex
	fd      int
	procFD  int
	selfFD  int
	fdDir   int
	initial snapshot
	fsType  string
	calls   kernelCalls
}

func classify(err error) error {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf("%w: %v", ErrPermission, err)
	case errors.Is(err, unix.EXDEV), errors.Is(err, unix.ELOOP):
		return fmt.Errorf("%w: %w", ErrExcluded, err)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.EAGAIN), errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %w", ErrTargetChanged, err)
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return fmt.Errorf("%w: %v", ErrEnvironment, err)
	default:
		return fmt.Errorf("%w: %w", ErrIO, err)
	}
}

// Failure to inspect trusted host metadata rejects the environment, while an
// actual I/O failure keeps the same classification as other inspection I/O.
func metadataFailure(err error) error {
	if errors.Is(err, ErrIO) {
		return err
	}
	return ErrEnvironment
}

func relativeOK(p string) bool {
	if p == "" || len(p) >= 4096 || strings.IndexByte(p, 0) >= 0 || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (r *Root) pin(dir int, name string, flags int, resolve uint64) (int, error) {
	// Two retries after the first attempt. Every attempt retains the same flags.
	for attempt := 0; attempt < 3; attempt++ {
		how := unix.OpenHow{Flags: uint64(flags), Resolve: resolve}
		fd, err := r.calls.openat2(dir, name, &how)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EAGAIN) || attempt == 2 {
			return -1, classify(err)
		}
	}
	return -1, ErrInvariant
}

func inspect(fd int) (snapshot, error) {
	var s snapshot
	mask := unix.STATX_BASIC_STATS | unix.STATX_MNT_ID
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, mask, &s.stat); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return s, ErrEnvironment
		}
		return s, classify(err)
	}
	if s.stat.Mask&uint32(mask) != uint32(mask) {
		return s, ErrEnvironment
	}
	var ordinary unix.Stat_t
	if err := unix.Fstat(fd, &ordinary); err != nil {
		return s, classify(err)
	}
	if s.stat.Ino != ordinary.Ino || uint64(ordinary.Size) != s.stat.Size ||
		uint32(ordinary.Mode) != uint32(s.stat.Mode) || uint64(s.stat.Nlink) != uint64(ordinary.Nlink) ||
		unix.Major(uint64(ordinary.Dev)) != s.stat.Dev_major || unix.Minor(uint64(ordinary.Dev)) != s.stat.Dev_minor {
		return s, ErrTargetChanged
	}
	if err := unix.Fstatfs(fd, &s.fs); err != nil {
		return s, classify(err)
	}
	return s, nil
}

func sameIdentity(a, b snapshot) bool {
	return a.stat.Ino == b.stat.Ino && a.stat.Dev_major == b.stat.Dev_major &&
		a.stat.Dev_minor == b.stat.Dev_minor && a.stat.Mnt_id == b.stat.Mnt_id &&
		a.stat.Mode&unix.S_IFMT == b.stat.Mode&unix.S_IFMT
}
func sameVersion(a, b snapshot) bool {
	return sameIdentity(a, b) && a.stat.Size == b.stat.Size && a.stat.Nlink == b.stat.Nlink &&
		a.stat.Mtime == b.stat.Mtime && a.stat.Ctime == b.stat.Ctime
}

func (r *Root) validateSnapshot(expected, actual snapshot) error {
	if !sameVersion(expected, actual) {
		return ErrTargetChanged
	}
	if r.allowed(actual) != nil {
		return ErrEnvironmentChanged
	}
	return nil
}

func (r *Root) allowed(s snapshot) error {
	if s.fs.Flags&requiredMountFlags != requiredMountFlags {
		return ErrMount
	}
	if s.stat.Mnt_id != r.initial.stat.Mnt_id ||
		s.stat.Dev_major != r.initial.stat.Dev_major || s.stat.Dev_minor != r.initial.stat.Dev_minor {
		return ErrExcluded
	}
	if r.fsType != "ext4" || s.fs.Type != unix.EXT4_SUPER_MAGIC {
		return ErrMount
	}
	return nil
}

func OpenRoot(absolute string) (root *Root, err error) {
	if !strings.HasPrefix(absolute, "/") || len(absolute) >= 4096 {
		return nil, ErrRoot
	}
	rel := strings.TrimSuffix(strings.TrimPrefix(absolute, "/"), "/")
	if !relativeOK(rel) {
		return nil, ErrRoot
	}
	// The prototype runs only in a trusted Linux test host; never drop privilege
	// inside the reader. The separate fixture harness does that before exec.
	u1, u2, u3 := unix.Getresuid()
	g1, g2, g3 := unix.Getresgid()
	if u1 == 0 || u1 != u2 || u2 != u3 || g1 != g2 || g2 != g3 {
		return nil, ErrPrivilege
	}
	r := &Root{fd: -1, procFD: -1, selfFD: -1, fdDir: -1, calls: realCalls()}
	defer func() {
		if root == nil || err != nil {
			if r.Close() != nil {
				err = ErrInvariant
			}
		}
	}()
	r.procFD, err = unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, metadataFailure(classify(err))
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(r.procFD, &fs); err != nil {
		return nil, metadataFailure(classify(err))
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrEnvironment
	}
	r.selfFD, err = r.pin(r.procFD, strconv.Itoa(os.Getpid()), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, resolveInside)
	if err != nil {
		return nil, metadataFailure(err)
	}
	r.fdDir, err = r.pin(r.selfFD, "fd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, resolveInside)
	if err != nil {
		return nil, metadataFailure(err)
	}
	status, err := r.metadata("status")
	if err != nil {
		return nil, err
	}
	if err = noCapabilities(status); err != nil {
		return nil, err
	}
	host, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, metadataFailure(classify(err))
	}
	defer func() {
		if unix.Close(host) != nil {
			err = ErrInvariant
		}
	}()
	r.fd, err = r.pin(host, rel, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, resolveInside&^unix.RESOLVE_NO_XDEV)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENAMETOOLONG) || errors.Is(err, ErrExcluded) {
			return nil, ErrRoot
		}
		return nil, err
	}
	r.initial, err = inspect(r.fd)
	if err != nil {
		return nil, err
	}
	hostStat, err := inspect(host)
	if err != nil {
		return nil, err
	}
	if r.initial.stat.Ino == hostStat.stat.Ino &&
		r.initial.stat.Dev_major == hostStat.stat.Dev_major && r.initial.stat.Dev_minor == hostStat.stat.Dev_minor {
		return nil, ErrRoot
	}
	mountinfo, err := r.metadata("mountinfo")
	if err != nil {
		return nil, err
	}
	r.fsType, err = mountType(mountinfo, r.initial)
	if err != nil {
		return nil, err
	}
	if err = r.allowed(r.initial); err != nil {
		return nil, err
	}
	dir, err := r.calls.reopen(r.fdDir, r.fd, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, classify(err)
	}
	defer func() {
		if unix.Close(dir) != nil {
			err = ErrInvariant
		}
	}()
	reopened, err := inspect(dir)
	if err != nil {
		return nil, err
	}
	if err = r.validateSnapshot(r.initial, reopened); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for _, fd := range []*int{&r.fd, &r.fdDir, &r.selfFD, &r.procFD} {
		if *fd >= 0 {
			if err := unix.Close(*fd); err != nil && first == nil {
				first = err
			}
			*fd = -1
		}
	}
	return first
}

// Revalidate reports observed root movement/attribute or mount changes.
// It cannot prove that a static copy is globally consistent.
func (r *Root) revalidateRoot() error {
	s, err := r.calls.snapshot(r.fd)
	if err != nil {
		return err
	}
	return r.validateSnapshot(r.initial, s)
}
