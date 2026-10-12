//go:build linux

package safefs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var ErrEntryLimit = errors.New("enumeration_entries")

// Entry describes one pinned child. Names are raw bytes, never display paths.
type Entry struct {
	Name      string
	Kind      string
	Reason    string
	Size      uint64
	Mtime     *time.Time
	Body      Result
	BodyError error
	version   snapshot
}

func (r *Root) childEntry(ctx context.Context, name string, budget *ReadBudget, selectBody func(Entry) bool) (entry Entry, err error) {
	entry.Name = name
	fd, err := r.pin(r.fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, resolveInside)
	if err != nil {
		switch {
		case errors.Is(err, unix.EXDEV):
			entry.Reason = "mount_excluded"
		case errors.Is(err, unix.ELOOP):
			entry.Reason = "symlink_excluded"
		case errors.Is(err, ErrPermission):
			entry.Reason = "permission_denied"
		default:
			return entry, err
		}
		return entry, nil
	}
	defer func() {
		if unix.Close(fd) != nil {
			err = ErrInvariant
		}
	}()
	s, err := r.calls.snapshot(fd)
	if err != nil {
		return entry, err
	}
	if err = r.allowed(s); err != nil {
		return entry, ErrEnvironmentChanged
	}
	switch s.stat.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		entry.Reason = "symlink_excluded"
	case unix.S_IFDIR:
		entry.Kind = "directory"
		entry.version = s
		entry.Reason = "directory_not_scanned"
	case unix.S_IFREG:
		entry.Kind = "regular"
		entry.Size = s.stat.Size
		t := time.Unix(s.stat.Mtime.Sec, int64(s.stat.Mtime.Nsec)).UTC()
		if t.Year() >= 0 && t.Year() <= 9999 {
			entry.Mtime = &t
		}
		if s.stat.Nlink != 1 {
			entry.Reason = "hardlink_excluded"
		}
	default:
		entry.Reason = "special_file"
	}
	if entry.Kind == "regular" && entry.Reason == "" && selectBody != nil && selectBody(entry) {
		entry.Body, entry.BodyError = r.readPinned(ctx, fd, s, budget)
	}
	return entry, nil
}

// VisitRoot enumerates only root's immediate children, in batches of at most
// 256 names. The visitor must not call back into Root while its lock is held.
func (r *Root) VisitRoot(ctx context.Context, visit func(Entry) error) (count int, err error) {
	return r.VisitRootBodies(ctx, nil, nil, visit)
}

// VisitRootBodies reads selected regular children while their original pin is
// live. Visitors must not reenter Root; body errors must be handled by them.
func (r *Root) VisitRootBodies(ctx context.Context, budget *ReadBudget, selectBody func(Entry) bool, visit func(Entry) error) (count int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fd < 0 {
		return 0, ErrInvariant
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if err = r.revalidateRoot(); err != nil {
		return
	}
	fd, err := r.calls.reopen(r.fdDir, r.fd, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return 0, classify(err)
	}
	f := os.NewFile(uintptr(fd), "hwh-pinned-directory")
	if f == nil {
		unix.Close(fd)
		return 0, ErrInvariant
	}
	defer func() {
		if f.Close() != nil {
			err = ErrInvariant
		}
	}()
	opened, err := r.calls.snapshot(fd)
	if err != nil {
		return
	}
	if err = r.validateSnapshot(r.initial, opened); err != nil {
		return 0, err
	}
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		if err = r.revalidateRoot(); err != nil {
			return
		}
		if count == 20000 {
			return count, ErrEntryLimit
		}
		take := min(256, 20000-count)
		names, readErr := f.Readdirnames(take)
		if readErr != nil && readErr != io.EOF {
			return count, classify(readErr)
		}
		if err = ctx.Err(); err != nil {
			return
		}
		for _, name := range names {
			if err = ctx.Err(); err != nil {
				return
			}
			count++
			if !relativeOK(name) || strings.Contains(name, "/") {
				return count, ErrInvariant
			}
			entry, inspectErr := r.childEntry(ctx, name, budget, selectBody)
			if inspectErr != nil {
				return count, inspectErr
			}
			if err = visit(entry); err != nil {
				return
			}
			if entry.BodyError != nil && !errors.Is(entry.BodyError, ErrPermission) && !errors.Is(entry.BodyError, ErrLimit) {
				return count, entry.BodyError
			}
		}
		if err = r.revalidateRoot(); err != nil {
			return
		}
		if readErr == io.EOF {
			return count, nil
		}
		if readErr != nil {
			return count, classify(readErr)
		}
	}
}
