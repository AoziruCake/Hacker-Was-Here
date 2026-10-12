//go:build linux

package safefs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Result contains data/hash only after EOF and successful post-read checks.
type Result struct {
	Data   []byte
	SHA256 string
}

const MaxTotalRead = 64 << 20
const MaxDeepTotalRead = 512 << 20

var ErrReadBudget = errors.New("total_read_bytes")

// ReadBudget charges actual returned bytes, including reads later discarded.
// A budget is owned by one serialized traversal. Limit is zero for the quick
// default and may only select the documented deep limit.
type ReadBudget struct {
	Used, Limit int
	ceiling     int
}

func (b *ReadBudget) maximum() int {
	limit := MaxTotalRead
	if b.Limit == MaxDeepTotalRead {
		limit = b.Limit
	}
	if b.ceiling > 0 && b.ceiling < limit {
		return b.ceiling
	}
	return limit
}

func (r *Root) Read(ctx context.Context, relative string) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	empty := Result{}
	if r.fd < 0 {
		return empty, ErrInvariant
	}
	if !relativeOK(relative) {
		return empty, ErrExcluded
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := r.revalidateRoot(); err != nil {
		return empty, err
	}
	pin, err := r.pin(r.fd, relative, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, resolveInside)
	if err != nil {
		return empty, err
	}
	defer unix.Close(pin)
	before, err := r.calls.snapshot(pin)
	if err != nil {
		return empty, err
	}
	return r.readPinned(ctx, pin, before, &ReadBudget{})
}

// Caller keeps pin alive and holds r.mu through the read and post-checks.
func (r *Root) readPinned(ctx context.Context, pin int, before snapshot, budget *ReadBudget) (result Result, err error) {
	empty := Result{}
	if before.stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return empty, ErrExcluded
	}
	if before.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return empty, ErrSpecial
	}
	if before.stat.Nlink != 1 {
		return empty, ErrHardlink
	}
	if before.stat.Size >= MaxFile {
		return empty, ErrLimit
	}
	if budget == nil || budget.Used < 0 || (budget.Limit != 0 && budget.Limit != MaxDeepTotalRead) || budget.Used > budget.maximum() {
		return empty, ErrInvariant
	}
	if budget.Used > budget.maximum() {
		return empty, ErrInvariant
	}
	if before.stat.Size >= uint64(budget.maximum()-budget.Used) {
		return empty, ErrReadBudget
	}
	if err = r.allowed(before); err != nil {
		return empty, ErrEnvironmentChanged
	}
	fd, err := r.calls.reopen(r.fdDir, pin, unix.O_RDONLY)
	if err != nil {
		return empty, classify(err)
	}
	defer func() {
		if unix.Close(fd) != nil {
			result, err = empty, ErrInvariant
		}
	}()
	opened, err := r.calls.snapshot(fd)
	if err != nil {
		return empty, err
	}
	if err = r.validateSnapshot(before, opened); err != nil {
		return empty, err
	}
	data := make([]byte, 0, int(before.stat.Size))
	buf := make([]byte, 32*1024)
	var stopped error
	for {
		if err = ctx.Err(); err != nil {
			stopped = err
			break
		}
		remaining := min(MaxFile-len(data), budget.maximum()-budget.Used)
		// Fail closed at the exact byte budget if EOF has not been observed.
		// No extra byte is read merely to decide whether an input grew.
		if remaining == 0 {
			stopped = ErrLimit
			if budget.Used == budget.maximum() {
				stopped = ErrReadBudget
			}
			break
		}
		take := len(buf)
		if take > remaining {
			take = remaining
		}
		n, readErr := r.calls.read(fd, buf[:take])
		if n < 0 && readErr == nil || n > take {
			return empty, ErrInvariant
		}
		if n > 0 {
			budget.Used += n
			data = append(data, buf[:n]...)
		}
		if readErr == unix.EINTR {
			continue
		}
		if readErr != nil {
			stopped = classify(readErr)
			break
		}
		if n == 0 {
			break
		}
	}
	after, err := r.calls.snapshot(fd)
	if err != nil {
		return empty, err
	}
	if !sameVersion(before, after) || stopped == nil && uint64(len(data)) != after.stat.Size {
		return empty, ErrTargetChanged
	}
	if err = r.allowed(after); err != nil {
		return empty, ErrEnvironmentChanged
	}
	if err = r.revalidateRoot(); err != nil {
		return empty, err
	}
	if stopped != nil {
		return empty, stopped
	}
	digest := sha256.Sum256(data)
	return Result{Data: data, SHA256: fmt.Sprintf("%x", digest)}, nil
}
