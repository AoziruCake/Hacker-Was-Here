//go:build linux

package safefs

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

// Exercise the traversal API used by scan; injection stays at the OS boundary.
func TestBodyScanStopsAndClosesOnFailure(t *testing.T) {
	for _, mode := range []string{"reopen", "type", "inode", "device", "mount", "mtime", "ctime", "size", "nlink", "flags", "cancel", "panic", "budget-mutation"} {
		t.Run(mode, func(t *testing.T) {
			r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/scan-small")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			calls := r.calls
			pin, body := -1, -1
			readStarted := false
			r.calls.reopen = func(d, p, f int) (int, error) {
				if f&unix.O_DIRECTORY != 0 {
					return calls.reopen(d, p, f)
				}
				pin = p
				if mode == "reopen" {
					return -1, unix.EIO
				}
				var e error
				body, e = calls.reopen(d, p, f)
				return body, e
			}
			r.calls.snapshot = func(fd int) (snapshot, error) {
				s, e := calls.snapshot(fd)
				if fd == body {
					switch mode {
					case "type":
						s.stat.Mode = unix.S_IFIFO
					case "inode":
						s.stat.Ino++
					case "device":
						s.stat.Dev_minor++
					case "mount":
						s.stat.Mnt_id++
					}
					if readStarted {
						switch mode {
						case "mtime":
							s.stat.Mtime.Sec++
						case "ctime":
							s.stat.Ctime.Sec++
						case "size", "budget-mutation":
							s.stat.Size++
						case "nlink":
							s.stat.Nlink++
						case "flags":
							s.fs.Flags &^= unix.ST_RDONLY
						}
					}
				}
				return s, e
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget := &ReadBudget{}
			if mode == "budget-mutation" {
				budget.Used = MaxTotalRead - 4
			}
			r.calls.read = func(fd int, b []byte) (int, error) {
				if _, e := inspect(pin); e != nil {
					t.Fatal("pin dead during read", e)
				}
				readStarted = true
				if mode == "cancel" {
					cancel()
				}
				if mode == "panic" {
					panic("synthetic")
				}
				if mode == "budget-mutation" {
					for i := range b {
						b[i] = 'x'
					}
					return len(b), nil
				}
				return calls.read(fd, b)
			}
			visited := 0
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				_, _, err = r.VisitQuick(ctx, budget, func(Entry) bool { return true }, func(e Entry) error {
					visited++
					if e.Body.SHA256 != "" || len(e.Body.Data) != 0 {
						t.Fatal("unvalidated body escaped")
					}
					return nil // Even a visitor ignoring the error must not continue.
				})
			}()
			if mode == "panic" {
				if !panicked {
					t.Fatal("panic seam not reached")
				}
			} else {
				if err == nil || visited != 1 {
					t.Fatalf("did not stop: %v, visits=%d", err, visited)
				}
				if mode == "budget-mutation" && !errors.Is(err, ErrTargetChanged) {
					t.Fatalf("mutation masked by budget: %v", err)
				}
			}
			for _, fd := range []int{pin, body} {
				if fd >= 0 {
					if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(e, unix.EBADF) {
						t.Fatal("FD leak", fd, e)
					}
				}
			}
			if budget.Used > MaxTotalRead {
				t.Fatal("read budget exceeded")
			}
		})
	}
}

func TestBodyScanBudgetRejectsBeforeReopen(t *testing.T) {
	r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/scan-small")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reopen := r.calls.reopen
	r.calls.reopen = func(d, p, f int) (int, error) {
		if f&unix.O_DIRECTORY == 0 {
			t.Fatal("body opened without EOF budget")
		}
		return reopen(d, p, f)
	}
	budget := &ReadBudget{Used: MaxTotalRead - 3}
	_, err = r.VisitRootBodies(context.Background(), budget, func(Entry) bool { return true }, func(e Entry) error { return nil })
	if !errors.Is(err, ErrReadBudget) || budget.Used != MaxTotalRead-3 {
		t.Fatal(err, budget)
	}
}
