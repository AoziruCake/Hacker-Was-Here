//go:build linux

package safefs

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestQuickDirectoryChangeAndCleanup(t *testing.T) {
	for _, mode := range []string{"queued-version", "move", "reopen", "cancel", "panic"} {
		t.Run(mode, func(t *testing.T) {
			r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/quick-small")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			beforeFDs, _ := os.ReadDir("/proc/self/fd")
			calls := r.calls
			pin, seen := -1, 0
			r.calls.openat2 = func(d int, p string, h *unix.OpenHow) (int, error) {
				fd, e := calls.openat2(d, p, h)
				if p == "home/alice" && e == nil {
					seen++
					if seen == 2 {
						pin = fd
					}
				}
				return fd, e
			}
			r.calls.snapshot = func(fd int) (snapshot, error) {
				s, e := calls.snapshot(fd)
				if mode == "queued-version" && pin >= 0 && fd == pin {
					s.stat.Ino++
				}
				return s, e
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			moved := false
			original := os.Getenv("HWH_TEST_WRITABLE") + "/quick-small/home/alice"
			defer func() {
				if moved {
					if e := os.Rename(original+"-moved", original); e != nil {
						t.Fatal(e)
					}
				}
			}()
			r.calls.reopen = func(d, p, f int) (int, error) {
				if pin >= 0 && p == pin {
					switch mode {
					case "move":
						if e := os.Rename(original, original+"-moved"); e != nil {
							t.Fatal(e)
						}
						moved = true
					case "reopen":
						return -1, unix.EIO
					case "cancel":
						cancel()
					case "panic":
						panic("synthetic directory interruption")
					}
				}
				return calls.reopen(d, p, f)
			}
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				_, _, err = r.VisitQuick(ctx, &ReadBudget{}, nil, func(Entry) error { return nil })
			}()
			want := ErrTargetChanged
			if mode == "reopen" {
				want = ErrIO
			}
			if mode == "cancel" {
				want = context.Canceled
			}
			if seen != 2 || (mode == "panic" && !panicked) || (mode != "panic" && !errors.Is(err, want)) {
				t.Fatalf("mode=%s seen=%d panic=%v err=%v", mode, seen, panicked, err)
			}
			afterFDs, _ := os.ReadDir("/proc/self/fd")
			if len(beforeFDs) != len(afterFDs) {
				t.Fatalf("descriptor leak: %d -> %d", len(beforeFDs), len(afterFDs))
			}
		})
	}
}

func TestQuickObservedOriginDisappearanceIsNotMissingPreset(t *testing.T) {
	r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/quick-small")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	calls := r.calls
	r.calls.openat2 = func(d int, p string, h *unix.OpenHow) (int, error) {
		if p == "home" {
			return -1, unix.ENOENT
		}
		return calls.openat2(d, p, h)
	}
	_, origins, err := r.VisitQuick(context.Background(), &ReadBudget{}, nil, func(Entry) error { return nil })
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("observed origin vanished: %v", err)
	}
	for _, o := range origins {
		if o.Path == "home" && o.Status != "incomplete" {
			t.Fatalf("lost origin reported as %s", o.Status)
		}
		if o.Path == "opt" && o.Status != "not_started" {
			t.Fatalf("later origin reported as %s", o.Status)
		}
	}
}
