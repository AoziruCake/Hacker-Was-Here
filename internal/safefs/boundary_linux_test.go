//go:build linux

package safefs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func expectEmpty(t *testing.T, got Result, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || len(got.Data) != 0 || got.SHA256 != "" {
		t.Fatalf("want %v and empty result; got %+v, %v", want, got, err)
	}
}

func TestF01RejectOutsidePaths(t *testing.T) {
	r := fixtureRoot(t)
	for _, p := range []string{"../outside/note.txt", os.Getenv("HWH_TEST_OUTSIDE") + "/note.txt", "dir/../../outside/note.txt"} {
		got, err := r.Read(context.Background(), p)
		expectEmpty(t, got, err, ErrExcluded)
	}
}

func TestF03MountBoundaries(t *testing.T) {
	r := fixtureRoot(t)
	for _, p := range []string{"bind/note.txt", "otherfs/missing"} {
		got, err := r.Read(context.Background(), p)
		expectEmpty(t, got, err, ErrExcluded)
	}
}

func TestF04SpecialFilesNeverReopened(t *testing.T) {
	r := fixtureRoot(t)
	r.calls.reopen = func(int, int, int) (int, error) { t.Fatal("special file body open"); return -1, unix.EIO }
	for _, p := range []string{"fifo", "socket", "char", "block"} {
		got, err := r.Read(context.Background(), p)
		expectEmpty(t, got, err, ErrSpecial)
	}
}

func TestF05HardlinksAndDirectory(t *testing.T) {
	r := fixtureRoot(t) // root directory nlink > 1 is accepted.
	for _, p := range []string{"hard-a", "hard-b", "external-hard"} {
		got, err := r.Read(context.Background(), p)
		expectEmpty(t, got, err, ErrHardlink)
	}
	// An unlinked pin is observable at the agreed OS boundary.
	real := r.calls.snapshot
	r.calls.snapshot = func(fd int) (snapshot, error) {
		s, e := real(fd)
		if fd != r.fd {
			s.stat.Nlink = 0
		}
		return s, e
	}
	r.calls.reopen = func(int, int, int) (int, error) { t.Fatal("hardlink body open"); return -1, unix.EIO }
	got, err := r.Read(context.Background(), "note.txt")
	expectEmpty(t, got, err, ErrHardlink)
}

func TestF06PermissionNotBypassed(t *testing.T) {
	r := fixtureRoot(t)
	got, err := r.Read(context.Background(), "unreadable")
	expectEmpty(t, got, err, ErrPermission)
}

func mutableNote(t *testing.T) (relative, writable string) {
	t.Helper()
	base := os.Getenv("HWH_TEST_WRITABLE")
	if base == "" {
		t.Fatal("writable synthetic fixture alias required")
	}
	dir, err := os.MkdirTemp(base, "race-")
	if err != nil {
		t.Fatal(err)
	}
	writable = filepath.Join(dir, "note")
	if err = os.WriteFile(writable, []byte("ORIGINAL_PIN"), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Base(dir) + "/note", writable
}

func TestF07PathReplacementDoesNotRedirectRead(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "regular"} {
		t.Run(kind, func(t *testing.T) {
			rel, path := mutableNote(t)
			r := fixtureRoot(t)
			reopen := r.calls.reopen
			r.calls.reopen = func(dir, pin, flags int) (int, error) {
				if err := os.Rename(path, path+".held"); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(os.Getenv("HWH_TEST_OUTSIDE")+"/note.txt", path)
				case "fifo":
					err = unix.Mkfifo(path, 0600)
				case "regular":
					err = os.WriteFile(path, []byte("REPLACEMENT_CANARY"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				return reopen(dir, pin, flags)
			}
			var observed strings.Builder
			read := r.calls.read
			r.calls.read = func(fd int, p []byte) (int, error) {
				n, e := read(fd, p)
				if n > 0 {
					observed.Write(p[:n])
				}
				return n, e
			}
			got, err := r.Read(context.Background(), rel)
			if err == nil {
				if string(got.Data) != "ORIGINAL_PIN" {
					t.Fatalf("redirected: %+v", got)
				}
			} else if len(got.Data) > 0 || got.SHA256 != "" {
				t.Fatal("partial result on change")
			}
			if s := observed.String(); s != "" && s != "ORIGINAL_PIN" {
				t.Fatalf("read replacement: %q", s)
			}
		})
	}
}

func TestF08ReopenFailureHasNoFallback(t *testing.T) {
	r := fixtureRoot(t)
	opens, reads := 0, 0
	r.calls.reopen = func(int, int, int) (int, error) { opens++; return -1, unix.EIO }
	r.calls.read = func(int, []byte) (int, error) { reads++; return 0, unix.EIO }
	got, err := r.Read(context.Background(), "note.txt")
	if err == nil || len(got.Data) > 0 || got.SHA256 != "" || opens != 1 || reads != 0 {
		t.Fatalf("fallback: %+v %v opens=%d reads=%d", got, err, opens, reads)
	}
}

func TestF09DescriptorLifetime(t *testing.T) {
	r := fixtureRoot(t)
	// Warm runtime poll state before counting process descriptors.
	if _, err := r.Read(context.Background(), "note.txt"); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		entries, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			t.Fatal(e)
		}
		return len(entries)
	}
	baseline := count()
	for _, mode := range []string{"success", "cancel", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				calls := realCalls()
				pin, body := -1, -1
				r.calls = calls
				r.calls.reopen = func(dir, p, flags int) (int, error) {
					pin = p
					if _, e := inspect(pin); e != nil {
						t.Fatal("pin closed before reopen", e)
					}
					fd, e := calls.reopen(dir, p, flags)
					body = fd
					return fd, e
				}
				ctx, cancel := context.WithCancel(context.Background())
				r.calls.read = func(fd int, b []byte) (int, error) {
					if _, e := inspect(pin); e != nil {
						t.Fatal("pin not alive during read", e)
					}
					switch mode {
					case "cancel":
						cancel()
					case "error":
						return 0, unix.EIO
					case "panic":
						panic("injected boundary panic")
					}
					return calls.read(fd, b)
				}
				panicked := false
				func() {
					defer func() {
						if recover() != nil {
							panicked = true
						}
					}()
					got, err := r.Read(ctx, "note.txt")
					if mode == "success" && err != nil {
						t.Fatal(err)
					}
					if mode != "success" && (err == nil || len(got.Data) > 0 || got.SHA256 != "") {
						t.Fatalf("unexpected result: %+v %v", got, err)
					}
				}()
				cancel()
				if panicked != (mode == "panic") {
					t.Fatal("wrong panic behavior")
				}
				for _, fd := range []int{pin, body} {
					if fd < 0 {
						t.Fatal("boundary not exercised")
					}
					if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(e, unix.EBADF) {
						t.Fatal("descriptor leaked", fd, e)
					}
				}
			}
			if got := count(); got != baseline {
				t.Fatalf("FD count %d -> %d", baseline, got)
			}
		})
	}
	r.calls = realCalls()
	// A second Close must not close a newly reused descriptor number.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	sentinel, e := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(sentinel)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, e = unix.FcntlInt(uintptr(sentinel), unix.F_GETFD, 0); e != nil {
		t.Fatal("double close", e)
	}
}

func TestF10ReopenedIdentityMismatchReadsNothing(t *testing.T) {
	for _, field := range []string{"type", "device", "inode", "mount"} {
		t.Run(field, func(t *testing.T) {
			r := fixtureRoot(t)
			body := -1
			reopen := r.calls.reopen
			r.calls.reopen = func(d, p, f int) (int, error) { var e error; body, e = reopen(d, p, f); return body, e }
			inspectFD := r.calls.snapshot
			r.calls.snapshot = func(fd int) (snapshot, error) {
				s, e := inspectFD(fd)
				if fd == body {
					switch field {
					case "type":
						s.stat.Mode = unix.S_IFIFO
					case "device":
						s.stat.Dev_minor++
					case "inode":
						s.stat.Ino++
					case "mount":
						s.stat.Mnt_id++
					}
				}
				return s, e
			}
			reads := 0
			r.calls.read = func(int, []byte) (int, error) { reads++; return 0, unix.EIO }
			got, err := r.Read(context.Background(), "note.txt")
			expectEmpty(t, got, err, ErrTargetChanged)
			if reads != 0 {
				t.Fatal("read before identity check")
			}
		})
	}
}

func TestF11PinnedDirectoryMoved(t *testing.T) {
	rel, path := mutableNote(t)
	sub := strings.TrimSuffix(rel, "/note")
	r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/" + sub)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	moved := filepath.Join(os.Getenv("HWH_TEST_OUTSIDE"), sub)
	if err = os.Rename(filepath.Dir(path), moved); err != nil {
		t.Fatal(err)
	}
	got, err := r.Read(context.Background(), "note")
	expectEmpty(t, got, err, ErrTargetChanged)
	t.Log("Observed directory metadata change; no claim of global location consistency")
}

func TestF12BoundedEAGAIN(t *testing.T) {
	r := fixtureRoot(t)
	attempts := 0
	r.calls.openat2 = func(_ int, p string, h *unix.OpenHow) (int, error) {
		attempts++
		want := uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC)
		if p != "note.txt" || h.Flags != want || h.Resolve != resolveInside {
			t.Fatal("weakened retry protection", fmt.Sprint(h))
		}
		return -1, unix.EAGAIN
	}
	got, err := r.Read(context.Background(), "note.txt")
	expectEmpty(t, got, err, ErrTargetChanged)
	if attempts != 3 {
		t.Fatalf("attempts=%d", attempts)
	}
}
