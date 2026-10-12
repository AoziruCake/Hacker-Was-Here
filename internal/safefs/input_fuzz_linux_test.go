//go:build linux

package safefs

import (
	"errors"
	"strings"
	"testing"
)

func mountinfoFuzzTarget() snapshot {
	target := snapshot{}
	target.stat.Mnt_id = 36
	target.stat.Dev_major = 0
	target.stat.Dev_minor = 32
	return target
}

func FuzzRelativePathValidation(f *testing.F) {
	for _, seed := range []string{
		"note.txt",
		"etc/motd",
		"",
		"/absolute",
		"../outside",
		"a//b",
		"a\x00b",
		strings.Repeat("a", 4096),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		accepted := relativeOK(path)
		if !accepted {
			return
		}
		if path == "" || len(path) >= 4096 || strings.IndexByte(path, 0) >= 0 ||
			strings.HasPrefix(path, "/") {
			t.Fatalf("accepted invalid relative path %q", path)
		}
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." {
				t.Fatalf("accepted invalid component %q in %q", part, path)
			}
		}
	})
}

func FuzzMountinfoParsing(f *testing.F) {
	f.Add([]byte("36 25 0:32 / /synthetic ro,nodev,nosuid,noexec - ext4 /dev/sda ro\n"))
	f.Add([]byte("36 25 0:32 / /synthetic ro,nodev,nosuid,noexec - xfs /dev/sda ro\n"))
	f.Add([]byte(""))
	f.Add([]byte("not mountinfo"))
	f.Add([]byte("36 25 0:32 / /synthetic rw,nodev,nosuid,noexec - ext4 /dev/sda rw\n"))
	f.Add([]byte("36 25 0:32 / /bad\\escape ro,nodev,nosuid,noexec - ext4 /dev/sda ro\n"))

	target := mountinfoFuzzTarget()

	f.Fuzz(func(t *testing.T, data []byte) {
		fsType, err := mountType(data, target)
		if err == nil {
			if fsType != "ext4" {
				t.Fatalf("accepted unsupported filesystem %q", fsType)
			}
			return
		}
		if !errors.Is(err, ErrEnvironment) && !errors.Is(err, ErrMount) {
			t.Fatalf("unexpected error classification: %v", err)
		}
	})
}

func TestMountinfoFuzzSeedsAcceptSupportedFilesystems(t *testing.T) {
	target := mountinfoFuzzTarget()
	line := "36 25 0:32 / /synthetic ro,nodev,nosuid,noexec - ext4 /dev/sda ro\n"
	got, err := mountType([]byte(line), target)
	if err != nil || got != "ext4" {
		t.Fatalf("ext4 seed: got %q, %v", got, err)
	}
}

func TestMountinfoRejectsXFS(t *testing.T) {
	target := mountinfoFuzzTarget()
	line := "36 25 0:32 / /synthetic ro,nodev,nosuid,noexec - xfs /dev/sda ro\n"
	if _, err := mountType([]byte(line), target); !errors.Is(err, ErrMount) {
		t.Fatalf("error = %v, want %v", err, ErrMount)
	}
}

func TestMountinfoFuzzSeedRejectsMissingProtection(t *testing.T) {
	target := mountinfoFuzzTarget()
	line := "36 25 0:32 / /synthetic rw,nodev,nosuid,noexec - ext4 /dev/sda rw\n"
	if _, err := mountType([]byte(line), target); !errors.Is(err, ErrMount) {
		t.Fatalf("error = %v, want %v", err, ErrMount)
	}
}
