//go:build linux

package safefs

import (
	"context"
	"os"
	"testing"
)

func TestF01ReadPinnedRegularFile(t *testing.T) {
	rootPath := os.Getenv("HWH_TEST_ROOT")
	if rootPath == "" {
		t.Fatal("run through the Docker fixture harness: HWH_TEST_ROOT required")
	}
	r, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.Read(context.Background(), "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "abc" {
		t.Fatalf("unexpected data: %q", got.Data)
	}
	if got.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("wrong complete hash: %s", got.SHA256)
	}
}
