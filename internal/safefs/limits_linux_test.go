//go:build linux

package safefs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func TestBoundedReadsAndCompleteHashes(t *testing.T) {
	for _, size := range []int{0, MaxFile - 1, MaxFile, MaxFile + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			rel, path := mutableNote(t)
			payload := make([]byte, size)
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			r := fixtureRoot(t)
			read := r.calls.read
			bytesRead := 0
			r.calls.read = func(fd int, p []byte) (int, error) {
				n, e := read(fd, p)
				if n > 0 {
					bytesRead += n
				}
				return n, e
			}
			got, err := r.Read(context.Background(), rel)
			if bytesRead > MaxFile {
				t.Fatalf("read past budget: %d", bytesRead)
			}
			if size >= MaxFile {
				// The prototype fails closed when EOF needs another byte of budget.
				expectEmpty(t, got, err, ErrLimit)
				if size > MaxFile && bytesRead != 0 {
					t.Fatal("oversize file read")
				}
			} else if err != nil || len(got.Data) != size || got.SHA256 != fmt.Sprintf("%x", sha256.Sum256(payload)) {
				t.Fatalf("incomplete/wrong hash: size=%d, %v", len(got.Data), err)
			}
		})
	}
}
