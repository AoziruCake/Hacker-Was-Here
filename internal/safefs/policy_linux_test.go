//go:build linux

package safefs

import (
	"context"
	"errors"
	"os"
	"testing"
)

func fixtureRoot(t *testing.T) *Root {
	t.Helper()
	p := os.Getenv("HWH_TEST_ROOT")
	if p == "" {
		t.Fatal("Docker fixture harness required")
	}
	r, err := OpenRoot(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestF02LinksArePolicyExcluded(t *testing.T) {
	r := fixtureRoot(t)
	for _, path := range []string{"out-link", "relative-link", "in-link", "ancestor-link/note.txt"} {
		t.Run(path, func(t *testing.T) {
			got, err := r.Read(context.Background(), path)
			if !errors.Is(err, ErrExcluded) || len(got.Data) != 0 || got.SHA256 != "" {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}
