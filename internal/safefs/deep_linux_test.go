//go:build linux

package safefs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestDeepReadBudgetAndCancellation(t *testing.T) {
	r, err := OpenRoot(os.Getenv("HWH_TEST_ROOT") + "/deep-small")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	budget := &ReadBudget{Used: MaxDeepTotalRead - 3, Limit: MaxDeepTotalRead}
	_, origins, err := r.VisitDeep(context.Background(), budget, func(Entry) bool { return true }, func(Entry) error { return nil })
	if !errors.Is(err, ErrReadBudget) || budget.Used != MaxDeepTotalRead-3 {
		t.Fatalf("deep budget: used=%d err=%v", budget.Used, err)
	}
	if len(origins) != 1 || origins[0].Status != "incomplete" {
		t.Fatalf("deep origins after budget: %#v", origins)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, origins, err = r.VisitDeep(ctx, &ReadBudget{Limit: MaxDeepTotalRead}, nil, func(Entry) error { return nil })
	if !errors.Is(err, context.Canceled) || len(origins) != 1 || origins[0].Status != "incomplete" {
		t.Fatalf("deep cancellation: origins=%#v err=%v", origins, err)
	}

	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, origins, err = r.VisitDeep(deadline, &ReadBudget{Limit: MaxDeepTotalRead}, nil, func(Entry) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || len(origins) != 1 || origins[0].Status != "incomplete" {
		t.Fatalf("deep deadline: origins=%#v err=%v", origins, err)
	}
}
