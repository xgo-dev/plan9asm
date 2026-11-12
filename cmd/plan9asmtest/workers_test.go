package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestShardWorkersBoundedAndEveryTaskCollected(t *testing.T) {
	plan := make([]shardResult, 40)
	for index := range plan {
		plan[index] = shardResult{Index: index, Status: "pending"}
	}
	started := make(chan int, len(plan))
	release := make(chan struct{})
	var active, maximum atomic.Int32
	collected := make(map[int]bool)
	closed := make(chan error, 1)
	go func() {
		closed <- runShardWorkers(context.Background(), 2, plan,
			func(ctx context.Context, result shardResult) shardResult {
				count := active.Add(1)
				defer active.Add(-1)
				for previous := maximum.Load(); count > previous; previous = maximum.Load() {
					if maximum.CompareAndSwap(previous, count) {
						break
					}
				}
				started <- result.Index
				<-release
				result.Status = "passed"
				return result
			}, func(result shardResult) error {
				if collected[result.Index] {
					return fmt.Errorf("task %d collected twice", result.Index)
				}
				collected[result.Index] = true
				return nil
			})
	}()
	for owner := 0; owner < 2; owner++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			<-closed
			t.Fatal("two independent workers did not start")
		}
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || maximum.Load() != 2 || len(collected) != len(plan) {
		t.Fatalf("worker ownership changed: active=%d max=%d collected=%d", active.Load(), maximum.Load(), len(collected))
	}
	for _, result := range plan {
		if result.Status != "pending" || !collected[result.Index] {
			t.Fatal("worker mutated or omitted an immutable plan value", result)
		}
	}
}

func TestShardWorkerPublicationFailureWaitsForActiveOwners(t *testing.T) {
	plan := []shardResult{{Index: 0}, {Index: 1}}
	entered := make(chan struct{})
	cleaned := make(chan struct{})
	publicationErr := errors.New("original publication failure")
	err := runShardWorkers(context.Background(), 2, plan,
		func(ctx context.Context, result shardResult) shardResult {
			if result.Index == 0 {
				<-entered
				return result
			}
			close(entered)
			<-ctx.Done()
			close(cleaned)
			return result
		}, func(result shardResult) error {
			return publicationErr
		})
	if !errors.Is(err, publicationErr) {
		t.Fatalf("publication failure was hidden: %v", err)
	}
	select {
	case <-cleaned:
	default:
		t.Fatal("returned while an active owner retained its resources")
	}
}

func TestShardWorkersCanceledScopeNeverExecutes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	execute := func(context.Context, shardResult) shardResult {
		t.Error("canceled scope started an executor")
		return shardResult{}
	}
	record := func(shardResult) error {
		t.Error("canceled scope invented a receipt")
		return nil
	}
	if err := runShardWorkers(ctx, 2, []shardResult{{Index: 0}}, execute, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation became success: %v", err)
	}
	for _, workers := range []int{-1, 0, 33} {
		if err := runShardWorkers(context.Background(), workers, nil, execute, record); err == nil {
			t.Fatalf("unbounded worker count %d accepted", workers)
		}
	}
	if _, err := ciPrepare(config{Workers: 2}); err == nil || !strings.Contains(err.Error(), "serial") {
		t.Fatalf("selected CI silently acquired a different execution plan: %v", err)
	}
}
