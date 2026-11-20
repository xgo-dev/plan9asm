package main

import (
	"context"
	"fmt"
	"sync"
)

// Each task has its own artifacts and owned child process group. Publication
// stays on the caller's goroutine. On cancellation or publication failure,
// wait for every active executor to release its descendants before returning.
func runShardWorkers(
	parent context.Context,
	workers int,
	plan []shardResult,
	execute func(context.Context, shardResult) shardResult,
	record func(shardResult) error,
) error {
	if workers < 1 || workers > 32 {
		return fmt.Errorf("workers must be 1..32")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	jobs := make(chan shardResult, len(plan))
	for _, result := range plan {
		if result.Status != "empty" {
			jobs <- result
		}
	}
	close(jobs)
	results := make(chan shardResult, workers)
	var owners sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		owners.Add(1)
		go func() {
			defer owners.Done()
			for result := range jobs {
				if ctx.Err() != nil {
					return
				}
				result = execute(ctx, result)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		owners.Wait()
		close(results)
	}()

	var publicationErr error
	for result := range results {
		if publicationErr == nil {
			if err := record(result); err != nil {
				publicationErr = err
				cancel()
			}
		}
	}
	if publicationErr != nil {
		return publicationErr
	}
	return parent.Err()
}
