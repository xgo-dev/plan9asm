package main

import (
	"errors"
	"testing"
	"time"
)

func TestDiscoveryFileRetriesAreBoundedAndPreserveErrors(t *testing.T) {
	temporary := errors.New("temporary sharing violation")
	permanent := errors.New("permanent filesystem failure")
	for _, test := range []struct {
		name     string
		failures int
		terminal error
	}{
		{name: "immediate success"},
		{name: "transient success", failures: 3},
		{name: "permanent error", terminal: permanent},
		{name: "transient then permanent", failures: 2, terminal: permanent},
		{name: "deadline", failures: 10000, terminal: temporary},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(0, 0)
			start := now
			calls, sleeps := 0, 0
			err := retryDiscoveryFileOperation(func() error {
				calls++
				if calls <= test.failures {
					return temporary
				}
				return test.terminal
			}, func(err error) bool {
				return errors.Is(err, temporary)
			}, func() time.Time {
				return now
			}, func(delay time.Duration) {
				if delay <= 0 || delay > 64*time.Millisecond {
					t.Fatalf("unbounded retry delay %s", delay)
				}
				sleeps++
				now = now.Add(delay)
			})
			if !errors.Is(err, test.terminal) {
				t.Fatalf("error = %v, want %v", err, test.terminal)
			}
			if test.name == "deadline" {
				if elapsed := now.Sub(start); elapsed != 2*time.Second || calls >= test.failures {
					t.Fatalf("retry bound: elapsed=%s calls=%d", elapsed, calls)
				}
			} else if calls != test.failures+1 || sleeps != test.failures {
				t.Fatalf("calls=%d sleeps=%d, want %d/%d", calls, sleeps, test.failures+1, test.failures)
			}
		})
	}
}
