//go:build unix

package ownedprocess

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestOwnedGroupPermissionRequiresExitedMembership(t *testing.T) {
	const pgid = 4123
	for _, test := range []struct {
		name         string
		parentReaped bool
		members      []groupMember
		observeErr   error
		wantDone     bool
	}{
		{name: "reaped absent", parentReaped: true, wantDone: true},
		{name: "reaped zombie descendants", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}}, wantDone: true},
		{name: "zombie leader before wait", members: []groupMember{{PID: pgid, PGID: pgid, State: "Z"}, {PID: 4124, PGID: pgid, State: "Z+"}}},
		{name: "leader termination unknown"},
		{name: "leader missing with zombie descendant", members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}}},
		{name: "live leader", members: []groupMember{{PID: pgid, PGID: pgid, State: "S"}}},
		{name: "live descendant", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "R"}}},
		{name: "stopped descendant", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "T"}}},
		{name: "unknown state", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "?"}}},
		{name: "wrong group", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid + 1, State: "Z"}}},
		{name: "unknown pid", parentReaped: true, members: []groupMember{{PGID: pgid, State: "Z"}}},
		{name: "duplicate member", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}, {PID: 4124, PGID: pgid, State: "Z"}}},
		{name: "inaccessible membership", parentReaped: true, observeErr: syscall.EPERM},
		{name: "snapshot unavailable", parentReaped: true, observeErr: syscall.EIO},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := stopGroup(pgid, test.parentReaped, func(pid int, signal syscall.Signal) error {
				if pid != -pgid || signal != syscall.SIGKILL {
					t.Fatalf("unowned signal: %d %v", pid, signal)
				}
				return syscall.EPERM
			}, func(observed int) ([]groupMember, error) {
				calls++
				if observed != pgid {
					t.Fatalf("unowned observation: %d", observed)
				}
				return test.members, test.observeErr
			})
			wantCalls := 0
			if test.parentReaped {
				wantCalls = 1
				if test.wantDone {
					wantCalls = 2 // Independent terminal snapshots close membership races.
				}
			}
			if calls != wantCalls {
				t.Fatalf("permission result lacks a post-Wait membership check: got %d want %d", calls, wantCalls)
			}
			if test.wantDone {
				if !errors.Is(err, os.ErrProcessDone) {
					t.Fatalf("independently exited group rejected: %v", err)
				}
			} else if !errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("live/unknown/inaccessible group accepted: %v", err)
			}
		})
	}
}

func TestOwnedGroupRejectsBroadSignalTargets(t *testing.T) {
	for _, pgid := range []int{-1, 0, 1} {
		called := false
		err := stopGroup(pgid, true, func(int, syscall.Signal) error {
			called = true
			return nil
		}, nil)
		if err == nil || called {
			t.Fatalf("unowned broad target was signalled: %d %v", pgid, err)
		}
	}
}

func TestOwnedGroupOtherSignalOutcomesRemainExact(t *testing.T) {
	for _, signalErr := range []error{nil, syscall.ESRCH, syscall.EIO, syscall.EINVAL, syscall.EPERM} {
		err := stopGroup(4123, true, func(int, syscall.Signal) error { return signalErr }, nil)
		if signalErr == syscall.ESRCH {
			if !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("absent group: %v", err)
			}
		} else if err != signalErr {
			t.Fatalf("signal error changed: got %v want %v", err, signalErr)
		}
	}
}

func TestOwnedGroupSuccessfulSignalRequiresTerminalMembership(t *testing.T) {
	const pgid = 4123
	for _, row := range []struct {
		name       string
		states     [][]groupMember
		minimum    int
		observeErr error
	}{
		{name: "terminal members", states: [][]groupMember{{{PID: 4124, PGID: pgid, State: "Z"}}}, minimum: 2},
		{name: "signal delivery is asynchronous", states: [][]groupMember{
			{{PID: 4124, PGID: pgid, State: "S"}},
			{{PID: 4124, PGID: pgid, State: "Z"}},
		}, minimum: 3},
		{name: "new descendant requires another complete observation", states: [][]groupMember{
			{{PID: 4124, PGID: pgid, State: "Z"}},
			{{PID: 4124, PGID: pgid, State: "Z"}, {PID: 4125, PGID: pgid, State: "Z"}},
		}, minimum: 3},
		{name: "reused pid requires another complete observation", states: [][]groupMember{
			{{PID: 4124, PGID: pgid, State: "Z", Born: 100}},
			{{PID: 4124, PGID: pgid, State: "Z", Born: 200}},
		}, minimum: 3},
		{name: "live member exceeds the bounded join", states: [][]groupMember{{{PID: 4124, PGID: pgid, State: "R"}}}, minimum: 2},
		{name: "live then inaccessible", states: [][]groupMember{{{PID: 4124, PGID: pgid, State: "R"}}}, minimum: 2, observeErr: syscall.EACCES},
		{name: "unknown kernel state", states: [][]groupMember{{{PID: 4124, PGID: pgid, State: "?"}}}, minimum: 1},
		{name: "foreign group", states: [][]groupMember{{{PID: 4124, PGID: pgid + 1, State: "Z"}}}, minimum: 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			calls := 0
			err := stopGroup(pgid, true, func(pid int, signal syscall.Signal) error {
				if pid != -pgid || signal != syscall.SIGKILL {
					t.Fatalf("cleanup signalled a different group or invented success probe: %d %v", pid, signal)
				}
				return nil
			}, func(group int) ([]groupMember, error) {
				calls++
				if group != pgid {
					t.Fatal("observed another group", group)
				}
				index := calls - 1
				if index >= len(row.states) {
					if row.observeErr != nil {
						return nil, row.observeErr
					}
					index = len(row.states) - 1
				}
				return row.states[index], nil
			})
			if calls < row.minimum {
				t.Fatal("accepted signal returned without terminal kernel observations", calls, err)
			}
			wantDone := row.name == "terminal members" || row.name == "signal delivery is asynchronous" ||
				row.name == "new descendant requires another complete observation" ||
				row.name == "reused pid requires another complete observation"
			if wantDone != errors.Is(err, os.ErrProcessDone) || !wantDone && err == nil {
				t.Fatal("live, unknown, or unstable membership acquired terminal credit", err)
			}
			if row.observeErr != nil && !errors.Is(err, row.observeErr) {
				t.Fatal("membership failure was lost", err)
			}
		})
	}
}

func TestOwnedGroupAbsentFastPathDoesNotInspect(t *testing.T) {
	for _, row := range []struct {
		name         string
		parentReaped bool
		signalErr    error
	}{
		{name: "already absent", parentReaped: true, signalErr: syscall.ESRCH},
		{name: "parent still needs Wait"},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := stopGroup(4123, row.parentReaped, func(pid int, signal syscall.Signal) error {
				if pid != -4123 || signal != syscall.SIGKILL {
					t.Fatal("unexpected signal", pid, signal)
				}
				return row.signalErr
			}, func(int) ([]groupMember, error) {
				t.Fatal("empty fast path or pre-Wait cancellation scanned membership")
				return nil, syscall.EIO
			})
			if row.parentReaped && !errors.Is(err, os.ErrProcessDone) || !row.parentReaped && err != nil {
				t.Fatal("original command outcome changed", err)
			}
		})
	}
}
