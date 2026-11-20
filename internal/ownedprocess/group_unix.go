//go:build unix

package ownedprocess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ErrCleanup distinguishes descendant cleanup failures from the command exit.
var ErrCleanup = errors.New("owned command descendants")

type groupMember struct {
	PID   int
	PGID  int
	State string
	Born  uint64 // Linux starttime prevents reused PIDs matching a prior snapshot.
}

type groupObserver func(int) ([]groupMember, error)

// Run owns only this command's newly created process group. Both cancellation
// and ordinary parent exit stop descendants before the caller removes files.
func Run(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return stopGroup(command.Process.Pid, false, syscall.Kill, observeProcessGroup)
	}
	err := command.Run()
	if command.Process != nil {
		cleanup := stopGroup(command.Process.Pid, command.ProcessState != nil, syscall.Kill, observeProcessGroup)
		if cleanup != nil && !errors.Is(cleanup, os.ErrProcessDone) {
			err = errors.Join(err, fmt.Errorf("%w: %w", ErrCleanup, cleanup))
		}
	}
	return err
}

func stopGroup(pgid int, parentReaped bool, kill func(int, syscall.Signal) error, observe groupObserver) error {
	if pgid <= 1 {
		return fmt.Errorf("refuse an unowned process group: %d", pgid)
	}
	err := kill(-pgid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	if err != nil && !errors.Is(err, syscall.EPERM) || !parentReaped || observe == nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	var previous map[int]groupMember
	for {
		members, snapshotErr := observe(pgid)
		if snapshotErr != nil {
			return errors.Join(err, fmt.Errorf("inspect exited owned group: %w", snapshotErr))
		}
		seen := make(map[int]groupMember, len(members))
		terminal, stable := true, previous != nil && len(previous) == len(members)
		for _, member := range members {
			if member.PID <= 1 || member.PGID != pgid || seen[member.PID].PID != 0 || !validGroupState(member.State) {
				return errors.Join(err, fmt.Errorf("owned group membership is unknown"))
			}
			seen[member.PID] = member
			terminal = terminal && member.State[0] == 'Z'
			stable = stable && previous[member.PID] == member
		}
		if terminal && stable {
			// Zombies cannot fork or write files. Their outside-group parent,
			// not this owner, must reap them. Two complete terminal snapshots
			// also close a child forked during a non-atomic /proc traversal.
			return os.ErrProcessDone
		}
		if !terminal && err != nil || time.Now().After(deadline) {
			return errors.Join(err, fmt.Errorf("owned group still has a live or unstable member"))
		}
		previous = nil
		if terminal {
			previous = seen
		}
		<-tick.C
	}
}

func validGroupState(state string) bool {
	// Linux has additional live states (uninterruptible, tracing, idle).
	// None is terminal credit; only a validated Z record establishes exit.
	return validDarwinState(state) || len(state) == 1 && strings.ContainsRune("DtXxKWP", rune(state[0]))
}

func validDarwinState(state string) bool {
	if len(state) == 0 || !strings.ContainsRune("IRSTUZ", rune(state[0])) {
		return false
	}
	for _, modifier := range state[1:] {
		if !strings.ContainsRune("+<>AELNSsVWX", modifier) {
			return false
		}
	}
	return true
}
