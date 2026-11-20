// Package goasmcmd owns bounded, machine-readable stock-Go commands. It has no
// dependency on the translator or its proof protocols.
package goasmcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type output struct {
	buffer   bytes.Buffer
	overflow bool
}

func (out *output) Len() int      { return out.buffer.Len() }
func (out *output) Bytes() []byte { return out.buffer.Bytes() }

func (out *output) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := 4<<20 - out.Len(); n > remaining {
		out.overflow = true
		data = data[:remaining]
	}
	_, _ = out.buffer.Write(data)
	return n, nil
}

// Observation retains the actual child outcome even when an independent
// cancellation, pipe or descendant-cleanup failure is joined to its exit.
// PGID identifies the owned group; it is not a claim that the group is gone.
type Observation struct {
	Stdout, Stderr []byte
	PID, PGID      int
	Waited         bool
	ExitCode       int
}

// Observe keeps the streams distinct and returns the unwrapped command cause.
// Unix implementations additionally terminate the fresh child's process group.
func Observe(ctx context.Context, dir string, env []string, name string, args ...string) (Observation, error) {
	observed := Observation{ExitCode: -1}
	if ctx == nil {
		return observed, fmt.Errorf("Go object command requires a live context")
	}
	if cause := ctx.Err(); cause != nil {
		return observed, errors.Join(fmt.Errorf("Go object command requires a live context"), cause)
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env, command.WaitDelay = dir, env, 2*time.Second
	var stdout, stderr output
	command.Stdout, command.Stderr = &stdout, &stderr
	err := run(command)
	if command.Process != nil {
		observed.PID = command.Process.Pid
		observed.PGID = configuredGroup(command)
	}
	if command.ProcessState != nil {
		observed.Waited = true
		observed.ExitCode = command.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, fmt.Errorf("Go object command output bound exceeded"))
	}
	observed.Stdout = append([]byte(nil), stdout.Bytes()...)
	observed.Stderr = append([]byte(nil), stderr.Bytes()...)
	return observed, err
}

// Run preserves the existing query contract: diagnostics are errors, and
// callers receive stdout only after the complete owned command succeeds.
func Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("Go object command requires a live context")
	}
	observed, err := Observe(ctx, dir, env, name, args...)
	if len(observed.Stderr) != 0 {
		err = errors.Join(err, fmt.Errorf("Go object command diagnostics: %s", observed.Stderr))
	}
	if err != nil {
		return nil, fmt.Errorf("actual Go %v: %w", args, err)
	}
	return observed.Stdout, nil
}
