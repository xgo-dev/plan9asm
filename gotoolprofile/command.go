package gotoolprofile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const commandOutputLimit = 4 << 20

type boundedOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (output *boundedOutput) Bytes() []byte  { return output.buffer.Bytes() }
func (output *boundedOutput) String() string { return output.buffer.String() }

func (output *boundedOutput) Write(data []byte) (int, error) {
	count := len(data)
	remaining := commandOutputLimit - output.buffer.Len()
	if len(data) > remaining {
		output.overflow = true
		data = data[:remaining]
	}
	_, _ = output.buffer.Write(data)
	return count, nil
}

// RunBounded preserves machine-readable stdout, stderr and the actual exit.
// Only this invocation's fresh process group is subject to cancellation.
func RunBounded(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("machine command requires a live context")
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env, command.WaitDelay = dir, env, 2*time.Second
	var stdout, stderr boundedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	err := runOwnedCommand(command)
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, fmt.Errorf("machine command exceeded the explicit output bound"))
	}
	if err != nil {
		err = fmt.Errorf("%s: %w\nstdout:\n%s\nstderr:\n%s", name, err, stdout.String(), stderr.String())
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
