package gotoolprofile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundedMachineCommandPreservesStdoutStderrAndExit(t *testing.T) {
	stdout, stderr, err := runCommandFixture(context.Background(), "json")
	if err != nil || string(stdout) != "{\"selected\":true}" || string(stderr) != "go: downloading fixture\n" {
		t.Fatalf("machine output stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	stdout, stderr, err = runCommandFixture(context.Background(), "exit")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || string(stdout) != "machine partial" || string(stderr) != "actual diagnostic" || !strings.Contains(err.Error(), "actual diagnostic") {
		t.Fatalf("actual exit/output was lost: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
}

func TestBoundedMachineCommandRejectsOverflowAndDeadline(t *testing.T) {
	stdout, _, err := runCommandFixture(context.Background(), "overflow")
	if err == nil || !strings.Contains(err.Error(), "output bound") || len(stdout) != commandOutputLimit {
		t.Fatalf("overflow was accepted: length=%d err=%v", len(stdout), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err = runCommandFixture(ctx, "deadline")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was lost: %v", err)
	}
}

func runCommandFixture(ctx context.Context, mode string) ([]byte, []byte, error) {
	return RunBounded(ctx, "", append(os.Environ(), "PLAN9ASM_MACHINE_FIXTURE="+mode), os.Args[0], "-test.run=^TestBoundedMachineFixture$")
}

func TestBoundedMachineFixture(t *testing.T) {
	switch os.Getenv("PLAN9ASM_MACHINE_FIXTURE") {
	case "":
		return
	case "json":
		fmt.Fprint(os.Stdout, "{\"selected\":true}")
		fmt.Fprint(os.Stderr, "go: downloading fixture\n")
	case "exit":
		fmt.Fprint(os.Stdout, "machine partial")
		fmt.Fprint(os.Stderr, "actual diagnostic")
		os.Exit(7)
	case "overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", commandOutputLimit+1))
	case "deadline":
		time.Sleep(time.Second)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func TestCaptureRejectsMissingCommandLifetime(t *testing.T) {
	if _, err := Capture(nil, "", "", nil, "linux/amd64", nil, RunBounded); err == nil {
		t.Fatal("nil lifetime was accepted")
	}
	if _, err := Capture(context.Background(), "", "", nil, "linux/amd64", nil, nil); err == nil {
		t.Fatal("nil command runner was accepted")
	}
}

func TestBoundedMachineActualGoToolRoutes(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range [][2]string{{"darwin", "amd64"}, {"linux", "386"}} {
		env := append(os.Environ(), "GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=0", "GOTOOLCHAIN=local")
		for _, tool := range []string{"vet", "nm"} {
			t.Run(target[0]+"-"+target[1]+"/"+tool, func(t *testing.T) {
				for repeat := 0; repeat < 16; repeat++ {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					stdout, stderr, err := RunBounded(ctx, "", env, goBinary, "tool", "-n", tool)
					cancel()
					path := strings.TrimSpace(string(stdout))
					if err != nil || len(stderr) != 0 || !filepath.IsAbs(path) || strings.Contains(path, "\n") {
						t.Fatalf("actual route %d: stdout=%q stderr=%q err=%v", repeat, stdout, stderr, err)
					}
					if _, err := os.Stat(path); err != nil {
						t.Fatalf("actual subtool route is absent: %v", err)
					}
				}
			})
		}
	}
}
