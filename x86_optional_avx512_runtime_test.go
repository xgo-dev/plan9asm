package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// This subprocess supplies a real process status, never an error-string stand-in.
func TestX86OptionalAVX512ExitFixture(t *testing.T) {
	value := os.Getenv("PLAN9ASM_AVX512_EXIT_FIXTURE")
	if value == "" {
		return
	}
	code, err := strconv.Atoi(value)
	if err != nil || code < 0 || code > 255 {
		t.Fatal("invalid fixture exit", value)
	}
	os.Exit(code)
}

func TestX86OptionalAVX512RuntimeRequiresMissingHardwareReceipt(t *testing.T) {
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestX86OptionalAVX512ExitFixture$")
	command.Env = append(os.Environ(), "PLAN9ASM_AVX512_EXIT_FIXTURE=78")
	_, unavailable := runtimeOracleCombinedOutput(ctx, command)
	if status, ok := unavailable.(*exec.ExitError); !ok || status.ExitCode() != 78 {
		t.Fatal("fixture did not produce an ordinary exit78", unavailable)
	}
	const missing = "original-floating profile=1 SSE2=1 AVX=1 OSXSAVE=1 AVX512F=0 AVX512VL=0 FMA=1 SSSE3=1 AVX2=1 XCR0=7\n"
	for _, code := range []int{0, 77, 79, 80, 81, 82, 255} {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestX86OptionalAVX512ExitFixture$")
		command.Env = append(os.Environ(), "PLAN9ASM_AVX512_EXIT_FIXTURE="+strconv.Itoa(code))
		_, err := runtimeOracleCombinedOutput(ctx, command)
		if x86OriginalFloatingRuntimeAllowsSkip("auto", 1, []byte(missing), err) {
			t.Fatal("non-capability process status became a skip", code)
		}
	}
	for _, profile := range []int{1, 2, 3, 4} {
		receipt := strings.Replace(missing, "profile=1", fmt.Sprintf("profile=%d", profile), 1)
		for _, mode := range []string{"", "required", "auto", "off", "AUTO"} {
			t.Run(fmt.Sprintf("profile%d/%s", profile, mode), func(t *testing.T) {
				if got := x86OriginalFloatingRuntimeAllowsSkip(mode, profile, []byte(receipt), unavailable); got != (mode == "auto") {
					t.Fatalf("missing CPU policy %q: skip=%t", mode, got)
				}
			})
		}
	}
	for _, test := range []struct {
		name, output string
		err          error
	}{
		{"success", missing, nil},
		{"error text", missing, errors.New("exit status 78")},
		{"timeout", missing, errors.Join(unavailable, context.DeadlineExceeded)},
		{"cancellation", missing, errors.Join(unavailable, context.Canceled)},
		{"cleanup", missing, errors.Join(unavailable, errors.New("cleanup failed"))},
		{"no receipt", "", unavailable},
		{"truncated", strings.TrimSuffix(missing, " XCR0=7\n"), unavailable},
		{"foreign profile", strings.Replace(missing, "profile=1", "profile=3", 1), unavailable},
		{"invalid feature", strings.Replace(missing, "AVX512F=0", "AVX512F=2", 1), unavailable},
		{"duplicate", missing + missing, unavailable},
		{"extra diagnostic", missing + "loader failed\n", unavailable},
		{"contradictory success", missing + "ORIGINAL_FLOATING_RUNTIME_CPU_OPCODES_OK\n", unavailable},
		{"capable host", strings.NewReplacer("AVX512F=0", "AVX512F=1", "AVX512VL=0", "AVX512VL=1", "XCR0=7", "XCR0=e7").Replace(missing), unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if x86OriginalFloatingRuntimeAllowsSkip("auto", 1, []byte(test.output), test.err) {
				t.Fatal("non-hardware failure became a runtime skip")
			}
		})
	}
	full := strings.NewReplacer("AVX512F=0", "AVX512F=1", "XCR0=7", "XCR0=e7").Replace(missing)
	if x86OriginalFloatingRuntimeAllowsSkip("auto", 1, []byte(full), unavailable) {
		t.Fatal("scalar conversion does not require AVX512VL")
	}
	for _, profile := range []int{2, 4} {
		receipt := strings.Replace(full, "profile=1", fmt.Sprintf("profile=%d", profile), 1)
		if !x86OriginalFloatingRuntimeAllowsSkip("auto", profile, []byte(receipt), unavailable) {
			t.Fatal("packed profile lost its actual AVX512VL requirement", profile)
		}
	}
	if !x86OriginalFloatingRuntimeAllowsSkip("auto", 1, []byte(strings.Replace(missing, "\n", "\r\n", 1)), unavailable) {
		t.Fatal("Windows receipt line ending rejected")
	}
	for _, profile := range []int{0, 7} {
		if x86OriginalFloatingRuntimeAllowsSkip("auto", profile, []byte(missing), unavailable) {
			t.Fatal("unknown profile became optional", profile)
		}
	}
	for _, profile := range []int{5, 6} {
		receipt := strings.Replace(missing, "profile=1", fmt.Sprintf("profile=%d", profile), 1)
		if x86OriginalFloatingRuntimeAllowsSkip("auto", profile, []byte(receipt), unavailable) {
			t.Fatal("explicit RCP14 native qualification became an optional hardware skip", profile)
		}
	}
}
