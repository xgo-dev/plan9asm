package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedShiftCountObservationTransport(t *testing.T) {
	const witness = "COUNT_NATIVE_STATUS kernel=3 mod16=1 "
	const normal = witness + "wait=0 outcome=normal\n"
	const fault = witness + "wait=11 outcome=fault\n"
	const core = witness + "wait=139 outcome=fault\n"
	const diagnostic = "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
	for _, c := range []struct {
		name, output, want string
	}{
		{"normal", normal, "normal"},
		{"native_fault", fault, "fault"},
		{"native_core", core, "fault"},
		{"pinned_fault", diagnostic + fault, "fault"},
		{"pinned_core", diagnostic + core, "fault"},
		{"old_unbound_text", diagnostic + "fault\n", ""},
		{"bare_normal", "normal\n", ""},
		{"bare_fault", "fault\n", ""},
		{"wrong_kernel", strings.Replace(normal, "kernel=3", "kernel=2", 1), ""},
		{"wrong_address", strings.Replace(normal, "mod16=1", "mod16=0", 1), ""},
		{"wrong_signal", strings.Replace(diagnostic, "signal 11", "signal 4", 1) + fault, ""},
		{"wrong_wait", strings.Replace(fault, "wait=11", "wait=4", 1), ""},
		{"wrong_normal_wait", strings.Replace(normal, "wait=0", "wait=11", 1), ""},
		{"wrong_fault_wait", strings.Replace(fault, "wait=11", "wait=0", 1), ""},
		{"normal_with_fault", diagnostic + normal, ""},
		{"duplicate_witness", fault + fault, ""},
		{"duplicate_diagnostic", diagnostic + diagnostic + fault, ""},
		{"late_diagnostic", fault + diagnostic, ""},
		{"unknown_output", "unknown tool failure\n" + fault, ""},
		{"truncated_witness", witness + "nor", ""},
		{"missing_newline", strings.TrimSuffix(normal, "\n"), ""},
		{"overflow_output", strings.Repeat("a", 257) + normal, ""},
		{"empty", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := x86PackedShiftCountObservation(3, []byte(c.output), nil)
			if c.want == "" {
				if err == nil {
					t.Fatalf("unbound observer output accepted: %q", c.output)
				}
			} else if err != nil || got != c.want {
				t.Fatalf("bound observation: got %q, %v; want %q", got, err, c.want)
			}
		})
	}
	for _, kernel := range []int{-1, 6} {
		if _, err := x86PackedShiftCountObservation(kernel, []byte(normal), nil); err == nil {
			t.Fatalf("unknown original kernel accepted: %d", kernel)
		}
	}
	for _, err := range []error{context.DeadlineExceeded, errors.New("observer cleanup failed")} {
		if _, observed := x86PackedShiftCountObservation(3, []byte(normal), err); observed == nil {
			t.Fatalf("observer infrastructure failure was discarded: %v", err)
		}
	}
}

// The immutable first-party observer validates its child wait status before
// publishing this exact kernel/address/outcome witness. Only the pinned
// QEMU's exact SIGSEGV diagnostic may precede a matching fault witness; do
// not broadly remove emulator output or accept a normal result after it.
func x86PackedShiftCountObservation(kernel int, output []byte, commandErr error) (string, error) {
	if commandErr != nil {
		return "", commandErr
	}
	if kernel < 0 || kernel >= 6 || len(output) > 256 || !strings.HasSuffix(string(output), "\n") {
		return "", fmt.Errorf("unbound original count observation")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	diagnostic := false
	if len(lines) == 2 && lines[0] == "qemu: uncaught target signal 11 (Segmentation fault) - core dumped" {
		diagnostic = true
		lines = lines[1:]
	}
	if len(lines) != 1 {
		return "", fmt.Errorf("unexpected original count observer output: %q", output)
	}
	prefix := fmt.Sprintf("COUNT_NATIVE_STATUS kernel=%d mod16=1 ", kernel)
	switch lines[0] {
	case prefix + "wait=0 outcome=normal":
		if !diagnostic {
			return "normal", nil
		}
	case prefix + "wait=11 outcome=fault", prefix + "wait=139 outcome=fault":
		return "fault", nil
	}
	return "", fmt.Errorf("invalid original count status/kernel/address: %q", output)
}
