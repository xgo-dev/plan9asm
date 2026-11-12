package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The unchanged C parent validates every child's actual wait status before
// publishing stdout. QEMU diagnostics remain a separate, counted stream:
// neither missing children nor unrelated stderr may borrow that receipt.
func x86FMA3PortableAccessReceipt(stdout, stderr []byte, commandErr error, want string, faults int, emulated bool) error {
	if commandErr != nil {
		return commandErr
	}
	if faults < 0 || faults > 6*len(x86FMA3PortableAccessCases()) {
		return fmt.Errorf("invalid independent fault inventory")
	}
	if !bytes.Equal(stdout, []byte(want)) {
		return fmt.Errorf("incomplete portable access observation")
	}
	if !emulated {
		if len(stderr) != 0 {
			return fmt.Errorf("unexpected native access diagnostics")
		}
		return nil
	}
	const segmentation = "qemu: uncaught target signal 11 (Segmentation fault) - core dumped"
	const bus = "qemu: uncaught target signal 7 (Bus error) - core dumped"
	if len(stderr) > faults*(len(segmentation)+1) {
		return fmt.Errorf("excess guest-child diagnostics")
	}
	lines := strings.Split(string(stderr), "\n")
	if len(lines) != faults+1 || lines[len(lines)-1] != "" {
		return fmt.Errorf("incomplete guest-child fault inventory")
	}
	for _, line := range lines[:faults] {
		if line != segmentation && line != bus {
			return fmt.Errorf("unexpected guest-child fault diagnostic")
		}
	}
	return nil
}

func TestX86FMA3PortableAccessReceiptRetainsExactStreamsAndFaults(t *testing.T) {
	const want = "portable FMA dead-q: admitted=14 context=0 reference=98 translated=98\n"
	const diagnostic = "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
	const bus = "qemu: uncaught target signal 7 (Bus error) - core dumped\n"
	const faults = 66 // Eleven nonempty rows, three fault probes, two implementations.
	if len(x86FMA3PortableAccessCases()) != 14 {
		t.Fatal("complete original case inventory changed")
	}
	nonempty := 0
	for _, row := range x86FMA3PortableAccessCases() {
		if row.bytes != 0 {
			nonempty++
		}
	}
	if nonempty*3*2 != faults {
		t.Fatal("independent full reference/translated fault inventory changed")
	}
	for _, test := range []struct {
		name, stdout, stderr string
		faults               int
		emulated, valid      bool
	}{
		{"native", want, "", faults, false, true},
		{"qemu_complete", want, strings.Repeat(diagnostic, faults), faults, true, true},
		{"qemu_mixed_valid_signals", want, strings.Repeat(diagnostic, faults-1) + bus, faults, true, true},
		{"missing_receipt", "", strings.Repeat(diagnostic, faults), faults, true, false},
		{"duplicate_receipt", want + want, strings.Repeat(diagnostic, faults), faults, true, false},
		{"wrong_case_count", strings.Replace(want, "reference=98", "reference=97", 1), strings.Repeat(diagnostic, faults), faults, true, false},
		{"truncated_receipt", strings.TrimSuffix(want, "\n"), strings.Repeat(diagnostic, faults), faults, true, false},
		{"diagnostic_in_stdout", diagnostic + want, strings.Repeat(diagnostic, faults-1), faults, true, false},
		{"missing_diagnostics", want, "", faults, true, false},
		{"missing_child", want, strings.Repeat(diagnostic, faults-1), faults, true, false},
		{"duplicate_child", want, strings.Repeat(diagnostic, faults+1), faults, true, false},
		{"unknown_stderr", want, "unknown tool failure\n" + strings.Repeat(diagnostic, faults), faults, true, false},
		{"wrong_signal", want, strings.Repeat(diagnostic, faults-1) + strings.Replace(diagnostic, "signal 11", "signal 4", 1), faults, true, false},
		{"truncated_diagnostic", want, strings.TrimSuffix(strings.Repeat(diagnostic, faults), "\n"), faults, true, false},
		{"native_must_not_borrow_qemu", want, strings.Repeat(diagnostic, faults), faults, false, false},
		{"negative_fault_inventory", want, "", -1, false, false},
		{"excess_fault_inventory", want, "", 6*14 + 1, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr := []byte(test.stdout), []byte(test.stderr)
			beforeStdout, beforeStderr := bytes.Clone(stdout), bytes.Clone(stderr)
			err := x86FMA3PortableAccessReceipt(stdout, stderr, nil, want, test.faults, test.emulated)
			if (err == nil) != test.valid {
				t.Errorf("bound stream/fault receipt valid=%t, want %t: %v", err == nil, test.valid, err)
			}
			if !bytes.Equal(stdout, beforeStdout) || !bytes.Equal(stderr, beforeStderr) {
				t.Fatal("receipt parser changed raw evidence")
			}
		})
	}
	for _, failure := range []error{errors.New("nonzero exit"), errors.New("owned cleanup failure")} {
		if err := x86FMA3PortableAccessReceipt([]byte(want), []byte(strings.Repeat(diagnostic, faults)), failure, want, faults, true); !errors.Is(err, failure) {
			t.Fatal("command failure was replaced by a successful receipt", err)
		}
	}
}
