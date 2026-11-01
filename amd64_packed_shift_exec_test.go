package plan9asm

import (
	"reflect"
	"testing"
)

func x86PackedShiftGuestExecution(prefix []string, executable string, arguments ...string) []string {
	command := append([]string(nil), prefix...)
	command = append(command, executable)
	if len(prefix) != 0 {
		// The pinned binfmt QEMU preserves a separate original argv[0].
		// Native execution must not duplicate it. The Linux runtime oracle
		// independently verifies this pinned transport before any ASM runs.
		command = append(command, executable)
	}
	return append(command, arguments...)
}

func TestX86PackedShiftGuestArgumentTransport(t *testing.T) {
	for _, c := range []struct {
		name      string
		prefix    []string
		arguments []string
		want      []string
	}{
		{"native", nil, []string{"numeric"}, []string{"/guest", "numeric"}},
		{"native_empty", nil, nil, []string{"/guest"}},
		{"pinned_empty", []string{"/qemu", "-L", "/sysroot"}, nil,
			[]string{"/qemu", "-L", "/sysroot", "/guest", "/guest"}},
		{"pinned_numeric", []string{"/qemu", "-L", "/sysroot"}, []string{"numeric"},
			[]string{"/qemu", "-L", "/sysroot", "/guest", "/guest", "numeric"}},
		{"pinned_fault", []string{"/qemu", "-L", "/sysroot"}, []string{"3", "with space"},
			[]string{"/qemu", "-L", "/sysroot", "/guest", "/guest", "3", "with space"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			beforePrefix := append([]string(nil), c.prefix...)
			beforeArguments := append([]string(nil), c.arguments...)
			got := x86PackedShiftGuestExecution(c.prefix, "/guest", c.arguments...)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("guest command: got %q, want %q", got, c.want)
			}
			if !reflect.DeepEqual(c.prefix, beforePrefix) || !reflect.DeepEqual(c.arguments, beforeArguments) {
				t.Fatal("argument construction mutated its inputs")
			}
		})
	}
}
