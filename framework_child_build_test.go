package plan9asm

import (
	"os"
	"os/exec"
	"reflect"
	"testing"
)

// This configures only child harnesses importing the translator/LLVM bindings.
// Independent original-Go SDK/package observations must not use these flags.
func frameworkChildGoBuildCommand(arguments ...string) *exec.Cmd {
	flags := []string{"build", "-tags="}
	if frameworkChildByoLLVM {
		flags[1] = "-tags=byollvm"
	}
	return exec.Command("go", append(flags, arguments...)...)
}

func TestFrameworkChildGoBuildRetainsParentLLVMMode(t *testing.T) {
	for _, flags := range []string{"", "-tags=foreign", "-tags=byollvm"} {
		t.Run(flags, func(t *testing.T) {
			t.Setenv("GOFLAGS", flags)
			arguments := []string{"-trimpath", "-o", "reader", "main.go"}
			before := append([]string(nil), arguments...)
			command := frameworkChildGoBuildCommand(arguments...)
			want := []string{"go", "build", "-tags="}
			if frameworkChildByoLLVM {
				want[2] = "-tags=byollvm"
			}
			want = append(want, arguments...)
			if !reflect.DeepEqual(command.Args, want) {
				t.Fatalf("child lost compiled parent LLVM mode: got=%v want=%v", command.Args, want)
			}
			if command.Env != nil || os.Getenv("GOFLAGS") != flags || !reflect.DeepEqual(arguments, before) {
				t.Fatal("child harness construction changed original SDK environment or caller arguments")
			}
		})
	}
}
