package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAMD64ABI0AnchorPreservesTailJumpRelocation(t *testing.T) {
	args := make([]LLVMType, 15)
	for i := range args {
		args[i] = I32
	}
	for _, anchorName := range []string{"gcasmABI0Keep", "relocationKeep"} {
		source := fmt.Sprintf("TEXT ·%s(SB),NOSPLIT,$0-0\n", anchorName) +
			"JMP ·Fn(SB)\nJMP ·FnTwo(SB)\nJMP ·FnThree(SB)\n"
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		sigs := map[string]FuncSig{
			"example." + anchorName: {Name: "example." + anchorName, Ret: Void},
			"example.Fn":            {Name: "example.Fn", Args: args, Ret: I32},
			"example.FnTwo":         {Name: "example.FnTwo", Args: args, Ret: I32},
			"example.FnThree":       {Name: "example.FnThree", Args: args, Ret: I32},
		}
		for _, target := range []struct {
			goarch string
			triple string
		}{
			{"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-apple-darwin"},
			{"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"},
			{"386", "i386-apple-darwin"},
			{"386", "i686-pc-windows-msvc"},
		} {
			triple := target.triple
			t.Run(anchorName+"/"+triple, func(t *testing.T) {
				ir, err := Translate(file, Options{
					Goarch: target.goarch, TargetTriple: triple,
					ResolveSym: testResolveSym("example"), Sigs: sigs,
				})
				if err != nil {
					t.Fatal(err)
				}
				for _, symbol := range []string{"example.Fn", "example.FnTwo", "example.FnThree"} {
					if !strings.Contains(ir, "ptr @"+symbol) {
						t.Fatalf("ABI0 anchor omitted direct symbol relocation for %s", symbol)
					}
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc not found")
				}
				objdump := findLLVM22Tool("llvm-objdump")
				if objdump == "" {
					t.Fatal("LLVM 22 llvm-objdump not found")
				}
				dir := t.TempDir()
				llPath := filepath.Join(dir, "anchor.ll")
				object := filepath.Join(dir, "anchor.o")
				if err := os.WriteFile(llPath, []byte(ir), 0644); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command(llc, "-mtriple="+triple, "-filetype=obj", llPath, "-o", object).CombinedOutput(); err != nil {
					t.Fatalf("LLVM 22 object compile: %v\n%s", err, output)
				}
				output, err := exec.Command(objdump, "-dr", object).CombinedOutput()
				if err != nil {
					t.Fatalf("LLVM 22 object dump: %v\n%s", err, output)
				}
				if !regexp.MustCompile(`(?m)^\s*0: e9 `).Match(output) {
					t.Fatalf("anchor is not an entry-point tail jump with target relocation:\n%s", output)
				}
				for _, symbol := range []string{"example.Fn", "example.FnTwo", "example.FnThree"} {
					if !strings.Contains(string(output), symbol) {
						t.Fatalf("object omitted relocation for %s:\n%s", symbol, output)
					}
				}
			})
		}
	}
}

func TestAMD64NonAnchorStillRejectsUnmappedTailArguments(t *testing.T) {
	const source = "TEXT ·forward(SB),NOSPLIT,$0-0\nJMP ·Fn(SB)\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	args := make([]LLVMType, 7)
	for i := range args {
		args[i] = I32
	}
	_, err = Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: testResolveSym("example"),
		Sigs: map[string]FuncSig{
			"example.forward": {Name: "example.forward", Ret: Void},
			"example.Fn":      {Name: "example.Fn", Args: args, Ret: I32},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "missing arg reg") {
		t.Fatalf("unmapped non-anchor tail arguments unexpectedly accepted: %v", err)
	}
}
