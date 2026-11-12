//go:build go1.27

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneAMD64FixedLocalCompleteCPPSpelling(t *testing.T) {
	const operation = `#define MIX(src,dst) PADDL src , dst
retained:
	MIX(16(SP), X0)
DATA literal<>+0(SB)/8, $0x1122334455667788
GLOBL literal<>(SB), RODATA, $8`
	pkg, input, config := amd64FixedLocalCLIFixture(t, operation)
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "complete-cpp.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatalf("actual Go accepted complete macro/label/DATA source but CLI changed its parsed identity: %v", err)
	}
	ir, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(ir), "fixed_local_native") || !strings.Contains(string(ir), "literal") {
		t.Fatalf("complete source lost its fixed frame or original DATA: %v", err)
	}
	if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || info.Size() == 0 {
		t.Fatalf("LLVM 22 original-source object absent: %v", err)
	}
	after, err := os.ReadFile(input)
	if err != nil || string(after) != string(original) {
		t.Fatal("CLI cropped or rewrote the complete original input", err)
	}

	// A canonical spelling is not permission to replace the complete input.
	// Keep the actual owner and reject caller-side instruction/DATA mutations.
	read, err := readAsmSource(input, pkg.Module.Dir)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, string(read), plan9asm.GoAssemblerDefines("linux", "amd64"), "amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFileWithDeclarations(pkg, file, resolve, "amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	sigs, owner, err := prepareAMD64FixedLocalSource(pkg, file, input, "linux/amd64", "x86_64-unknown-linux-gnu",
		"amd64", config, resolve, sigs, nil)
	if err != nil || owner == nil {
		t.Fatal("complete unchanged source did not retain its actual owner", err)
	}
	defer func() {
		if err := owner.close(); err != nil {
			t.Error(err)
		}
	}()
	for _, mutation := range []string{"instruction deleted", "instruction changed", "DATA deleted"} {
		t.Run(mutation, func(t *testing.T) {
			changed, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, string(read), plan9asm.GoAssemblerDefines("linux", "amd64"), "amd64", nil)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "DATA deleted" {
				changed.Data = nil
			} else {
				found := false
				for ordinal, ins := range changed.Funcs[0].Instrs {
					if ins.Op != "PADDL" {
						continue
					}
					found = true
					if mutation == "instruction deleted" {
						changed.Funcs[0].Instrs = append(changed.Funcs[0].Instrs[:ordinal], changed.Funcs[0].Instrs[ordinal+1:]...)
					} else {
						changed.Funcs[0].Instrs[ordinal].Op = "PADDQ"
						changed.Funcs[0].Instrs[ordinal].Raw = strings.Replace(ins.Raw, "PADDL", "PADDQ", 1)
					}
					break
				}
				if !found {
					t.Fatal("complete-source mutation fixture lost its PADDL instruction")
				}
			}
			ir, err := plan9asm.Translate(changed, plan9asm.Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs,
			})
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || ir != "" {
				t.Fatal("canonical CPP bypassed the complete original source fingerprint", err)
			}
		})
	}
}
