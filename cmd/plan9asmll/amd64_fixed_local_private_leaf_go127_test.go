//go:build go1.27

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

const amd64FixedLocalCLIPrivateLeaf = `TEXT ·Value(SB),4,$80-16
 MOVQ a+0(FP),AX
 MOVQ AX,16(SP)
 LEAQ 16(SP),BP
 CALL leaf<>(SB)
 MOVQ AX,ret+8(FP)
 RET
TEXT leaf<>(SB),4,$0
 ADDQ $7,(BP)
 MOVQ (BP),AX
 RET
`

func TestAMD64FixedLocalCapturedSignaturesKeepProducerIdentity(t *testing.T) {
	plain := plan9asm.FuncSig{Name: "local", Ret: plan9asm.I64}
	declared := plan9asm.FuncSig{Name: "Value", Args: []plan9asm.LLVMType{plan9asm.I64}, Ret: plan9asm.I64}
	untouched := plan9asm.FuncSig{Name: "other", Ret: plan9asm.Void}
	sigs := map[string]plan9asm.FuncSig{"local": plain, "Value": declared, "other": untouched}
	fallbacks := map[string]plan9asm.FuncSig{"local": plain}
	actual, err := fixedLocalCapturedSignatures(sigs, fallbacks)
	if err != nil || len(actual) != 2 || !reflect.DeepEqual(actual["Value"], declared) ||
		!reflect.DeepEqual(actual["other"], untouched) || !reflect.DeepEqual(sigs["local"], plain) {
		t.Fatal("projection discarded an unrecorded/declared entry or changed its input", err)
	}
	for _, row := range []struct {
		name string
		sig  plan9asm.FuncSig
	}{
		{"name", plan9asm.FuncSig{Name: "changed", Ret: plan9asm.I64}},
		{"return", plan9asm.FuncSig{Name: "local", Ret: plan9asm.Void}},
		{"arguments", plan9asm.FuncSig{Name: "local", Args: []plan9asm.LLVMType{plan9asm.I64}, Ret: plan9asm.I64}},
		{"attributes", plan9asm.FuncSig{Name: "local", Ret: plan9asm.I64, Attrs: "nounwind"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			if result, err := fixedLocalCapturedSignatures(map[string]plan9asm.FuncSig{"local": row.sig}, fallbacks); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || result != nil {
				t.Fatal("changed automatic entry was silently discarded", err)
			}
		})
	}
	if result, err := fixedLocalCapturedSignatures(nil, fallbacks); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || result != nil {
		t.Fatal("missing original automatic entry was silently discarded", err)
	}
}

func TestCompileOneAMD64FixedLocalPrivateLeafDeclarations(t *testing.T) {
	for _, row := range []struct{ name, assembly, declaration string }{
		{"static", amd64FixedLocalCLIPrivateLeaf, ""},
		{"bare", strings.ReplaceAll(amd64FixedLocalCLIPrivateLeaf, "leaf<>", "leaf"), ""},
		// A separate Go implementation with the same base name does not give
		// the assembly file's static leaf a callable Go declaration.
		{"static_namespace", amd64FixedLocalCLIPrivateLeaf, "func leaf() uint64 { return 999 }\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, input, config := amd64FixedLocalCLISourceFixture(t, row.assembly,
				"package fixedlocal\nfunc Value(a uint64) uint64\n"+row.declaration)
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, row.assembly)
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			fallback, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil || len(file.Funcs) != 2 {
				t.Fatal("complete original source signature inventory", err)
			}
			if _, found := fallback[resolve(file.Funcs[1].Sym)]; !found {
				t.Fatal("regression fixture no longer exercises CLI fallback signature selection")
			}
			output := filepath.Join(t.TempDir(), "complete.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", targetTriple("linux", "amd64"),
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatal("actual Go accepted the whole source, but its private leaf acquired a fallback ABI", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || strings.Count(string(ir), "define ") != 1 || !strings.Contains(string(ir), "fixed_local_native") {
				t.Fatal("original framed root did not retain its sole callable definition", err)
			}
			if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatal("complete original source has no LLVM 22 object", err)
			}
		})
	}
}

func TestCompileOneAMD64FixedLocalPrivateLeafDeclarationBoundaries(t *testing.T) {
	for _, row := range []struct{ name, assembly, declaration string }{
		{"uninitialized", strings.Replace(amd64FixedLocalCLIPrivateLeaf, "MOVQ AX,16(SP)", "NOP", 1), ""},
		{"nonzero_helper", strings.Replace(amd64FixedLocalCLIPrivateLeaf, "TEXT leaf<>(SB),4,$0", "TEXT leaf<>(SB),4,$8", 1), ""},
		{"extra_sibling", amd64FixedLocalCLIPrivateLeaf + "TEXT unused<>(SB),4,$8\n RET\n", ""},
		{"bare_false_declaration", strings.ReplaceAll(amd64FixedLocalCLIPrivateLeaf, "leaf<>", "leaf"), "func leaf()\n"},
		{"foreign_namespace", strings.ReplaceAll(amd64FixedLocalCLIPrivateLeaf, "leaf<>", "other·leaf"), "func leaf() uint64 { return 999 }\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, input, config := amd64FixedLocalCLISourceFixture(t, row.assembly,
				"package fixedlocal\nfunc Value(a uint64) uint64\n"+row.declaration)
			dir := t.TempDir()
			output := filepath.Join(dir, "rejected.ll")
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", targetTriple("linux", "amd64"),
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("declaration selection authorized an unclosed original source", err)
			}
			artifacts, readErr := os.ReadDir(dir)
			if readErr != nil || len(artifacts) != 0 {
				t.Fatal("rejected whole source published an artifact", artifacts, readErr)
			}
		})
	}
}
