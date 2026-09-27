//go:build !windows

package main

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestCompileOneChecksEveryFunctionInBoundedModules(t *testing.T) {
	config, err := resolveCompileConfig(true, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions = 1
	dir := t.TempDir()
	asm := filepath.Join(dir, "functions_amd64.s")
	const source = `
TEXT ·first(SB),$0-0
	RET
TEXT ·second(SB),$0-0
	RET
TEXT ·third(SB),$0-0
	RET
`
	if err := os.WriteFile(asm, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/chunks",
		Types:   types.NewPackage("example.com/chunks", "chunks"),
		Imports: map[string]*packages.Package{},
	}
	out := filepath.Join(dir, "functions.ll")
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out}, false, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"functions.ll", "functions.part-0001.ll", "functions.part-0002.ll"} {
		path := filepath.Join(dir, name)
		ir, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(ir), "define "); got != 1 {
			t.Fatalf("%s contains %d defined functions, want one", name, got)
		}
		object := strings.TrimSuffix(path, ".ll") + ".o"
		if _, err := os.Stat(object); !os.IsNotExist(err) {
			t.Fatalf("temporary object %s was not removed: %v", object, err)
		}
	}
}

func TestCompileOneBoundsModuleByInstructionCount(t *testing.T) {
	config, err := resolveCompileConfig(true, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions = 128
	config.MaxInstructions = 3

	dir := t.TempDir()
	asm := filepath.Join(dir, "instructions_amd64.s")
	const source = `
TEXT ·first(SB),$0-0
	NOP
	RET
TEXT ·second(SB),$0-0
	NOP
	RET
TEXT ·third(SB),$0-0
	NOP
	RET
`
	if err := os.WriteFile(asm, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/instructionchunks",
		Types:   types.NewPackage("example.com/instructionchunks", "instructionchunks"),
		Imports: map[string]*packages.Package{},
	}
	out := filepath.Join(dir, "instructions.ll")
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out}, false, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"instructions.ll", "instructions.part-0001.ll", "instructions.part-0002.ll"} {
		ir, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(ir), "define "); got != 1 {
			t.Fatalf("%s contains %d functions, want one", name, got)
		}
	}
}

func TestCompileOneBoundedModulesDoNotHideLateFailure(t *testing.T) {
	config, err := resolveCompileConfig(true, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions = 1
	dir := t.TempDir()
	asm := filepath.Join(dir, "functions_amd64.s")
	const source = `
TEXT ·first(SB),$0-0
	RET
TEXT ·second(SB),$0-0
	RET
TEXT ·third(SB),$0-0
	UNKNOWNINSTRUCTION
	RET
`
	if err := os.WriteFile(asm, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/chunks",
		Types:   types.NewPackage("example.com/chunks", "chunks"),
		Imports: map[string]*packages.Package{},
	}
	out := filepath.Join(dir, "functions.ll")
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out}, false, config)
	if err == nil || !strings.Contains(err.Error(), "third") {
		t.Fatalf("late invalid function was not reported: %v", err)
	}
	for _, name := range []string{"functions.ll", "functions.part-0001.ll"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("earlier chunk %s was not checked: %v", name, err)
		}
	}
}

func TestCompileOneBoundedModulesPreserveCrossChunkRawText(t *testing.T) {
	config, err := resolveCompileConfig(true, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions = 1
	dir := t.TempDir()
	asm := filepath.Join(dir, "raw_amd64.s")
	const source = `TEXT ·refer(SB),$0-0
	LEAQ ·blob(SB), AX
	RET
TEXT ·blob(SB),$0-0
	LONG $0xdeadbeef
`
	if err := os.WriteFile(asm, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/chunks",
		Types:   types.NewPackage("example.com/chunks", "chunks"),
		Imports: map[string]*packages.Package{},
	}
	out := filepath.Join(dir, "raw.ll")
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out}, false, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "raw.part-0001.ll"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(second), `.byte 239, 190, 173, 222`) {
		t.Fatal("cross-chunk address-sensitive raw TEXT was not preserved byte-for-byte")
	}
}
