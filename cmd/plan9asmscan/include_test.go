package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanPackagesCountsIncludedMacroInstructions(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"save.h":  "#define SAVE() PUSHQ BP; MOVQ SP,BP\n#define RESTORE() POPQ BP\n",
		"probe.s": "#include \"save.h\"\nTEXT probe(SB),4,$0-0\nSAVE()\nXORQ AX,AX\nRESTORE()\nRET\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ops, _, parseErrors, packages, sources, err := scanPackages([]pkgJSON{{
		ImportPath: "example.invalid/included", Dir: dir, SFiles: []string{"probe.s"},
	}}, plan9asm.ArchAMD64, "amd64", runtime.GOROOT())
	if err != nil || len(parseErrors) != 0 || packages != 1 || sources != 1 {
		t.Fatalf("included source lost: error=%v parse=%v packages=%d sources=%d", err, parseErrors, packages, sources)
	}
	for _, opcode := range []string{"PUSHQ", "MOVQ", "XORQ", "POPQ", "RET"} {
		if ops[opcode] == nil || ops[opcode].Count != 1 {
			t.Errorf("included macro instruction %s not counted exactly once: %#v", opcode, ops[opcode])
		}
	}
}

func TestScanPackagesUsesSelectedSDKAndTargetMacros(t *testing.T) {
	dir, sdk := t.TempDir(), t.TempDir()
	include := filepath.Join(sdk, "pkg", "include")
	if err := os.MkdirAll(include, 0700); err != nil {
		t.Fatal(err)
	}
	// The header exists only in the explicitly selected SDK, not the host's.
	header := "#ifdef GOOS_windows\n#define SAVE() PUSHQ BP\n#else\n#define SAVE() PUSHQ BX\n#endif\n"
	if err := os.WriteFile(filepath.Join(include, "selected.h"), []byte(header), 0600); err != nil {
		t.Fatal(err)
	}
	source := "#include \"selected.h\"\n#include \"go_asm.h\"\nTEXT probe(SB),4,$0-0\nSAVE()\nMOVQ g_stackguard0(BP),BX\nRET\n"
	if err := os.WriteFile(filepath.Join(dir, "probe.s"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ goos, register string }{{"windows", "BP"}, {"linux", "BX"}} {
		t.Run(target.goos, func(t *testing.T) {
			ops, forms, parseErrors, _, _, err := scanPackages([]pkgJSON{{
				ImportPath: "example.invalid/selected", Dir: dir, SFiles: []string{"probe.s"},
			}}, plan9asm.ArchAMD64, "amd64", sdk, plan9asm.GoAssemblerDefines(target.goos, "amd64")...)
			if err != nil || len(parseErrors) != 0 || ops["PUSHQ"] == nil {
				t.Fatalf("selected SDK macro was lost: error=%v parse=%v", err, parseErrors)
			}
			var push, contextual int
			for _, form := range forms {
				if form.Descriptor.Opcode == "PUSHQ" {
					for _, example := range form.Examples {
						if example == "PUSHQ "+target.register {
							push++
						}
					}
				}
				if form.Descriptor.Opcode == "MOVQ" {
					contextual += form.ContextCount
					if form.SupportedCount != 0 || form.UnsupportedCount != 0 {
						t.Fatal("missing generated layout was certified as a resolved instruction")
					}
				}
			}
			if push != 1 || contextual != 1 {
				t.Fatalf("wrong target macro or lost unresolved generated operand: pushes=%d contextual=%d forms=%#v", push, contextual, forms)
			}
		})
	}
}

func TestScanPackagesRetainsGeneratedGlobalSizeAsContext(t *testing.T) {
	dir := t.TempDir()
	source := "GLOBL data(SB),8,$const_tlsSize\nTEXT probe(SB),4,$0-0\nXORQ AX,AX\nRET\n"
	if err := os.WriteFile(filepath.Join(dir, "probe.s"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ops, forms, parseErrors, _, _, err := scanPackages([]pkgJSON{{
		ImportPath: "example.invalid/global", Dir: dir, SFiles: []string{"probe.s"},
	}}, plan9asm.ArchAMD64, "amd64", runtime.GOROOT())
	if err != nil || len(parseErrors) != 0 || ops["XORQ"] == nil || ops["GLOBL"] == nil {
		t.Fatalf("global context swallowed later instructions: error=%v parse=%v", err, parseErrors)
	}
	var contextual int
	for _, form := range forms {
		if form.Descriptor.Opcode == "GLOBL" {
			contextual += form.ContextCount
			if form.SupportedCount != 0 || form.UnsupportedCount != 0 {
				t.Fatal("unresolved global size was reported as a resolved form")
			}
		}
	}
	if contextual != 1 {
		t.Fatalf("generated global size disappeared from contextual forms: %d", contextual)
	}
}
