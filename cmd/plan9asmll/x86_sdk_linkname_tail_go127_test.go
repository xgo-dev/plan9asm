//go:build go1.27

package main

import (
	"debug/elf"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneSDKAssemblyOnlyAtomicTails(t *testing.T) {
	for _, test := range []struct {
		arch, triple string
		machine      elf.Machine
		patterns     []string
	}{
		{"386", "i386-unknown-linux-gnu", elf.EM_386, []string{"."}},
		{"amd64", "x86_64-unknown-linux-gnu", elf.EM_X86_64, []string{".", "internal/runtime/atomic"}},
	} {
		t.Run(test.arch, func(t *testing.T) {
			setX86SDKNumericalCLIProfile(t, "explicit")
			t.Setenv("GOROOT", runtime.GOROOT())
			t.Chdir(filepath.Join(runtime.GOROOT(), "src", "sync", "atomic"))
			selected, environment, err := loadPkgsInEnvironment("linux", test.arch, test.patterns, nil, "", true, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			var index int
			for index < len(selected) && selected[index].PkgPath != "sync/atomic" {
				index++
			}
			if index == len(selected) {
				t.Fatal("actual SDK package missing")
			}
			pkg := selected[index]
			if pkg.Imports["internal/runtime/atomic"] != nil {
				t.Fatal("the tail target unexpectedly became a Go import")
			}
			input := filepath.Join(pkg.Dir, "asm.s")
			source, err := plan9asm.ReadGoAssemblySourceAtGOROOT(input, pkg.Dir, runtime.GOROOT())
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), plan9asm.GoAssemblerDefines("linux", test.arch))
			if err != nil || len(parsed.Funcs) != 36 {
				t.Fatal("complete original SDK assembly inventory changed", err)
			}
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(selected, "linux/"+test.arch, environment)
			output := filepath.Join(t.TempDir(), "atomic.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", test.arch, test.triple,
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatal(err)
			}
			object, err := elf.Open(strings.TrimSuffix(output, ".ll") + ".o")
			if err != nil {
				t.Fatal(err)
			}
			defer object.Close()
			if object.Machine != test.machine {
				t.Fatal("wrong target object", object.Machine)
			}
			symbols, err := object.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			definitions, imports := make(map[string]bool), make(map[string]bool)
			for _, symbol := range symbols {
				if symbol.Section == elf.SHN_UNDEF {
					imports[symbol.Name] = true
				} else if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
					definitions[symbol.Name] = true
				}
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			for _, function := range parsed.Funcs {
				callee := strings.TrimSuffix(function.Instrs[1].Args[0].Sym, "(SB)")
				if !definitions[resolve(function.Sym)] || !imports[resolve(callee)] {
					t.Fatal("missing source entry or its exact external target", function.Sym, callee)
				}
			}
		})
	}
}
