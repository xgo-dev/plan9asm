package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

// Exercise the real report path. Its hints must describe the same expanded,
// target-selected instructions that failed, not a second raw-source scan.
func TestUnsupportedDiagnosticsUseActualCompilationInput(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")

	cases := []struct {
		name, source, failure string
		ops                   []string
		hits                  int
	}{
		{
			name:    "supported-multiline-macro-context",
			source:  "#define SLEEPCALL \\\nMOVD $101,R8; \\\nSVC; \\\nRET\nTEXT ·F(SB),NOSPLIT,$0-0\nSLEEPCALL\n",
			failure: "instruction probe needs function context",
		},
		{
			name:    "inactive-target-instruction",
			source:  "TEXT ·F(SB),NOSPLIT,$0-0\n#ifdef GOOS_windows\nHIDDENOP R0,R1\n#else\nMOVD $101,R8\nSVC\n#endif\nRET\n",
			failure: "instruction probe needs function context",
		},
		{
			name:    "actual-expanded-unknown-instruction",
			source:  "#define BROKEN \\\nNOTIMPLEMENTED R0,R1; \\\nRET\nTEXT ·F(SB),NOSPLIT,$0-0\nBROKEN\n",
			failure: "NOTIMPLEMENTED", ops: []string{"NOTIMPLEMENTED"}, hits: 1,
		},
		{
			name:    "parse-failure-has-no-instruction-inventory",
			source:  "TEXT ·F(SB),NOSPLIT,$invalid-0\n#ifdef GOOS_windows\nHIDDENOP R0,R1\n#endif\nRET\n",
			failure: "parse asm:",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, source := range map[string]string{
				"go.mod":        "module example.invalid/opdiagnostic\n\ngo 1.24\n",
				"value.go":      "package opdiagnostic\nfunc F()\n",
				"value_arm64.s": "#include \"textflag.h\"\n" + test.source,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "arm64"},
				[]string{"."}, nil, nil, "", t.TempDir(), false, 0, true, false, true, repo, compileConfig{})
			if err != nil || report.TotalAsm != 1 || report.Success != 0 || report.Failed != 1 ||
				report.NotApplicable != 0 || len(report.Fails) != 1 {
				t.Fatalf("real failed compilation was lost: report=%+v err=%v", report, err)
			}
			failure := report.Fails[0]
			if !strings.Contains(failure.Err, test.failure) {
				t.Fatalf("wrong actual failure: %s", failure.Err)
			}
			if !reflect.DeepEqual(failure.Unsupported, test.ops) || len(failure.UnsupportedHits) != test.hits {
				t.Fatalf("hints differ from actual selected instructions: ops=%v hits=%+v", failure.Unsupported, failure.UnsupportedHits)
			}
			for _, hit := range failure.UnsupportedHits {
				if hit.Op != "NOTIMPLEMENTED" || !strings.Contains(hit.Source, "NOTIMPLEMENTED R0,R1") {
					t.Fatalf("macro text or noninstruction became an opcode hint: %+v", hit)
				}
			}
		})
	}
}

func TestInstructionDiagnosticsCollectCompleteParsedFiveArchInputs(t *testing.T) {
	for _, row := range []struct {
		name string
		arch plan9asm.Arch
	}{
		{"386", plan9asm.ArchAMD64},
		{"amd64", plan9asm.ArchAMD64},
		{"arm", plan9asm.ArchARM},
		{"arm64", plan9asm.ArchARM64},
		{"wasm", plan9asm.ArchWASM},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "DATA text<>+0(SB)/8,$\"a;BOGUS\"\n" +
				"TEXT first(SB),$0-0\nNOTIMPLEMENTED\nRET\n" +
				"TEXT second(SB),$0-0\nNOTIMPLEMENTED\nRET\n"
			goos := "linux"
			if row.name == "wasm" {
				goos = "js"
			}
			file, err := plan9asm.ParseWithDefines(row.arch, source, plan9asm.GoAssemblerDefines(goos, row.name))
			if err != nil {
				t.Fatal(err)
			}
			diagnostics := instructionDiagnostics{supported: map[string]struct{}{"RET": {}}}
			diagnostics.collect(file)
			if !reflect.DeepEqual(diagnostics.ops, []string{"NOTIMPLEMENTED"}) || len(diagnostics.hits) != 2 {
				t.Fatalf("lost complete parsed instruction inventory: %+v", diagnostics)
			}
			for index, hit := range diagnostics.hits {
				if hit.Function != file.Funcs[index].Sym || hit.Instruction <= 0 || hit.Line != 0 ||
					hit.Source != "NOTIMPLEMENTED" || hit.Op != "NOTIMPLEMENTED" {
					t.Fatalf("hint invented an original line or lost its parsed function: %+v", hit)
				}
			}
			diagnostics.collect(nil)
			if diagnostics.ops != nil || diagnostics.hits != nil {
				t.Fatal("absent input retained another file's hints")
			}
		})
	}
}

func TestInstructionDiagnosticsResetBeforeFailedSourceRead(t *testing.T) {
	diagnostics := instructionDiagnostics{
		supported: map[string]struct{}{"RET": {}},
		ops:       []string{"STALE"},
		hits:      []unsupportedHit{{Op: "STALE"}},
	}
	err := compileOne(nil, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{AsmFile: filepath.Join(t.TempDir(), "absent_arm64.s")}, false,
		compileConfig{diagnostics: &diagnostics})
	if err == nil || !strings.Contains(err.Error(), "read asm:") || diagnostics.ops != nil || diagnostics.hits != nil {
		t.Fatalf("failed read reused another compilation's hints: %v %+v", err, diagnostics)
	}
}
