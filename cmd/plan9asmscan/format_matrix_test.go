package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanOrthogonalFormatMatrixAllArches(t *testing.T) {
	goroot := runtime.GOROOT()
	arm64MaxUnsup := 2
	if ver := runtime.Version(); strings.HasPrefix(ver, "go1.20") || strings.HasPrefix(ver, "go1.21") {
		// Go 1.20-1.21 cmd/internal/obj/arm64 optab omits the status regTo2 slot
		// on 16 STXR*/STLXR*/CASP*/DUFF* rows.
		arm64MaxUnsup = 20
	}
	cases := []struct {
		goarch         string
		arch           plan9asm.Arch
		maxUnsup       int
		maxNonSVEUnsup int
		minForms       int
	}{
		{goarch: "386", arch: plan9asm.ArchAMD64, maxUnsup: 10, minForms: 10000},
		{goarch: "amd64", arch: plan9asm.ArchAMD64, maxUnsup: 275, minForms: 10000},
		{goarch: "arm", arch: plan9asm.ArchARM, maxUnsup: 0, minForms: 400},
		// ARM64 keeps strict <= arm64MaxUnsup on all non-SVE/NEON/scalar forms,
		// while honestly rejecting unmodeled SVE2/SME forms rather than emitting
		// placeholder IR.
		{goarch: "arm64", arch: plan9asm.ArchARM64, maxUnsup: 900, maxNonSVEUnsup: arm64MaxUnsup, minForms: 900},
		// Wasm honestly rejects the 9 unmodeled segment/table/pseudo ops
		// (DataDrop, ElemDrop, MemoryInit, ResumePoint, TableCopy/Fill/Grow/Init/Size).
		{goarch: "wasm", arch: plan9asm.ArchWASM, maxUnsup: 9, minForms: 200},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.goarch, func(t *testing.T) {
			t.Parallel()
			ops, forms, parseErrs, tables, catalog, err := scanOrthogonalFormatMatrix(goroot, tc.arch, tc.goarch)
			if err != nil {
				t.Fatalf("scanOrthogonalFormatMatrix(%s): %v", tc.goarch, err)
			}
			if len(parseErrs) != 0 {
				limit := len(parseErrs)
				if limit > 5 {
					limit = 5
				}
				t.Fatalf("scanOrthogonalFormatMatrix(%s) parse errors (%d): %v", tc.goarch, len(parseErrs), parseErrs[:limit])
			}
			if len(ops) == 0 || tables == 0 || len(catalog) == 0 {
				t.Fatalf("scanOrthogonalFormatMatrix(%s) empty result: ops=%d tables=%d catalog=%d", tc.goarch, len(ops), tables, len(catalog))
			}
			if len(forms) < tc.minForms {
				t.Fatalf("scanOrthogonalFormatMatrix(%s) forms=%d < min=%d", tc.goarch, len(forms), tc.minForms)
			}
			unsup := 0
			nonSVEUnsup := 0
			var bad []string
			var badNonSVE []string
			for _, fs := range forms {
				if fs.UnsupportedCount > 0 && fs.SupportedCount == 0 && fs.ContextCount == 0 {
					unsup++
					if len(bad) < 10 && len(fs.Examples) > 0 {
						bad = append(bad, fs.Examples[0])
					}
					opName := ""
					if len(fs.Examples) > 0 {
						fields := strings.Fields(fs.Examples[0])
						if len(fields) > 0 {
							opName = strings.ToUpper(fields[0])
						}
					}
					if tc.goarch == "arm64" && !strings.HasPrefix(opName, "Z") && !strings.HasPrefix(opName, "P") {
						nonSVEUnsup++
						if len(badNonSVE) < 10 && len(fs.Examples) > 0 {
							badNonSVE = append(badNonSVE, fs.Examples[0])
						}
					}
				}
			}
			if unsup > tc.maxUnsup {
				t.Fatalf("scanOrthogonalFormatMatrix(%s) unsupported=%d > max=%d; samples=%v", tc.goarch, unsup, tc.maxUnsup, bad)
			}
			if tc.goarch == "arm64" && nonSVEUnsup > tc.maxNonSVEUnsup {
				t.Fatalf("scanOrthogonalFormatMatrix(arm64) non-SVE unsupported=%d > max=%d; samples=%v", nonSVEUnsup, tc.maxNonSVEUnsup, badNonSVE)
			}
		})
	}
}

func TestFormatMatrixHelpers(t *testing.T) {
	if err := validateCorpusTarget("formats", "amd64"); err != nil {
		t.Fatalf("validateCorpusTarget(formats, amd64): %v", err)
	}
	if got := synthesizeFormatMatrixLines("unknown", encoderFormReport{Opcode: "NOP"}, nil); len(got) != 0 {
		t.Fatalf("unexpected lines for unknown goarch: %v", got)
	}
	if got := expandX86FormatMatrix("amd64", encoderFormReport{Opcode: "TEXT", OperandClasses: []string{"Ytextsize"}}, nil, nil); got != nil {
		t.Fatalf("expected nil for Ytextsize, got %v", got)
	}
	if got := expandX86FormatMatrix("amd64", encoderFormReport{Opcode: "END"}, []string{"END"}, nil); len(got) != 1 {
		t.Fatalf("expected base preserved for END, got %v", got)
	}
	if got := expandARM64FormatMatrix(encoderFormReport{Opcode: "END"}, []string{"END"}); len(got) != 1 {
		t.Fatalf("expected base preserved for arm64 END, got %v", got)
	}
	if got := expandARMFormatMatrix(encoderFormReport{Opcode: "END"}, []string{"END"}); len(got) != 1 {
		t.Fatalf("expected base preserved for arm END, got %v", got)
	}
	if got := extraOrthogonalFormatLines("unknown"); got != nil {
		t.Fatalf("expected nil extra lines for unknown goarch, got %v", got)
	}
	// Verify SVE P0.Z / P0.M slash-predicate expansion branch.
	sveLines := expandARM64FormatMatrix(
		encoderFormReport{Opcode: "ZADD", OperandClasses: []string{"C_ZREG", "C_PREG", "C_ZREG"}},
		[]string{"ZADD Z0.S, P0.Z, Z1.S", "ZADD Z0.S, P0.M, Z1.S"},
	)
	joined := strings.Join(sveLines, "\n")
	if !strings.Contains(joined, "P0/Z") || !strings.Contains(joined, "P0/M") {
		t.Fatalf("expected P0/Z and P0/M expansion in %q", joined)
	}
}

func TestAsmSourceMatchesArchBuildConstraints(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		goarch string
		want   bool
	}{
		{"negated other arch substring", "//go:build !arm64\nTEXT f(SB),$0\n", "arm", true},
		{"negated same arch", "//go:build !arm\nTEXT f(SB),$0\n", "arm", false},
		{"compound other arch", "//go:build arm64 && !purego\nTEXT f(SB),$0\n", "arm", false},
		{"compound same arch", "//go:build arm64 && !purego\nTEXT f(SB),$0\n", "arm64", true},
		{"or includes arch", "//go:build arm || arm64\nTEXT f(SB),$0\n", "arm", true},
		{"or excludes arch", "//go:build arm || arm64\nTEXT f(SB),$0\n", "amd64", false},
		{"negated or excludes arch", "//go:build !(arm || arm64)\nTEXT f(SB),$0\n", "arm", false},
		{"negated or allows other", "//go:build !(arm || arm64)\nTEXT f(SB),$0\n", "amd64", true},
		{"negated and allows non-excluded", "//go:build !(arm && purego)\nTEXT f(SB),$0\n", "arm", true},
	}
	for _, tc := range cases {
		if got := asmSourceMatchesArch(tc.src, tc.goarch); got != tc.want {
			t.Errorf("%s: asmSourceMatchesArch(%q, %q) = %v, want %v", tc.name, tc.src, tc.goarch, got, tc.want)
		}
	}
}
