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
		goarch      string
		arch        plan9asm.Arch
		maxUnsup    int
		minForms    int
		wantExample string
	}{
		{goarch: "386", arch: plan9asm.ArchAMD64, maxUnsup: 10, minForms: 10000},
		{goarch: "amd64", arch: plan9asm.ArchAMD64, maxUnsup: 275, minForms: 10000},
		{goarch: "arm", arch: plan9asm.ArchARM, maxUnsup: 0, minForms: 400},
		{goarch: "arm64", arch: plan9asm.ArchARM64, maxUnsup: arm64MaxUnsup, minForms: 900},
		{goarch: "wasm", arch: plan9asm.ArchWASM, maxUnsup: 0, minForms: 200},
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
			var bad []string
			for _, fs := range forms {
				if fs.UnsupportedCount > 0 && fs.SupportedCount == 0 && fs.ContextCount == 0 {
					unsup++
					if len(bad) < 10 && len(fs.Examples) > 0 {
						bad = append(bad, fs.Examples[0])
					}
				}
			}
			if unsup > tc.maxUnsup {
				t.Fatalf("scanOrthogonalFormatMatrix(%s) unsupported=%d > max=%d; samples=%v", tc.goarch, unsup, tc.maxUnsup, bad)
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
