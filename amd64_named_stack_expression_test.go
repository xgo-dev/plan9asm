package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestAMD64NamedStackConstantExpressions(t *testing.T) {
	const source = `TEXT namedStackExpressions(SB),$64-0
	MOVL AX, tmpdig-(0*4)(SP)
	MOVL BX, tmpdig-(1*4)(SP)
	ADDL tmpdig-(0*4)(SP), AX
	ADDL tmpdig-(1*4)(SP), BX
	RET
`
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Args[1]; got.Kind != OpMem || got.Mem.Off != 0 {
		t.Fatalf("first named stack slot parsed as %+v, want offset 0 memory", got)
	}
	if got := file.Funcs[0].Instrs[2].Args[1]; got.Kind != OpMem || got.Mem.Off != -4 {
		t.Fatalf("second named stack slot parsed as %+v, want offset -4 memory", got)
	}
	// These original operands establish constant-expression grammar only.
	// AX/BX have no inputs, and NAME_AUTO offset zero is not a logical
	// four-byte local within [-64,-4]. Keep the complete source as Context.
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("unbound/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func namedStackExpressions()",
				"amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original grammar supplied entry NUM or native frame storage", err)
			}
		})
	}

	// Preserve the four exact operations and their original offsets. The
	// actual source-bound frame and temporary SP relocation put their reads
	// and writes inside the 64-byte local; both input values are initialized.
	const initialized = `TEXT ·namedStackExpressions(SB),4,$64-24
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	MOVQ SP, R11
	ADDQ $-16, SP
	MOVL AX, tmpdig-(0*4)(SP)
	MOVL BX, tmpdig-(1*4)(SP)
	ADDL tmpdig-(0*4)(SP), AX
	ADDL tmpdig-(1*4)(SP), BX
	MOVQ R11, SP
	ADDQ BX, AX
	MOVQ AX, ret+16(FP)
	RET
`
	x86StackExpressionBoundObjects(t, initialized, "func namedStackExpressions(a,b uint64) uint64")
}

// Observe actual complete Go sources for each API, then compile their emitted
// IR at both optimization levels. A previous API cannot extend the source lease.
func x86StackExpressionBoundObjects(t *testing.T, source, declaration string) {
	t.Helper()
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("initialized-without-binding/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration,
				"amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("initialized source spelling supplied native frame authority", err)
			}
		})
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run("bound/"+goos, func(t *testing.T) {
			triple := testTargetTriple(goos, "amd64")
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, source, declaration, goos+"/amd64", triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "fixed_local_native") {
					t.Fatal("initialized exact expression lost its source-bound local frame", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		})
	}
}

func TestNamedStackConstantOffsetRejectsUnresolvedExpressions(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   int64
		ok     bool
	}{
		{prefix: "tmpdig-(7*4)", want: -28, ok: true},
		{prefix: "tmpdig+(2<<3)", want: 16, ok: true},
		{prefix: "tmpdig-(unknown*4)"},
		{prefix: "tmpdig-(4/0)"},
		{prefix: "tmp-dig-(1*4)"},
	} {
		got, ok := parseNamedStackConstantOffset(tc.prefix)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("parseNamedStackConstantOffset(%q) = %d, %v; want %d, %v", tc.prefix, got, ok, tc.want, tc.ok)
		}
	}
}
