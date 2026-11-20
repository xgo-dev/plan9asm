package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MMXNarrowOriginalFixtureObjects(t *testing.T) {
	var source, declarations strings.Builder
	count := 0
	for _, row := range x86NarrowOracleRows() {
		if row.bank != "M" {
			continue
		}
		name := fmt.Sprintf("Narrow%d", count)
		source.WriteString(x86NarrowIndependentAssembly(name, row))
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b,old *[64]byte,mask,flags uint64,csr uint32)\n", name)
		count++
	}
	if count != 12 {
		t.Fatal("complete original MMX narrowing fixture denominator changed", count)
	}
	x86MMXOriginalFixtureObjects(t, source.String(), declarations.String())
}

func TestX86MMXWordMaddOriginalLogicalFPFixtureObjects(t *testing.T) {
	source := x86WordMaddLogicalFPAssembly("Value", 8, 0)
	x86MMXOriginalFixtureObjects(t, source, "func Value(source [64]byte,out *byte,mask uint64)")
}

func TestX86MMXOriginalFixturesKeepPhysicalStateBoundary(t *testing.T) {
	var row x86NarrowOracleRow
	for _, candidate := range x86NarrowOracleRows() {
		if candidate.bank == "M" {
			row = candidate
			break
		}
	}
	if row.bank != "M" {
		t.Fatal("original MMX narrowing family disappeared")
	}
	setup := "LDMXCSR csr+48(FP)\nPUSHQ flags+40(FP)\nPOPFQ\n"
	narrow := x86NarrowIndependentAssembly("Value", row)
	narrow = strings.Replace(narrow, setup, "", 1)
	narrow = strings.Replace(narrow, "MOVQ (DX),M1\n", "MOVQ (DX),M1\n"+setup, 1)
	madd := strings.Replace(x86WordMaddLogicalFPAssembly("Value", 8, 0), "EMMS\n", "", 1)
	for _, control := range []struct{ name, source, declaration string }{
		{"interrupted-region", narrow, "func Value(out *[80]byte,a,b,old *[64]byte,mask,flags uint64,csr uint32)"},
		{"missing-emms", madd, "func Value(source [64]byte,out *byte,mask uint64)"},
	} {
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(control.name+"/"+triple, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", triple, control.source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, control.source, control.declaration, "amd64", triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unclosed physical MMX state was accepted", api, err)
					}
				}
			})
		}
	}
}

func x86MMXOriginalFixtureObjects(t *testing.T, source, declarations string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil {
					t.Fatal("original initialized MMX fixture did not close its physical state", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			}
		})
	}
}
