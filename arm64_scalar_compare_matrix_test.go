package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64CompareCase struct {
	op          string
	bits        int
	left, right int
	zero, dead  bool
	raw         bool
}

func arm64CompareCases(banks []int, raw bool) []arm64CompareCase {
	var cases []arm64CompareCase
	for _, op := range arm64ScalarCompareNames {
		bits := 32
		if strings.HasSuffix(op, "D") {
			bits = 64
		}
		for _, bank := range banks {
			for _, form := range []int{0, 1, 2} {
				for _, dead := range []bool{false, true} {
					right := (bank + 1) % 32
					if form == 1 {
						right = bank
					}
					cases = append(cases, arm64CompareCase{op, bits, bank, right, form == 2, dead, raw})
				}
			}
		}
	}
	return cases
}

func (row arm64CompareCase) instruction() string {
	if row.raw {
		word := uint32(0x1e202000) | uint32(row.left)<<5
		if row.bits == 64 {
			word |= 1 << 22
		} else if row.bits == 16 {
			word |= 3 << 22
		}
		if strings.Contains(row.op, "E") {
			word |= 1 << 4
		}
		if row.zero {
			word |= 1 << 3
		} else {
			word |= uint32(row.right) << 16
		}
		return fmt.Sprintf("WORD $%#08x", word)
	}
	if row.zero {
		// Nonzero C_FCON spellings are accepted by Go and encode zero.
		return fmt.Sprintf("%s $(-1.25),F%d", row.op, row.left)
	}
	return fmt.Sprintf("%s F%d,F%d", row.op, row.right, row.left)
}

func arm64CompareMatrixSource(cases []arm64CompareCase) (source, goSource string) {
	var assembly, declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index, row := range cases {
		name := fmt.Sprintf("compareMatrix%d", index)
		fmt.Fprintf(&declarations, "func %s(*[66]uint64,*[69]uint64)\n", name)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for register := 0; register < 32; register++ {
			fmt.Fprintf(&assembly, "VLD1.P 16(R0),[V%d.B16]\n", register)
		}
		assembly.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD (R0),R12\nMSR R12,FPCR\nMOVD 8(R0),R12\nMSR R12,FPSR\n")
		assembly.WriteString(row.instruction() + "\n")
		if row.dead {
			assembly.WriteString("CMP R0,R0\n")
		}
		assembly.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET CS,R4\nCSET VS,R5\nLSL $3,R2,R2\nLSL $2,R3,R3\nLSL $1,R4,R4\nORR R3,R2,R2\nORR R4,R2,R2\nORR R5,R2,R2\n")
		assembly.WriteString("MRS FPCR,R3\nMRS FPSR,R4\n")
		for register := 0; register < 32; register++ {
			fmt.Fprintf(&assembly, "VST1.P [V%d.B16],16(R1)\n", register)
		}
		assembly.WriteString("MOVD R2,(R1)\nMOVD R4,8(R1)\nMOVD R3,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return assembly.String(), declarations.String()
}

func arm64CompareMatrixIRs(t *testing.T, source, goSource, triple string) []string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "compare", goSource)
	sizes := types.SizesFor("gc", "arm64")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
	text, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, options)
	if err != nil {
		t.Fatal(err)
	}
	direct := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	goBound := bound.Module.String()
	bound.Module.Dispose()
	return []string{text, direct, goBound}
}

func TestARM64ScalarCompareNativeFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// Every source/destination register occurs, including same-register aliases.
	// Raw H/S/D is a separate existing decoder domain, never a named H grant.
	var banks []int
	for bank := 0; bank < 32; bank++ {
		banks = append(banks, bank)
	}
	cases := arm64CompareCases(banks, false)
	raw := arm64CompareCases([]int{0, 31}, true)
	for _, row := range raw {
		if row.bits == 32 {
			row.bits = 16
			cases = append(cases, row)
		}
	}
	cases = append(cases, raw...)
	// One initialized register bank is enough for format/object coverage. The
	// runtime matrix separately tests each operation with complete bank output.
	var fixture strings.Builder
	fixture.WriteString("TEXT compareMatrix0(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n")
	for register := 0; register < 32; register++ {
		fmt.Fprintf(&fixture, "VLD1.P 16(R0),[V%d.B16]\n", register)
	}
	for _, row := range cases {
		fixture.WriteString(row.instruction() + "\n")
		if row.dead {
			fixture.WriteString("CMP R0,R0\n")
		}
	}
	fixture.WriteString("CSET VS,R2\nMOVD R2,(R1)\nRET\n")
	source := fixture.String()
	declarations := "package compare\nfunc compareMatrix0(*[66]uint64,*[69]uint64)\n"
	for _, target := range []struct{ goos, triple string }{
		{"darwin", "aarch64-apple-darwin"},
		{"linux", "aarch64-unknown-linux-gnu"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			arm64CompareGoObject(t, source, target.goos)
			for api, ir := range arm64CompareMatrixIRs(t, source, declarations, target.triple) {
				if got := strings.Count(ir, `asm sideeffect "fcmp`); got != len(cases) {
					t.Fatalf("API %d kept %d/%d native comparisons", api, got, len(cases))
				}
				optimized := armFloatEffectOptimizedIR(t, ir)
				if got := strings.Count(optimized, `asm sideeffect "fcmp`); got != len(cases) {
					t.Fatalf("API %d removed a dead native compare: %d/%d", api, got, len(cases))
				}
				compileLLVMToObject(t, llc, target.triple, "compare-matrix.ll", "compare-matrix.o", optimized)
			}
		})
	}
	t.Logf("%d initialized named/raw/register/zero/bank/alias/live/dead rows ×3 APIs ×3 OS objects", len(cases))
}

func TestARM64ScalarCompareNativeMalformedFamily(t *testing.T) {
	for _, op := range arm64ScalarCompareNames {
		for _, suffix := range []string{
			" F0", " F0,F1,F2", " R0,F1", " F0,R1", " V0.S4,F1",
			" $0,F1", " $(1),F1", " (R0),F1", " F0,(R1)", ".P F0,F1",
		} {
			t.Run(op+suffix, func(t *testing.T) {
				source := "TEXT invalid(SB),4,$0-0\n" + op + suffix + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				context := llvm.NewContext()
				defer context.Dispose()
				pkg := mustGoPackage(t, "compare", "package compare\nfunc invalid()\n")
				for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
					options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}}
					if ir, err := Translate(file, options); err == nil || ir != "" {
						t.Fatalf("invalid form acquired text IR: %v", err)
					}
					module, err := TranslateModuleInContext(context, file, options)
					if !module.IsNil() {
						module.Dispose()
						t.Fatal("invalid form published LLVM module")
					}
					if err == nil {
						t.Fatal("invalid form has no module error")
					}
					bound, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: triple})
					if bound != nil {
						bound.Module.Dispose()
						t.Fatal("invalid form published Go module")
					}
					if err == nil {
						t.Fatal("invalid form has no Go module error")
					}
				}
			})
		}
	}
}
