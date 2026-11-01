package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Intel SDM Vol. 2C, Table 5-27 and ReduceArgumentSP/DP specify that the
// final subtraction uses the same selected RC as ROUND, not ambient RC.
// https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf
// This oracle performs both operations on exact rationals, then rounds once
// to the destination's IEEE precision. It shares no translator bit algorithm.
func x86ScaledRoundExactIEEE(input uint64, bits, scale, mode int, daz, reduce bool) uint64 {
	fraction, bias, precision := uint(23), 127, uint(24)
	exponentMask := uint64(0x7f800000)
	if bits == 64 {
		fraction, bias, precision = 52, 1023, 53
		exponentMask = 0x7ff0000000000000
	}
	sign := uint64(1) << (bits - 1)
	magnitude := input & (sign - 1)
	fractionMask := uint64(1)<<fraction - 1
	if magnitude >= exponentMask {
		if magnitude > exponentMask {
			return input | uint64(1)<<(fraction-1)
		}
		if reduce {
			return 0
		}
		return input
	}
	if magnitude == 0 || (daz && magnitude < uint64(1)<<fraction) {
		if reduce {
			if mode == 1 {
				return sign
			}
			return 0
		}
		return input & sign
	}

	exponent := int(magnitude >> fraction)
	significand := magnitude & fractionMask
	if exponent == 0 {
		exponent = 1
	} else {
		significand |= uint64(1) << fraction
	}
	numerator := new(big.Int).SetUint64(significand)
	denominator := big.NewInt(1)
	shift := exponent - bias - int(fraction)
	if shift >= 0 {
		numerator.Lsh(numerator, uint(shift))
	} else {
		denominator.Lsh(denominator, uint(-shift))
	}
	if input&sign != 0 {
		numerator.Neg(numerator)
	}
	value := new(big.Rat).SetFrac(numerator, denominator)
	unit := new(big.Int).Lsh(big.NewInt(1), uint(scale))
	scaled := new(big.Rat).Mul(value, new(big.Rat).SetInt(unit))
	integer, remainder := new(big.Int), new(big.Int)
	integer.QuoRem(scaled.Num(), scaled.Denom(), remainder)
	if remainder.Sign() != 0 {
		increment := false
		switch mode {
		case 0:
			distance := new(big.Int).Lsh(new(big.Int).Abs(remainder), 1)
			comparison := distance.Cmp(scaled.Denom())
			increment = comparison > 0 || comparison == 0 && integer.Bit(0) != 0
		case 1:
			increment = value.Sign() < 0
		case 2:
			increment = value.Sign() > 0
		}
		if increment {
			integer.Add(integer, big.NewInt(int64(value.Sign())))
		}
	}
	result := new(big.Rat).SetFrac(integer, unit)
	if reduce {
		result.Sub(value, result)
	}
	if result.Sign() == 0 {
		if reduce {
			if mode == 1 {
				return sign
			}
			return 0
		}
		return input & sign
	}
	rounding := []big.RoundingMode{big.ToNearestEven, big.ToNegativeInf, big.ToPositiveInf, big.ToZero}
	rounded := new(big.Float).SetPrec(precision).SetMode(rounding[mode]).SetRat(result)
	if bits == 32 {
		value, _ := rounded.Float32()
		return uint64(math.Float32bits(value))
	}
	value64, _ := rounded.Float64()
	return math.Float64bits(value64)
}

func TestX86ScaledRoundExactIEEEReferenceControls(t *testing.T) {
	for _, row := range []struct {
		bits, mode int
		input      uint64
		round      uint64
		reduce     uint64
	}{
		{32, 1, 0x80000001, 0xbe000000, 0x3dffffff},
		{32, 2, 1, 0x3e000000, 0xbdffffff},
		{64, 1, 0x8000000000000001, 0xbfc0000000000000, 0x3fbfffffffffffff},
		{64, 2, 1, 0x3fc0000000000000, 0xbfbfffffffffffff},
		{32, 0, 1, 0, 1},
		{64, 0, 1, 0, 1},
	} {
		if got := x86ScaledRoundExactIEEE(row.input, row.bits, 3, row.mode, false, false); got != row.round {
			t.Fatalf("independent ROUND%d input=%x mode=%d: got %x want %x", row.bits, row.input, row.mode, got, row.round)
		}
		if got := x86ScaledRoundExactIEEE(row.input, row.bits, 3, row.mode, false, true); got != row.reduce {
			t.Fatalf("independent REDUCE%d input=%x mode=%d: got %x want %x", row.bits, row.input, row.mode, got, row.reduce)
		}
	}
}

func x86ScaledRoundSelectedRoundingRows() string {
	var rows strings.Builder
	for _, bits := range []int{32, 64} {
		inputs := []uint64{0x3fc00000, 0x40200000, 0xbfc00000, 0xc0200000,
			0x3fb00000, 0xbfb00000, 0, 0x80000000, 0x7f800000, 0xff800000,
			0x7fc12345, 0xff812345, 1, 0x80000001, 0x4e800000, 0x3f800001}
		if bits == 64 {
			inputs = []uint64{0x3ff8000000000000, 0x4004000000000000, 0xbff8000000000000,
				0xc004000000000000, 0x3ff6000000000000, 0xbff6000000000000, 0,
				0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000,
				0x7ff8123456789abc, 0xfff0123456789abc, 1, 0x8000000000000001,
				0x41d0000000000000, 0x3ff0000000000001}
		}
		for scale := 0; scale < 16; scale++ {
			for mode := 0; mode < 4; mode++ {
				for daz := 0; daz < 2; daz++ {
					for operation := 0; operation < 2; operation++ {
						for _, input := range inputs {
							want := x86ScaledRoundExactIEEE(input, bits, scale, mode, daz != 0, operation != 0)
							fmt.Fprintf(&rows, "{%d,%d,%d,%d,%d,UINT64_C(0x%x),UINT64_C(0x%x)},\n",
								bits, scale, mode, daz, operation, input, want)
						}
					}
				}
			}
		}
	}
	// Retain the complete original 8,192-row matrix above. Supplement only
	// the small/grid boundary that makes the final subtraction inexact:
	// either side of half-step, retained-unit ties and discarded bits.
	for _, bits := range []int{32, 64} {
		fraction, bias := uint(23), uint64(127)
		if bits == 64 {
			fraction, bias = 52, 1023
		}
		for scale := 0; scale < 16; scale++ {
			regular := bias - uint64(scale)
			half := (regular - 1) << fraction
			middle := (regular - 4) << fraction
			unit := (regular - 1 - uint64(fraction)) << fraction
			inputs := []uint64{half - 1, half, half + 1, middle, middle + 1,
				middle + (uint64(1) << (fraction - 1)) - 1,
				middle + (uint64(1) << fraction) - 1, unit, unit + 1,
				unit - 1}
			for _, magnitude := range inputs {
				for negative := 0; negative < 2; negative++ {
					input, mode := magnitude, 2
					if negative != 0 {
						input |= uint64(1) << (bits - 1)
						mode = 1
					}
					want := x86ScaledRoundExactIEEE(input, bits, scale, mode, false, true)
					fmt.Fprintf(&rows, "{%d,%d,%d,0,1,UINT64_C(0x%x),UINT64_C(0x%x)},\n", bits, scale, mode, input, want)
				}
			}
		}
	}
	return rows.String()
}

const x86ScaledRoundSelectedRoundingTable = `
typedef struct { unsigned bits,scale,mode,daz,reduce; uint64_t input,want; } Row;
static const Row rows[] = {
ROWS
};
`

func x86ScaledRoundOriginalCReference(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_lower_scaled_round_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reference string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64ScaledRoundRuntimeSemantics" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if ok && len(value.Names) == 1 && value.Names[0].Name == "mainC" && len(value.Values) == 1 {
				literal, valid := value.Values[0].(*ast.BasicLit)
				if !valid || literal.Kind != token.STRING || reference != "" {
					t.Fatal("original C reference is not one complete literal")
				}
				reference, err = strconv.Unquote(literal.Value)
			}
			return true
		})
	}
	start := strings.Index(reference, "static int inc(")
	end := strings.Index(reference, "static uint32_t u32(")
	if err != nil || start < 0 || end <= start {
		t.Fatal("original four C reference helpers lost their complete boundaries", err)
	}
	return reference[start:end]
}

func x86ScaledRoundOriginalCReportComplete(output []byte) bool {
	report := string(output)
	return report == "original C exact IEEE observations 35328 failures 0\n" ||
		report == "original C exact IEEE observations 35328 failures 0\r\n"
}

func TestX86ScaledRoundOriginalCReferenceSelectedRounding(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM22 clang required for the actual original C reference")
	}
	source := "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <fenv.h>\n#pragma STDC FENV_ACCESS ON\n" +
		x86ScaledRoundOriginalCReference(t) + strings.Replace(x86ScaledRoundSelectedRoundingTable, "ROWS", x86ScaledRoundSelectedRoundingRows(), 1) + `
int main(void) {
 const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
 int original=fegetround(); unsigned failures=0,observations=0;
 for(unsigned ambient=0;ambient<4;ambient++) {
  if(fesetround(modes[ambient])) return 2;
  for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
   const Row *r=&rows[i]; uint64_t got;
   if(r->bits==32) got=r->reduce?reduce32((uint32_t)r->input,r->scale,r->mode,r->daz):round32((uint32_t)r->input,r->scale,r->mode,r->daz);
   else got=r->reduce?reduce64(r->input,r->scale,r->mode,r->daz):round64(r->input,r->scale,r->mode,r->daz);
   if(got!=r->want || fegetround()!=modes[ambient]) {
    if(failures++<12) fprintf(stderr,"original C bits=%u reduce=%u scale=%u selected=%u ambient=%u daz=%u input=%llx got=%llx want=%llx rounding_after=%d\n",r->bits,r->reduce,r->scale,r->mode,ambient,r->daz,(unsigned long long)r->input,(unsigned long long)got,(unsigned long long)r->want,fegetround());
   }
   observations++;
  }
 }
 if(fesetround(original)) return 3;
 printf("original C exact IEEE observations %u failures %u\n",observations,failures);
 return failures!=0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			directory := t.TempDir()
			input, executable := filepath.Join(directory, "reference.c"), filepath.Join(directory, "reference")
			if runtime.GOOS == "windows" {
				executable += ".exe"
			}
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			arguments := []string{level, "-frounding-math", input, "-o", executable}
			if runtime.GOOS != "windows" {
				arguments = append(arguments, "-lm")
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			x86FloatCompareCaptureCommand(t, runtimeOracleNativeCCommand(t, ctx, clang, arguments...))
			output := x86FloatCompareCaptureCommand(t, exec.Command(executable))
			if !x86ScaledRoundOriginalCReportComplete(output) {
				t.Fatalf("incomplete original C observations: %s", output)
			}
		})
	}
}

func TestX86ScaledRoundPortableSelectedRoundingExactIEEE(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var ir, declarations strings.Builder
	source, _ := x86ScaledRoundSelectedPublicSource("amd64")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Use the real whole-module requirements, not hand-written declarations
	// that could conceal a missing public helper registration.
	emitAMD64Prelude(&ir, "amd64", file)
	for _, bits := range []int{32, 64} {
		for operation := 0; operation < 2; operation++ {
			for scale := 0; scale < 16; scale++ {
				name := fmt.Sprintf("scaled_%d_%d_%d", bits, operation, scale)
				fmt.Fprintf(&ir, "define i64 @%s(i64 %%source, i32 %%mode, i32 %%daz) {\nentry:\n", name)
				input := "%source"
				if bits == 32 {
					ir.WriteString("  %input = trunc i64 %source to i32\n")
					input = "%input"
				}
				fmt.Fprintf(&ir, "  %%vector = insertelement <1 x i%d> poison, i%d %s, i32 0\n  %%flush = icmp ne i32 %%daz, 0\n", bits, bits, input)
				// This is expressly a private portable mathematical entry, not a
				// public source/ABI or native x86 MXCSR certificate. Both packed
				// and scalar fallback lowering call this exact shared producer.
				ctx := newX86Ctx(&ir, Func{}, FuncSig{}, nil, nil, "amd64", triple, false)
				result := ctx.emitScaledRoundBits(1, bits, "%vector", "%flush", "%mode", uint8(scale), amd64ScaledRoundMode(operation))
				fmt.Fprintf(&ir, "  %%low = extractelement <1 x i%d> %s, i32 0\n", bits, result)
				if bits == 32 {
					ir.WriteString("  %out = zext i32 %low to i64\n  ret i64 %out\n}\n")
				} else {
					ir.WriteString("  ret i64 %low\n}\n")
				}
				fmt.Fprintf(&declarations, "extern uint64_t %s(uint64_t,unsigned,unsigned);\n", name)
			}
		}
	}
	var functions strings.Builder
	functions.WriteString("typedef uint64_t (*Kernel)(uint64_t,unsigned,unsigned);\nstatic const Kernel kernels[2][2][16]={\n")
	for _, bits := range []int{32, 64} {
		functions.WriteString("{\n")
		for operation := 0; operation < 2; operation++ {
			functions.WriteString("{")
			for scale := 0; scale < 16; scale++ {
				fmt.Fprintf(&functions, "scaled_%d_%d_%d,", bits, operation, scale)
			}
			functions.WriteString("},\n")
		}
		functions.WriteString("},\n")
	}
	functions.WriteString("};\n")
	main := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + functions.String() +
		strings.Replace(x86ScaledRoundSelectedRoundingTable, "ROWS", x86ScaledRoundSelectedRoundingRows(), 1) + `
int main(void) {
 unsigned failures=0,observations=0;
 for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
  const Row *r=&rows[i]; uint64_t got=kernels[r->bits==64][r->reduce][r->scale](r->input,r->mode,r->daz);
  if(got!=r->want && failures++<12) fprintf(stderr,"portable LLVM bits=%u reduce=%u scale=%u selected=%u daz=%u input=%llx got=%llx want=%llx\n",r->bits,r->reduce,r->scale,r->mode,r->daz,(unsigned long long)r->input,(unsigned long long)got,(unsigned long long)r->want);
  observations++;
 }
 printf("portable exact IEEE observations %u failures %u\n",observations,failures);
 return failures!=0;
}
`
	x86ConflictFunnelPortableRuntime(t, llc, clang, "scaled-round-selected-ieee", triple, ir.String(), main)
}
