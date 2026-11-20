package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64DivRemRuntimeCase struct {
	op                      string
	divisor, dividend, dest Reg
	two                     bool
}

const arm64DivRemDiscard = uint64(0x123456789abcdef)

// Preserve the complete original Darwin fixture body as a separate entry. Only
// its first-party symbol is renamed so stock Go and all LLVM APIs can execute
// it alongside the wider initialized matrix on both native platforms.
const arm64DivRemOriginalRuntimeSource = `TEXT ·OriginalDivideRem(SB),$0-16
MOVD input+0(FP),R10
MOVD output+8(FP),R11
MOVD 0(R10),R0
MOVD 8(R10),R1
MOVD 16(R10),R2
MOVD 24(R10),R3
MOVD 32(R10),R4
MOVD 40(R10),R5
MOVD 48(R10),R23
SDIV R1,R0,R6
SDIVW R1,R0,R7
UDIV R3,R2,R8
UDIVW R3,R2,R9
REM R1,R0,R12
REMW R1,R0,R13
UREM R3,R2,R14
UREMW R3,R2,R15
SDIV ZR,R0,R16
UDIV ZR,R2,R17
REM ZR,R0,R19
UREM ZR,R2,R20
SDIV R5,R4,R21
SDIVW R5,R23,R22
MOVD R6,0(R11)
MOVD R7,8(R11)
MOVD R8,16(R11)
MOVD R9,24(R11)
MOVD R12,32(R11)
MOVD R13,40(R11)
MOVD R14,48(R11)
MOVD R15,56(R11)
MOVD R16,64(R11)
MOVD R17,72(R11)
MOVD R19,80(R11)
MOVD R20,88(R11)
MOVD R21,96(R11)
MOVD R22,104(R11)
RET
`

func arm64DivRemRuntimeCases() []arm64DivRemRuntimeCase {
	var cases []arm64DivRemRuntimeCase
	for _, op := range []string{"SDIV", "SDIVW", "UDIV", "UDIVW", "REM", "REMW", "UREM", "UREMW"} {
		// Both Go optab rows use C_ZREG throughout. These initialized aliases
		// cover two/three operands and every ZR role without using R18 or g.
		// Go REM's implicit R27 quotient is a separate observable-state axis.
		for _, form := range []arm64DivRemRuntimeCase{
			{divisor: "R1", dividend: "R0", dest: "R20"},
			{divisor: "R1", dividend: "R0", dest: "R0", two: true},
			{divisor: "R1", dividend: "R0", dest: "R0"},
			{divisor: "R1", dividend: "R0", dest: "R1"},
			{divisor: "R0", dividend: "R0", dest: "R20"},
			{divisor: "R0", dividend: "R0", dest: "R0", two: true},
			{divisor: "R0", dividend: "R0", dest: "R0"},
			{divisor: ZR, dividend: "R0", dest: "R20"},
			{divisor: "R1", dividend: ZR, dest: "R20"},
			{divisor: "R1", dividend: "R0", dest: ZR},
			{divisor: "R1", dividend: ZR, dest: ZR, two: true},
			{divisor: ZR, dividend: ZR, dest: ZR},
		} {
			form.op = op
			cases = append(cases, form)
		}
	}
	return cases
}

func arm64DivRemRuntimeSource(cases []arm64DivRemRuntimeCase) string {
	var source strings.Builder
	source.WriteString("TEXT ·DivideRem(SB),4,$0-16\nMOVD input+0(FP),R10\nMOVD output+8(FP),R11\n")
	for index, tc := range cases {
		source.WriteString("MOVD 0(R10),R0\nMOVD 8(R10),R1\nMOVD 16(R10),R6\nMOVD 24(R10),R7\n")
		fmt.Fprintf(&source, "MOVD $%#x,R20\nCMP R7,R6\n", arm64DivRemDiscard)
		if tc.two {
			fmt.Fprintf(&source, "%s %s,%s\n", tc.op, tc.divisor, tc.dest)
		} else {
			fmt.Fprintf(&source, "%s %s,%s,%s\n", tc.op, tc.divisor, tc.dividend, tc.dest)
		}
		result := tc.dest
		if result == ZR {
			result = "R20"
		}
		fmt.Fprintf(&source, "MOVD %s,%d(R11)\n", result, index*16)
		source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET HS,R4\nCSET VS,R5\n")
		source.WriteString("LSL $1,R3\nLSL $2,R4\nLSL $3,R5\nORR R3,R2\nORR R4,R2\nORR R5,R2\n")
		fmt.Fprintf(&source, "MOVD R2,%d(R11)\n", index*16+8)
	}
	source.WriteString("RET\n")
	source.WriteString(arm64DivRemOriginalRuntimeSource)
	return source.String()
}

func arm64DivRemRuntimeInputs() [][4]uint64 {
	inputs := [][4]uint64{
		{9, 2, 0, 0}, {^uint64(8), 2, 0, 1}, {9, ^uint64(1), 1, 0},
		{1 << 63, ^uint64(0), 1 << 63, 1}, {1 << 31, ^uint64(0), 0, 1 << 63},
		{^uint64(0), 0, ^uint64(0), 1}, {0, 0, 0, ^uint64(0)},
		{0xfedcba9880000000, 0x12345678ffffffff, 1 << 63, ^uint64(0)},
	}
	seed := uint64(0xabcdef0123456789)
	for i := 0; i < 64; i++ {
		var input [4]uint64
		for index := range input {
			seed = seed*6364136223846793005 + 1
			input[index] = seed
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func arm64DivRemRuntimeExpected(tc arm64DivRemRuntimeCase, input [4]uint64) uint64 {
	if tc.dest == ZR {
		return arm64DivRemDiscard
	}
	read := func(reg Reg) uint64 {
		switch reg {
		case "R0":
			return input[0]
		case "R1":
			return input[1]
		case ZR:
			return 0
		default:
			panic("unregistered numerical oracle register")
		}
	}
	numerator, denominator := read(tc.dividend), read(tc.divisor)
	word := strings.HasSuffix(tc.op, "W")
	if word {
		numerator, denominator = uint64(uint32(numerator)), uint64(uint32(denominator))
	}
	remainder := strings.Contains(tc.op, "REM")
	if denominator == 0 {
		if remainder {
			return numerator
		}
		return 0
	}
	signed := strings.HasPrefix(tc.op, "S") || strings.HasPrefix(tc.op, "REM")
	var result uint64
	if signed {
		n, d := int64(numerator), int64(denominator)
		if word {
			n, d = int64(int32(numerator)), int64(int32(denominator))
		}
		if remainder {
			result = uint64(n % d)
		} else {
			result = uint64(n / d)
		}
	} else if remainder {
		result = numerator % denominator
	} else {
		result = numerator / denominator
	}
	if word {
		result = uint64(uint32(result))
	}
	return result
}

func arm64DivRemRuntimeFlags(a, b uint64) uint64 {
	result := a - b
	flags := result >> 63
	if result == 0 {
		flags |= 2
	}
	if a >= b {
		flags |= 4
	}
	flags |= (((a ^ b) & (a ^ result)) >> 63) << 3
	return flags
}

func arm64DivRemRuntimePrograms(cases []arm64DivRemRuntimeCase) (goSource, cSource string) {
	var goText, cText strings.Builder
	count := len(cases) * 2
	fmt.Fprintf(&goText, `package main
func DivideRem(input *[4]uint64, output *[%d]uint64)
func OriginalDivideRem(input *[7]uint64, output *[14]uint64)
func main() {
	type row struct { input [4]uint64; want [%d]uint64 }
	rows := []row{
`, count, count)
	fmt.Fprintf(&cText, `#include <stdint.h>
#include <stdio.h>
extern void DivideRem(const uint64_t *, uint64_t *);
extern void OriginalDivideRem(const uint64_t *, uint64_t *);
struct row { uint64_t input[4]; uint64_t want[%d]; };
static const struct row rows[] = {
`, count)
	for _, input := range arm64DivRemRuntimeInputs() {
		fmt.Fprintf(&goText, "\t{input: [4]uint64{%#x,%#x,%#x,%#x}, want: [%d]uint64{", input[0], input[1], input[2], input[3], count)
		fmt.Fprintf(&cText, "  {{UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x)}, {", input[0], input[1], input[2], input[3])
		flags := arm64DivRemRuntimeFlags(input[2], input[3])
		for _, tc := range cases {
			result := arm64DivRemRuntimeExpected(tc, input)
			fmt.Fprintf(&goText, "%#x,%#x,", result, flags)
			fmt.Fprintf(&cText, "UINT64_C(%#x),UINT64_C(%#x),", result, flags)
		}
		goText.WriteString("}},\n")
		cText.WriteString("}},\n")
	}
	fmt.Fprintf(&goText, `
	}
	for rowIndex, r := range rows {
		input := r.input
		out := struct { left uint64; values [%d]uint64; right uint64 }{
			left: 0x1122334455667788, right: 0x8877665544332211,
		}
		for i := range out.values { out.values[i] = 0xa7a7a7a7a7a7a7a7 }
		DivideRem(&input, &out.values)
		if input != r.input || out.left != 0x1122334455667788 || out.right != 0x8877665544332211 {
			panic("divide/remainder input or canary changed")
		}
		for index, want := range r.want {
			if got := out.values[index]; got != want {
				println(rowIndex, index, got, want)
				panic("original Go divide/remainder numerical or NZCV mismatch")
			}
		}
	}
	originalInput := [7]uint64{0xfffffffffffffff7,2,9,2,0x8000000000000000,0xffffffffffffffff,0x80000000}
	originalWant := [14]uint64{0xfffffffffffffffc,0xfffffffc,4,4,0xffffffffffffffff,0xffffffff,1,1,0,0,0xfffffffffffffff7,9,0x8000000000000000,0x80000000}
	original := struct { left uint64; values [14]uint64; right uint64 }{
		left: 0x1122334455667788, right: 0x8877665544332211,
	}
	OriginalDivideRem(&originalInput, &original.values)
	if original.values != originalWant || original.left != 0x1122334455667788 || original.right != 0x8877665544332211 {
		panic("complete original divide/remainder body mismatch")
	}
}
`, count)
	fmt.Fprintf(&cText, `
};
int main(void) {
  for (unsigned row_index = 0; row_index < sizeof(rows)/sizeof(rows[0]); row_index++) {
    uint64_t input[4];
    struct { uint64_t left; uint64_t values[%d]; uint64_t right; } out;
    out.left = UINT64_C(0x1122334455667788);
    out.right = UINT64_C(0x8877665544332211);
    for (unsigned i = 0; i < 4; i++) input[i] = rows[row_index].input[i];
    for (unsigned i = 0; i < %d; i++) out.values[i] = UINT64_C(0xa7a7a7a7a7a7a7a7);
    DivideRem(input, out.values);
    if (out.left != UINT64_C(0x1122334455667788) || out.right != UINT64_C(0x8877665544332211)) return 1;
    for (unsigned i = 0; i < 4; i++) if (input[i] != rows[row_index].input[i]) return 2;
    for (unsigned i = 0; i < %d; i++) {
      if (out.values[i] != rows[row_index].want[i]) {
        fprintf(stderr, "row=%%u result=%%u got=%%llx want=%%llx\n", row_index, i,
          (unsigned long long)out.values[i], (unsigned long long)rows[row_index].want[i]);
        return 3;
      }
    }
  }
  const uint64_t original_input[7] = {
    UINT64_C(0xfffffffffffffff7),2,9,2,UINT64_C(0x8000000000000000),UINT64_MAX,UINT64_C(0x80000000)
  };
  const uint64_t original_want[14] = {
    UINT64_C(0xfffffffffffffffc),UINT64_C(0xfffffffc),4,4,UINT64_MAX,UINT32_MAX,1,1,0,0,
    UINT64_C(0xfffffffffffffff7),9,UINT64_C(0x8000000000000000),UINT64_C(0x80000000)
  };
  struct { uint64_t left; uint64_t values[14]; uint64_t right; } original = {0};
  original.left = UINT64_C(0x1122334455667788);
  original.right = UINT64_C(0x8877665544332211);
  OriginalDivideRem(original_input, original.values);
  if (original.left != UINT64_C(0x1122334455667788) || original.right != UINT64_C(0x8877665544332211)) return 4;
  for (unsigned i = 0; i < 14; i++) if (original.values[i] != original_want[i]) return 5;
  return 0;
}
`, count, count, count)
	return goText.String(), cText.String()
}

func arm64DivRemRuntimeIRs(t *testing.T, source, triple string, count int) []string {
	t.Helper()
	pkg := mustGoPackage(t, "divrem", fmt.Sprintf(`package divrem
func DivideRem(input *[4]uint64, output *[%d]uint64)
func OriginalDivideRem(input *[7]uint64, output *[14]uint64)
`, count))
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Audit the complete original file before deriving callable declarations.
	// Source-only continuations must not acquire independent helper signatures.
	file, err = CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	moduleIR := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	boundIR := bound.Module.String()
	bound.Module.Dispose()
	return []string{ir, moduleIR, boundIR}
}

func TestARM64DivideRemainderInitializedRuntimeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	cases := arm64DivRemRuntimeCases()
	source := arm64DivRemRuntimeSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin",
		"aarch64-pc-windows-msvc", "aarch64-w64-windows-gnu",
	} {
		for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*2) {
			compileLLVMToObject(t, llc, triple, fmt.Sprintf("divrem-%d.ll", api), fmt.Sprintf("divrem-%d.o", api), ir)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64DivideRemainderInitialized(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases := arm64DivRemRuntimeCases()
	source := arm64DivRemRuntimeSource(cases)
	goSource, cSource := arm64DivRemRuntimePrograms(cases)
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*2) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("divrem-%d", api), triple, ir, cSource, runner)
	}
	t.Logf("actual Go and all three LLVM APIs: %d U/S W/X divide/remainder forms x %d inputs, aliases/ZR, zero/min-overflow, preserved NZCV and complete canaries", len(cases), len(arm64DivRemRuntimeInputs()))
}
