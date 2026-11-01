package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RemainderScratchCases() []arm64DivRemRuntimeCase {
	var cases []arm64DivRemRuntimeCase
	for _, op := range []string{"REM", "REMW", "UREM", "UREMW", "SDIV", "SDIVW", "UDIV", "UDIVW"} {
		for _, divisor := range []Reg{"R0", "R1", "R27", ZR} {
			for _, dest := range []Reg{"R0", "R1", "R2", "R27", ZR} {
				cases = append(cases, arm64DivRemRuntimeCase{
					op: op, divisor: divisor, dividend: dest, dest: dest, two: true,
				})
				for _, dividend := range []Reg{"R0", "R1", "R27", ZR} {
					cases = append(cases, arm64DivRemRuntimeCase{
						op: op, divisor: divisor, dividend: dividend, dest: dest,
					})
				}
			}
		}
	}
	return cases
}

func arm64RemainderScratchSource(cases []arm64DivRemRuntimeCase) string {
	var source strings.Builder
	source.WriteString("TEXT ·DivideRem(SB),4,$0-16\nMOVD input+0(FP),R10\nMOVD output+8(FP),R11\n")
	for index, tc := range cases {
		source.WriteString("MOVD 0(R10),R0\nMOVD 8(R10),R1\nMOVD 16(R10),R27\nMOVD 16(R10),R6\nMOVD 24(R10),R7\n")
		fmt.Fprintf(&source, "MOVD $%#x,R2\nCMP R7,R6\n", arm64DivRemDiscard)
		if tc.two {
			fmt.Fprintf(&source, "%s %s,%s\n", tc.op, tc.divisor, tc.dest)
		} else {
			fmt.Fprintf(&source, "%s %s,%s,%s\n", tc.op, tc.divisor, tc.dividend, tc.dest)
		}
		result := tc.dest
		if result == ZR {
			result = "R2"
		}
		fmt.Fprintf(&source, "MOVD %s,%d(R11)\nMOVD R27,%d(R11)\n", result, index*24, index*24+8)
		source.WriteString("CSET MI,R3\nCSET EQ,R4\nCSET HS,R5\nCSET VS,R8\n")
		source.WriteString("LSL $1,R4\nLSL $2,R5\nLSL $3,R8\nORR R4,R3\nORR R5,R3\nORR R8,R3\n")
		fmt.Fprintf(&source, "MOVD R3,%d(R11)\n", index*24+16)
	}
	source.WriteString("RET\n")
	return source.String()
}

// Go asm7 case 16 emits DIV Rm,Rn,R27 followed by MSUB R27,Rm,Rn,Rd.
// The second instruction reads the already overwritten R27, including when
// Rm or Rn aliases it. This is not an architectural remainder instruction.
func arm64RemainderScratchExpected(tc arm64DivRemRuntimeCase, input [4]uint64) (result, scratch uint64) {
	registers := map[Reg]uint64{"R0": input[0], "R1": input[1], "R2": arm64DivRemDiscard, "R27": input[2], ZR: 0}
	numerator, denominator := registers[tc.dividend], registers[tc.divisor]
	word := strings.HasSuffix(tc.op, "W")
	if word {
		numerator, denominator = uint64(uint32(numerator)), uint64(uint32(denominator))
	}
	if denominator != 0 {
		if strings.HasPrefix(tc.op, "U") {
			scratch = numerator / denominator
		} else if word {
			scratch = uint64(int64(int32(numerator)) / int64(int32(denominator)))
		} else {
			scratch = uint64(int64(numerator) / int64(denominator))
		}
	}
	if word {
		scratch = uint64(uint32(scratch))
	}
	if !strings.Contains(tc.op, "REM") {
		result = scratch
		scratch = input[2]
		if tc.dest == "R27" {
			scratch = result
		}
		if tc.dest == ZR {
			result = arm64DivRemDiscard
		}
		return result, scratch
	}
	registers["R27"] = scratch
	result = registers[tc.dividend] - scratch*registers[tc.divisor]
	if word {
		result = uint64(uint32(result))
	}
	if tc.dest == "R27" {
		scratch = result
	}
	if tc.dest == ZR {
		result = arm64DivRemDiscard
	}
	return result, scratch
}

func arm64RemainderScratchPrograms(cases []arm64DivRemRuntimeCase) (string, string) {
	count := len(cases) * 3
	var goText, cText strings.Builder
	fmt.Fprintf(&goText, `package main
func DivideRem(input *[4]uint64, output *[%d]uint64)
func main() {
	type row struct { input [4]uint64; want [%d]uint64 }
	rows := []row{
`, count, count)
	fmt.Fprintf(&cText, `#include <stdint.h>
#include <stdio.h>
extern void DivideRem(const uint64_t *, uint64_t *);
struct row { uint64_t input[4]; uint64_t want[%d]; };
static const struct row rows[] = {
`, count)
	for _, input := range arm64DivRemRuntimeInputs() {
		fmt.Fprintf(&goText, "{input:[4]uint64{%#x,%#x,%#x,%#x}, want:[%d]uint64{", input[0], input[1], input[2], input[3], count)
		fmt.Fprintf(&cText, "{{UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x)}, {", input[0], input[1], input[2], input[3])
		for _, tc := range cases {
			result, scratch := arm64RemainderScratchExpected(tc, input)
			flags := arm64DivRemRuntimeFlags(input[2], input[3])
			fmt.Fprintf(&goText, "%#x,%#x,%#x,", result, scratch, flags)
			fmt.Fprintf(&cText, "UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x),", result, scratch, flags)
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
		for i := range out.values {
			out.values[i] = 0xa7a7a7a7a7a7a7a7
		}
		DivideRem(&input, &out.values)
		if input != r.input || out.left != 0x1122334455667788 || out.right != 0x8877665544332211 {
			panic("remainder input or canary changed")
		}
		for index, want := range r.want {
			if got := out.values[index]; got != want {
				println(rowIndex, index, got, want)
				panic("Go pseudo-remainder/R27/NZCV mismatch")
			}
		}
	}
}
`, count)
	fmt.Fprintf(&cText, `
};
int main(void) {
  for (unsigned row = 0; row < sizeof(rows)/sizeof(rows[0]); row++) {
    uint64_t input[4];
    struct { uint64_t left; uint64_t values[%d]; uint64_t right; } out;
    out.left = UINT64_C(0x1122334455667788);
    out.right = UINT64_C(0x8877665544332211);
    for (unsigned i = 0; i < 4; i++) input[i] = rows[row].input[i];
    for (unsigned i = 0; i < %d; i++) out.values[i] = UINT64_C(0xa7a7a7a7a7a7a7a7);
    DivideRem(input, out.values);
    if (out.left != UINT64_C(0x1122334455667788) || out.right != UINT64_C(0x8877665544332211)) return 1;
    for (unsigned i = 0; i < 4; i++) if (input[i] != rows[row].input[i]) return 2;
    for (unsigned i = 0; i < %d; i++) {
      if (out.values[i] != rows[row].want[i]) {
        fprintf(stderr, "row=%%u result=%%u got=%%llx want=%%llx\n", row, i,
          (unsigned long long)out.values[i], (unsigned long long)rows[row].want[i]);
        return 3;
      }
    }
  }
  return 0;
}
`, count, count, count)
	return goText.String(), cText.String()
}

func TestCrossLinuxRuntimeMatrixARM64RemainderScratch(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases := arm64RemainderScratchCases()
	source := arm64RemainderScratchSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	goSource, cSource := arm64RemainderScratchPrograms(cases)
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*3) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("remainder-scratch-%d", api), triple, ir, cSource, runner)
	}
	t.Logf("original Go and three LLVM APIs: %d divide/REM W/X signed/unsigned forms x %d initialized inputs, observable R27/aliases/ZR, preserved NZCV and canaries", len(cases), len(arm64DivRemRuntimeInputs()))
}

func TestARM64RemainderScratchCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	cases := arm64RemainderScratchCases()
	source := arm64RemainderScratchSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	for _, target := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin",
		"aarch64-pc-windows-msvc", "aarch64-w64-windows-gnu",
	} {
		for api, ir := range arm64DivRemRuntimeIRs(t, source, target, len(cases)*3) {
			compileLLVMToObject(t, llc, target, fmt.Sprintf("remainder-%d.ll", api), fmt.Sprintf("remainder-%d.o", api), ir)
		}
	}
}
