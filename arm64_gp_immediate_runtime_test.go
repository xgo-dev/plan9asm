package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64ImmediateOracleConstant struct {
	value             int64
	add, split, bit64 bool
	bit32             bool
}

type arm64ImmediateOracleCase struct {
	op      string
	value   int64
	left    Reg
	dest    Reg
	two     bool
	scratch bool
	encoded uint32
}

// These are independent Go encoder-class witnesses, not values derived from
// the translator's classifier. The original Go runtime checks the table too.
func arm64ImmediateOracleCases() []arm64ImmediateOracleCase {
	constants := []arm64ImmediateOracleConstant{
		{0, true, false, false, false}, {1, true, false, true, true},
		{4096, true, false, true, true}, {0x1234, false, false, false, false},
		{0x123456, false, true, false, false}, {0xffff0000, false, false, true, true},
		{0x123400005678, false, false, false, false},
		{0x123400005678009a, false, false, false, false},
		{0x123456789abcdef, false, false, false, false},
		{-1, false, false, false, false}, {-4096, false, false, true, true},
		{0x00ff00ff00ff00ff, false, false, true, true},
		{0x000ffffffffff000, false, false, true, true},
		{0x0f0f0f0f0f0f0f0f, false, false, true, true},
	}
	var cases []arm64ImmediateOracleCase
	for _, base := range []string{"ADD", "ADDS", "SUB", "SUBS", "CMP", "CMN", "AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST"} {
		for _, suffix := range []string{"", "W"} {
			for _, constant := range constants {
				word := suffix == "W"
				bitmask := constant.bit64
				if word {
					bitmask = constant.bit32
				}
				arithmetic := base == "ADD" || base == "ADDS" || base == "SUB" || base == "SUBS" || base == "CMP" || base == "CMN"
				compare := base == "CMP" || base == "CMN" || base == "TST"
				flags := compare || strings.HasSuffix(base, "S")
				encoderVariant := !word && (constant.value == 0x00ff00ff00ff00ff || constant.value == 0x0f0f0f0f0f0f0f0f)
				scratch := !bitmask
				if arithmetic {
					add, split := constant.add, constant.split
					if word && uint64(constant.value) > 0xffffffff && constant.value >= 0 {
						// Both wide MOVCON2/3 witnesses truncate to an ordinary
						// single MOVCON in W mode, not ADDCON2 or ADDCON.
						add, split = false, false
					}
					scratch = !add && !(split && !flags)
				}
				if compare {
					cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: constant.value, left: "R0", scratch: scratch})
					if base == "TST" || word || constant.value != 0 && constant.value != -1 {
						if arithmetic && encoderVariant {
							continue // Independently observed old/new Go encoder context.
						}
						// X single-MOV CMP/CMN-to-ZR is Go-accepted, but its
						// fixed-width expansion ends in UDF. It has separate
						// original-Go/LLVM fault and exact-byte oracles.
						if arithmetic && !word && (constant.value == 1 || constant.value == 4096 ||
							constant.value == 0x1234 || constant.value == 0xffff0000 || constant.value == -4096) {
							continue
						}
						zrScratch := scratch
						if arithmetic {
							zrScratch = true
						}
						cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: constant.value, left: ZR, scratch: zrScratch})
					}
					continue
				}
				for _, dest := range []Reg{"R1", "R27"} {
					cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: constant.value, left: "R0", dest: dest, scratch: scratch})
				}
				cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: constant.value, left: "R27", dest: "R27", two: true, scratch: scratch})
				if !arithmetic {
					if !flags && (encoderVariant || !word && constant.value == 4096) {
						continue // X C_ABCON-to-ZR fallback has a separate UDF oracle.
					}
					cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: constant.value, left: "R0", dest: ZR, scratch: scratch || !flags})
				}
			}
		}
	}
	return cases
}

func arm64ImmediateOracleInstruction(tc arm64ImmediateOracleCase) string {
	if tc.encoded != 0 {
		return fmt.Sprintf("WORD $%#x", tc.encoded)
	}
	text := fmt.Sprintf("%s $%d,%s", tc.op, tc.value, tc.left)
	if tc.dest != "" && !tc.two {
		text += "," + string(tc.dest)
	}
	return text
}

func arm64ImmediateOracleSource(cases []arm64ImmediateOracleCase) string {
	var source strings.Builder
	source.WriteString("TEXT ·DivideRem(SB),4,$0-16\nMOVD input+0(FP),R10\nMOVD output+8(FP),R11\n")
	for _, tc := range cases {
		source.WriteString("MOVD 0(R10),R0\nMOVD 8(R10),R27\nMOVD 16(R10),R6\nMOVD 24(R10),R7\nMOVD $107,R1\nCMP R7,R6\n")
		source.WriteString(arm64ImmediateOracleInstruction(tc) + "\n")
		result := tc.dest
		if result == "" || result == ZR {
			result = "R1"
		}
		fmt.Fprintf(&source, "MOVD %s,(R11)\nMOVD R27,8(R11)\n", result)
		source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET HS,R4\nCSET VS,R5\nLSL $1,R3\nLSL $2,R4\nLSL $3,R5\nORR R3,R2\nORR R4,R2\nORR R5,R2\n")
		source.WriteString("MOVD R2,16(R11)\nADD $24,R11\n")
	}
	source.WriteString("RET\n")
	return source.String()
}

func arm64ImmediateOracleExpected(tc arm64ImmediateOracleCase, input [4]uint64) [3]uint64 {
	base := strings.TrimSuffix(tc.op, "W")
	word := strings.HasSuffix(tc.op, "W")
	right, scratch := uint64(tc.value), input[1]
	if word {
		right = uint64(uint32(right))
	}
	if tc.scratch {
		scratch = right
	}
	left := input[0]
	if tc.left == "R27" {
		left = scratch
	} else if tc.left == ZR {
		left = 0
	}
	if word {
		left = uint64(uint32(left))
	}
	if base == "BIC" || base == "BICS" || base == "ORN" || base == "EON" {
		right = ^right
	}
	if word {
		right = uint64(uint32(right))
	}
	result, operation := uint64(0), "logic"
	switch base {
	case "ADD", "ADDS", "CMN":
		result, operation = left+right, "add"
	case "SUB", "SUBS", "CMP":
		result, operation = left-right, "sub"
	case "AND", "ANDS", "BIC", "BICS", "TST":
		result = left & right
	case "ORR", "ORN":
		result = left | right
	case "EOR", "EON":
		result = left ^ right
	}
	width := uint(64)
	if word {
		width, result = 32, uint64(uint32(result))
	}
	flags := arm64DivRemRuntimeFlags(input[2], input[3])
	if strings.HasSuffix(base, "S") || tc.dest == "" {
		flags = 0
		sign := uint64(1) << (width - 1)
		if result&sign != 0 {
			flags |= 1
		}
		if result == 0 {
			flags |= 2
		}
		if operation == "add" {
			if result < left {
				flags |= 4
			}
			if (^(left^right)&(left^result))&sign != 0 {
				flags |= 8
			}
		} else if operation == "sub" {
			if left >= right {
				flags |= 4
			}
			if ((left^right)&(left^result))&sign != 0 {
				flags |= 8
			}
		}
	}
	if tc.dest == "R27" {
		scratch = result
	}
	if tc.dest == "" || tc.dest == ZR {
		result = 107
	}
	return [3]uint64{result, scratch, flags}
}

func arm64ImmediateOraclePrograms(cases []arm64ImmediateOracleCase) (string, string) {
	inputs := arm64DivRemRuntimeInputs()[:8]
	var goData, cData strings.Builder
	for _, input := range inputs {
		goData.WriteString("{\n")
		cData.WriteString("{\n")
		for _, tc := range cases {
			for _, value := range arm64ImmediateOracleExpected(tc, input) {
				fmt.Fprintf(&goData, "%d,", value)
				fmt.Fprintf(&cData, "UINT64_C(%d),", value)
			}
			goData.WriteByte('\n')
			cData.WriteByte('\n')
		}
		goData.WriteString("},\n")
		cData.WriteString("},\n")
	}
	var goInputs, cInputs strings.Builder
	for _, input := range inputs {
		fmt.Fprintf(&goInputs, "{%d,%d,%d,%d},\n", input[0], input[1], input[2], input[3])
		fmt.Fprintf(&cInputs, "{UINT64_C(%d),UINT64_C(%d),UINT64_C(%d),UINT64_C(%d)},\n", input[0], input[1], input[2], input[3])
	}
	count := len(cases) * 3
	goSource := fmt.Sprintf(`package main
import "fmt"
func DivideRem(input *[4]uint64, output *[%d]uint64)
var expected = [...][%d]uint64{%s}
var inputs = [...][4]uint64{%s}
func main() {
 for row, input := range inputs {
  initial := input
  var storage [%d]uint64
  storage[0],storage[len(storage)-1] = 0x12345678,0x87654321
  output := (*[%d]uint64)(storage[1:])
  DivideRem(&input,output)
  if input != initial || storage[0] != 0x12345678 || storage[len(storage)-1] != 0x87654321 { panic("Go canary/input mutation") }
  for index, want := range expected[row] {
   if output[index] != want { panic(fmt.Sprintf("Go row %%d case %%d axis %%d got %%#x want %%#x",row,index/3,index%%3,output[index],want)) }
  }
 }
}
`, count, count, goData.String(), goInputs.String(), count+2, count)
	cSource := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void DivideRem(uint64_t *,uint64_t *);
static const uint64_t expected[][%d] = {%s};
static const uint64_t inputs[][4] = {%s};
int main(void) {
 for (unsigned row=0;row<sizeof(inputs)/sizeof(inputs[0]);row++) {
  uint64_t input[4],storage[%d] = {0};
  memcpy(input,inputs[row],sizeof(input));
  storage[0]=0x12345678;storage[%d]=0x87654321;
  DivideRem(input,storage+1);
  if (memcmp(input,inputs[row],sizeof(input)) || storage[0]!=0x12345678 || storage[%d]!=0x87654321) return 2;
  for (unsigned index=0;index<%d;index++) {
   if (storage[index+1]!=expected[row][index]) {
    fprintf(stderr,"LLVM row %%u case %%u axis %%u got %%#llx want %%#llx\n",row,index/3,index%%3,(unsigned long long)storage[index+1],(unsigned long long)expected[row][index]);
    return 1;
   }
  }
 }
 return 0;
}
`, count, cData.String(), cInputs.String(), count+2, count+1, count+1, count)
	return goSource, cSource
}

func TestCrossLinuxRuntimeMatrixARM64GPImmediateScratch(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases := arm64ImmediateOracleCases()
	source := arm64ImmediateOracleSource(cases)
	goSource, cSource := arm64ImmediateOraclePrograms(cases)
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*3) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("gp-immediate-%d", api), triple, ir, cSource, runner)
	}
	t.Logf("30 opcode family: %d original-Go/three-API LLVM cases x 8 boundary inputs, result/R27/NZCV/full canaries", len(cases))
}

func TestARM64GPImmediateScratchCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	cases := arm64ImmediateOracleCases()
	source := arm64ImmediateOracleSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc", "aarch64-w64-windows-gnu"} {
		for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*3) {
			compileLLVMToObject(t, llc, triple, fmt.Sprintf("gp-immediate-%d.ll", api), fmt.Sprintf("gp-immediate-%d.o", api), ir)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64GPImmediateEncodedVsSource(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var cases []arm64ImmediateOracleCase
	for _, suffix := range []string{"", "W"} {
		bank, zero := "x", "xzr"
		if suffix == "W" {
			bank, zero = "w", "wzr"
		}
		for _, base := range []string{"AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST"} {
			mnemonic, mask := strings.ToLower(base), "4096"
			destination, dest := bank+"1", Reg("R1")
			switch base {
			case "BIC", "BICS":
				mnemonic = strings.Replace(mnemonic, "bic", "and", 1)
				mask = "-4097"
			case "ORN":
				mnemonic, mask = "orr", "-4097"
			case "EON":
				mnemonic, mask = "eor", "-4097"
			case "TST":
				mnemonic = "ands"
			}
			if base == "ANDS" || base == "BICS" || base == "TST" {
				destination, dest = zero, ZR
			}
			assembly := fmt.Sprintf("%s %s,%s0,#%s", mnemonic, destination, bank, mask)
			word := assembleARM64LLVMWords(t, []string{assembly}, "")[0]
			if base == "TST" {
				dest = "" // Compare-class oracle: flags, with no GP result.
			}
			cases = append(cases, arm64ImmediateOracleCase{op: base + suffix, value: 4096, left: "R0", dest: dest, encoded: word})
		}
		assembly := fmt.Sprintf("adds %s,%s0,#1", zero, bank)
		word := assembleARM64LLVMWords(t, []string{assembly}, "")[0]
		cases = append(cases, arm64ImmediateOracleCase{op: "ADDS" + suffix, value: 1, left: "R0", dest: ZR, encoded: word})
		// Both named ADD and its genuine raw encoding have no implicit R27
		// output. The named ADDS-to-ZR spelling above is Go-rejected, while
		// the physical WORD is legal and must not acquire source optab rules.
		word = assembleARM64LLVMWords(t, []string{fmt.Sprintf("add %s1,%s0,#1", bank, bank)}, "")[0]
		cases = append(cases,
			arm64ImmediateOracleCase{op: "ADD" + suffix, value: 1, left: "R0", dest: "R1", encoded: word},
			arm64ImmediateOracleCase{op: "ADD" + suffix, value: 1, left: "R0", dest: "R1"})
	}
	source := arm64ImmediateOracleSource(cases)
	goSource, cSource := arm64ImmediateOraclePrograms(cases)
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*3) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("raw-immediate-%d", api), triple, ir, cSource, runner)
	}
	for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		for api, ir := range arm64DivRemRuntimeIRs(t, source, target, len(cases)*3) {
			compileLLVMToObject(t, llc, target, fmt.Sprintf("raw-immediate-%d.ll", api), fmt.Sprintf("raw-immediate-%d.o", api), ir)
		}
	}
}
