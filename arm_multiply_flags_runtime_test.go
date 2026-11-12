package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMMultiplyWithoutCPSRRead(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const source = `TEXT oracle(SB),4,$0-20
 MOVW value+0(FP),R0
 MOVW amount+4(FP),R1
 MOVW out+16(FP),R4
 CMP $1,R0
 MUL.S R0,R1,R2
 MOVW $0,R3
 MOVW.EQ $1,R3
 MOVW R3,(R4)
 RET
`
	runARMGoSourceOracle(t, source, `package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *uint32)
func main(){var out uint32;oracle(0,2,0,0,&out);if out!=1{panic(fmt.Sprint(out))};fmt.Println("MUL.S result Z drives ordinary EQ predicate=1")}
`)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "multiply_z_branch", "armv7-unknown-linux-gnueabihf", ir,
		`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
int main(void){uint32_t out=99;oracle(0,2,0,0,&out);if(out!=1){fprintf(stderr,"LLVM MUL.S Z predicate=%u want=1\n",out);return 1;}return 0;}
`, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}

type armMultiplyRuntimeCase struct {
	op, condition string
	setFlags      bool
	twoOperands   bool
}

func armMultiplyRuntimeCases() []armMultiplyRuntimeCase {
	var cases []armMultiplyRuntimeCase
	for _, op := range []string{"MUL", "MULU", "MULA", "MULL", "MULLU", "MULAL", "MULALU"} {
		for _, condition := range []string{"", "EQ", "NE", "CS", "CC", "HS", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL"} {
			for _, flags := range []bool{false, true} {
				cases = append(cases, armMultiplyRuntimeCase{op: op, condition: condition, setFlags: flags})
				if op == "MUL" || op == "MULU" {
					cases = append(cases, armMultiplyRuntimeCase{op: op, condition: condition, setFlags: flags, twoOperands: true})
				}
			}
		}
	}
	return cases
}

func armMultiplyRuntimeSource(cases []armMultiplyRuntimeCase) string {
	var source strings.Builder
	source.WriteString("TEXT oracle(SB),4,$0-20\n MOVW out+16(FP),R4\n")
	for index, test := range cases {
		mnemonic := test.op
		if test.condition != "" {
			mnemonic += "." + test.condition
		}
		if test.setFlags {
			mnemonic += ".S"
		}
		args := "R0,R1,R3"
		if test.twoOperands {
			args = "R0,R3"
		} else if test.op == "MULA" {
			args = "R0,R1,R2,R3"
		} else if test.op != "MUL" && test.op != "MULU" {
			args = "R0,R1,(R5,R3)"
		}
		fmt.Fprintf(&source, " MOVW value+0(FP),R0\n MOVW amount+4(FP),R1\n MOVW lhs+8(FP),R2\n MOVW R2,R3\n MOVW $0x89abcdef,R5\n MOVW status+12(FP),R6\n MOVW R6,CPSR\n %s %s\n MOVW R3,%d(R4)\n MOVW R5,%d(R4)\n MOVW CPSR,R6\n SRL $28,R6\n MOVW R6,%d(R4)\n", mnemonic, args, index*12, index*12+4, index*12+8)
	}
	source.WriteString(" RET\n")
	return source.String()
}

func armConditionReference(condition string, flags uint32) bool {
	n, z, c, v := flags&8 != 0, flags&4 != 0, flags&2 != 0, flags&1 != 0
	switch condition {
	case "", "AL":
		return true
	case "EQ":
		return z
	case "NE":
		return !z
	case "CS", "HS":
		return c
	case "CC", "LO":
		return !c
	case "MI":
		return n
	case "PL":
		return !n
	case "VS":
		return v
	case "VC":
		return !v
	case "HI":
		return c && !z
	case "LS":
		return !c || z
	case "GE":
		return n == v
	case "LT":
		return n != v
	case "GT":
		return !z && n == v
	case "LE":
		return z || n != v
	}
	panic("invalid reference condition")
}

func armMultiplyReference(test armMultiplyRuntimeCase, value, multiplier, accumulator, status uint32) (lo, hi, flags uint32) {
	lo, hi, flags = accumulator, 0x89abcdef, status>>28
	if !armConditionReference(test.condition, flags) {
		return lo, hi, flags
	}
	if test.twoOperands {
		multiplier = accumulator
	}
	product := uint64(value) * uint64(multiplier)
	if test.op == "MULL" || test.op == "MULAL" {
		product = uint64(int64(int32(value)) * int64(int32(multiplier)))
	}
	if test.op == "MULAL" || test.op == "MULALU" {
		product += uint64(hi)<<32 | uint64(lo)
	}
	if test.op == "MULA" {
		product += uint64(accumulator)
	}
	lo = uint32(product)
	negative, zero := lo>>31, lo == 0
	if test.op != "MUL" && test.op != "MULU" && test.op != "MULA" {
		hi = uint32(product >> 32)
		negative, zero = hi>>31, product == 0
	}
	if test.setFlags {
		flags = flags&3 | negative<<3
		if zero {
			flags |= 4
		}
	}
	return lo, hi, flags
}

func TestCrossLinuxRuntimeMatrixARMMultiplyCompleteFlags(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	cases := armMultiplyRuntimeCases()
	source := armMultiplyRuntimeSource(cases)
	var goVectors, cVectors strings.Builder
	inputs := [][3]uint32{{0, 0xffffffff, 0}, {1, 0xffffffff, 1}, {0x80000000, 2, 0x7fffffff}, {0xffffffff, 0xffffffff, 0xffffffff}, {0x7fffffff, 0x7fffffff, 0x80000000}}
	for _, input := range inputs {
		for flags := uint32(0); flags < 16; flags++ {
			fmt.Fprintf(&goVectors, "{[4]uint32{%d,%d,%d,%d},[%d]uint32{", input[0], input[1], input[2], flags<<28, 3*len(cases))
			fmt.Fprintf(&cVectors, "{{%du,%du,%du,%du},{", input[0], input[1], input[2], flags<<28)
			for _, test := range cases {
				lo, hi, status := armMultiplyReference(test, input[0], input[1], input[2], flags<<28)
				fmt.Fprintf(&goVectors, "%d,%d,%d,", lo, hi, status)
				fmt.Fprintf(&cVectors, "%du,%du,%du,", lo, hi, status)
			}
			goVectors.WriteString("}},\n")
			cVectors.WriteString("}},\n")
		}
	}
	goMain := fmt.Sprintf(`package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *[%d]uint32)
var vectors=[]struct{args [4]uint32;want [%d]uint32}{%s}
func main(){for i,v:=range vectors{var out [%d]uint32;oracle(v.args[0],v.args[1],v.args[2],v.args[3],&out);for j,w:=range v.want{if out[j]!=w{panic(fmt.Sprintf("Go multiply vector=%%d lane=%%d got=%%x want=%%x",i,j,out[j],w))}}};fmt.Println("seven multiply members, complete conditions, result widths and NZCV passed")}
`, 3*len(cases), 3*len(cases), goVectors.String(), 3*len(cases))
	runARMGoSourceOracle(t, source, goMain)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	cMain := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
static const struct{uint32_t args[4],want[%d];}vectors[]={%s};
int main(void){for(unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++){uint32_t out[%d]={0};oracle(vectors[i].args[0],vectors[i].args[1],vectors[i].args[2],vectors[i].args[3],out);for(unsigned j=0;j<%d;j++)if(out[j]!=vectors[i].want[j]){fprintf(stderr,"LLVM multiply vector=%%u lane=%%u got=%%x want=%%x\n",i,j,out[j],vectors[i].want[j]);return 1;}}return 0;}
`, 3*len(cases), cVectors.String(), 3*len(cases), 3*len(cases))
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "multiply_flags", "armv7-unknown-linux-gnueabihf", ir, cMain,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
	t.Logf("actual Go/LLVM: %d source forms x %d independent vectors", len(cases), len(inputs)*16)
}
