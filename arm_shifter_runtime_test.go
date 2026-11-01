package plan9asm

import (
	"fmt"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func requireARMScalarRuntime(t *testing.T) string {
	t.Helper()
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for actual ARM scalar Go/LLVM execution")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM scalar runtime requires a Linux driver")
	}
	for _, tool := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	return llc
}

func runARMGoSourceOracle(t *testing.T, source, main string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module armshifteroracle\n\ngo 1.20\n", "main.go": main,
		"oracle_arm.s": strings.ReplaceAll(source, "TEXT oracle(", "TEXT ·oracle("),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go ARM oracle: %v\n%s", err, output)
	} else {
		t.Logf("actual Go oracle: %s", output)
	}
}

func armShifterOracleSignature() map[string]FuncSig {
	return map[string]FuncSig{"oracle": {
		Name: "oracle", Args: []LLVMType{I32, I32, I32, I32, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I32, Index: 0, Field: -1},
			{Offset: 4, Type: I32, Index: 1, Field: -1},
			{Offset: 8, Type: I32, Index: 2, Field: -1},
			{Offset: 12, Type: I32, Index: 3, Field: -1},
			{Offset: 16, Type: Ptr, Index: 4, Field: -1},
		}},
	}}
}

func TestCrossLinuxRuntimeMatrixARMBarrelCarryWithoutCPSRRead(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const source = `TEXT oracle(SB),4,$0-20
 MOVW value+0(FP),R0
 MOVW amount+4(FP),R1
 MOVW out+16(FP),R4
 MOVW $0,R2
 CMP $1,R2
 TST R0<<R1,R0
 MOVW $0,R3
 MOVW.CS $1,R3
 MOVW R3,(R4)
 RET
`
	runARMGoSourceOracle(t, source, `package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *uint32)
func main(){var out uint32;oracle(0x80000000,1,0,0,&out);if out!=1{panic(fmt.Sprint(out))};fmt.Println("shifted TST carry branch=1")}
`)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "barrel_carry_branch", "armv7-unknown-linux-gnueabihf", ir,
		`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
int main(void){uint32_t out=99;oracle(0x80000000u,1,0,0,&out);if(out!=1){fprintf(stderr,"LLVM carry branch=%u want=1\n",out);return 1;}return 0;}
`, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}

func TestCrossLinuxRuntimeMatrixARMRawTSTCarryEncoding(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const source = `TEXT oracle(SB),4,$0-20
 MOVW value+0(FP),R0
 MOVW out+16(FP),R4
 MOVW $0x30000000,R6
 MOVW R6,CPSR
 WORD $0xe3100001
 MOVW CPSR,R3
 SRL $28,R3
 MOVW R3,0(R4)
 MOVW $0x30000000,R6
 MOVW R6,CPSR
 WORD $0xe3100104
 MOVW CPSR,R3
 SRL $28,R3
 MOVW R3,4(R4)
 RET
`
	runARMGoSourceOracle(t, source, `package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *[2]uint32)
func main(){for _,v:=range []uint32{0,1,0xffffffff}{var out [2]uint32;oracle(v,0,0,0,&out);want:=[2]uint32{3,1};if v&1==0{want=[2]uint32{7,5}};if out!=want{panic(fmt.Sprintf("raw TST value=%x got=%v want=%v",v,out,want))}};fmt.Println("same decoded literal, distinct raw rotated-immediate carry passed")}
`)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "raw_tst_carry", "armv7-unknown-linux-gnueabihf", ir,
		`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
int main(void){const uint32_t values[]={0,1,0xffffffffu};for(unsigned i=0;i<3;i++){uint32_t out[2]={0},want[2]={3,1};if((values[i]&1)==0){want[0]=7;want[1]=5;}oracle(values[i],0,0,0,out);if(out[0]!=want[0]||out[1]!=want[1]){fprintf(stderr,"raw carry got=%u,%u want=%u,%u\n",out[0],out[1],want[0],want[1]);return 1;}}return 0;}
`, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}

func TestCrossLinuxRuntimeMatrixARMZeroShiftMemoryOffsets(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const source = `TEXT oracle(SB),4,$0-20
 MOVW value+0(FP),R0
 MOVW lhs+8(FP),R2
 MOVW out+16(FP),R4
 MOVW R2,R0>>0(R4)
 ADD $8,R4
 MOVW R2,R0->0(R4)
 ADD $8,R4
 MOVW R2,R0@>0(R4)
 RET
`
	runARMGoSourceOracle(t, source, `package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *[6]uint32)
func main(){var out [6]uint32;oracle(4,0,123,0,&out);want:=[6]uint32{0,123,0,123,0,123};if out!=want{panic(fmt.Sprint(out))};fmt.Println("Go canonicalized memory zero-shift offsets passed")}
`)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "zero_shift_memory", "armv7-unknown-linux-gnueabihf", ir,
		`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
int main(void){uint32_t out[6]={0};oracle(4,0,123,0,out);for(unsigned i=0;i<6;i++)if(out[i]!=(i&1?123u:0u)){fprintf(stderr,"zero-shift offset lane=%u got=%u\n",i,out[i]);return 1;}return 0;}
`, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}

type armShifterRuntimeCase struct {
	instruction string
	op          string
	shift       int
	amount      int // -1 means register-controlled; other values are encoded imm5.
	condition   string
	setFlags    bool
	resultReg   string
	aliasSource bool
}

func armShifterRuntimeCases() []armShifterRuntimeCase {
	var cases []armShifterRuntimeCase
	for shift, token := range []string{"<<", ">>", "->", "@>"} {
		for _, amount := range []int{-1, 0, 1, 31} {
			operand := "R0" + token + "R1"
			if amount >= 0 {
				operand = fmt.Sprintf("R0%s%d", token, amount)
			}
			for _, op := range []string{"MOVW", "MVN", "AND", "ORR", "EOR", "BIC", "TST", "TEQ"} {
				for _, condition := range []string{"", "EQ", "NE"} {
					for _, flags := range []bool{false, true} {
						if (op == "TST" || op == "TEQ") && !flags {
							continue
						}
						mnemonic := op
						if condition != "" {
							mnemonic += "." + condition
						}
						if flags && op != "TST" && op != "TEQ" {
							mnemonic += ".S"
						}
						args := operand + ",R3"
						if op == "AND" || op == "ORR" || op == "EOR" || op == "BIC" {
							args = operand + ",R2,R3"
						}
						if op == "TST" || op == "TEQ" {
							args = operand + ",R2"
						}
						cases = append(cases, armShifterRuntimeCase{instruction: mnemonic + " " + args, op: op, shift: shift, amount: amount, condition: condition, setFlags: flags})
					}
				}
			}
		}
	}
	for shift, op := range []string{"SLL", "SRL", "SRA"} {
		for _, amount := range []int{-1, 0, 1, 31, 32} {
			operand := "R1"
			if amount >= 0 {
				operand = fmt.Sprintf("$%d", amount)
			}
			for _, condition := range []string{"", "EQ", "NE"} {
				mnemonic := op + ".S"
				if condition != "" {
					mnemonic = op + "." + condition + ".S"
				}
				cases = append(cases, armShifterRuntimeCase{instruction: mnemonic + " " + operand + ",R0,R3", op: op, shift: shift, amount: amount, condition: condition, setFlags: true})
			}
		}
	}
	for shift, token := range []string{"<<", ">>", "->", "@>"} {
		for _, op := range []string{"MOVW", "MVN", "AND", "ORR", "EOR", "BIC"} {
			for _, destination := range []string{"R0", "R1"} {
				args := "R0" + token + "R1," + destination
				aliasLeft := false
				if op != "MOVW" && op != "MVN" {
					args = "R0" + token + "R1,R2," + destination
				}
				cases = append(cases, armShifterRuntimeCase{instruction: op + ".S " + args, op: op, shift: shift, amount: -1, setFlags: true, resultReg: destination, aliasSource: aliasLeft})
			}
			if op != "MOVW" && op != "MVN" {
				cases = append(cases, armShifterRuntimeCase{instruction: op + ".S R0" + token + "R1,R0", op: op, shift: shift, amount: -1, setFlags: true, resultReg: "R0", aliasSource: true})
			}
		}
	}
	return cases
}

func armShifterRuntimeSource(cases []armShifterRuntimeCase) string {
	var source strings.Builder
	source.WriteString("TEXT oracle(SB),4,$0-20\n MOVW out+16(FP),R4\n")
	for index, test := range cases {
		resultReg := test.resultReg
		if resultReg == "" {
			resultReg = "R3"
		}
		fmt.Fprintf(&source, " MOVW value+0(FP),R0\n MOVW amount+4(FP),R1\n MOVW lhs+8(FP),R2\n MOVW $0x13579bdf,R3\n MOVW status+12(FP),R6\n MOVW R6,CPSR\n %s\n MOVW %s,%d(R4)\n MOVW CPSR,R6\n SRL $28,R6\n MOVW R6,%d(R4)\n", test.instruction, resultReg, index*8, index*8+4)
	}
	source.WriteString(" RET\n")
	return source.String()
}

// This reference follows the architectural barrel shifter directly, without
// calling the translator's evaluators or reproducing their LLVM operations.
func armShifterReference(test armShifterRuntimeCase, value, amount, lhs, status uint32) (result, flags uint32) {
	result, flags = 0x13579bdf, status>>28
	if test.resultReg == "R0" {
		result = value
	} else if test.resultReg == "R1" {
		result = amount
	}
	if test.aliasSource {
		lhs = value
	}
	if test.condition == "EQ" && flags&4 == 0 || test.condition == "NE" && flags&4 != 0 {
		return result, flags
	}
	carry := flags >> 1 & 1
	count := amount & 255
	if test.amount >= 0 {
		count = uint32(test.amount) & 31
		if count == 0 && test.amount != 0 && (test.op == "SRL" || test.op == "SRA") {
			count = 32
		}
	}
	shifted := value
	if test.amount == 0 {
		count = 0 // Go oplook canonicalizes every shifted-operand zero to LSL #0.
	}
	switch test.shift {
	case 0:
		if count > 0 && count <= 32 {
			carry = value >> (32 - count) & 1
			shifted = value << count
		} else if count > 32 {
			shifted, carry = 0, 0
		}
	case 1:
		if count > 0 && count <= 32 {
			carry = value >> (count - 1) & 1
			shifted = value >> count
		} else if count > 32 {
			shifted, carry = 0, 0
		}
	case 2:
		if count > 0 {
			if count >= 32 {
				count = 32
			}
			carry = value >> (count - 1) & 1
			shifted = uint32(int32(value) >> count)
		}
	case 3:
		if count > 0 {
			shifted = bits.RotateLeft32(value, -int(count))
			carry = shifted >> 31
		}
	}
	switch test.op {
	case "MOVW", "SLL", "SRL", "SRA":
		result = shifted
	case "MVN":
		result = ^shifted
	case "AND":
		result = lhs & shifted
	case "ORR":
		result = lhs | shifted
	case "EOR":
		result = lhs ^ shifted
	case "BIC":
		result = lhs &^ shifted
	case "TST":
		shifted = lhs & shifted
	case "TEQ":
		shifted = lhs ^ shifted
	}
	if test.setFlags {
		flagResult := result
		if test.op == "TST" || test.op == "TEQ" {
			flagResult = shifted
		}
		flags = flags&1 | carry<<1 | flagResult>>31<<3
		if flagResult == 0 {
			flags |= 4
		}
	}
	return result, flags
}

func TestCrossLinuxRuntimeMatrixARMBarrelShifterFullSemantics(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	cases := armShifterRuntimeCases()
	source := armShifterRuntimeSource(cases)
	var inputs [][4]uint32
	for _, count := range []uint32{0, 1, 31, 32, 33, 63, 64, 255, 256, 257, 0x80000100, 0xffffffff} {
		for _, status := range []uint32{0, 0x30000000, 0x60000000, 0x90000000} {
			inputs = append(inputs, [4]uint32{0x80000001, count, 0x7fffffff, status})
		}
	}
	for _, value := range []uint32{0, 1, 0x7fffffff, 0x80000000, 0xffffffff} {
		for _, status := range []uint32{0, 0x30000000, 0x60000000, 0x90000000} {
			inputs = append(inputs, [4]uint32{value, 1, 0xffffffff, status})
		}
	}
	var goVectors, cVectors strings.Builder
	for _, input := range inputs {
		fmt.Fprintf(&goVectors, "{[4]uint32{%d,%d,%d,%d},[%d]uint32{", input[0], input[1], input[2], input[3], 2*len(cases))
		fmt.Fprintf(&cVectors, "{{%du,%du,%du,%du},{", input[0], input[1], input[2], input[3])
		for _, test := range cases {
			value, flags := armShifterReference(test, input[0], input[1], input[2], input[3])
			fmt.Fprintf(&goVectors, "%d,%d,", value, flags)
			fmt.Fprintf(&cVectors, "%du,%du,", value, flags)
		}
		goVectors.WriteString("}},\n")
		cVectors.WriteString("}},\n")
	}
	goMain := fmt.Sprintf(`package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *[%d]uint32)
var vectors=[]struct{args [4]uint32;want [%d]uint32}{%s}
func main(){for i,v:=range vectors{var out [%d]uint32;oracle(v.args[0],v.args[1],v.args[2],v.args[3],&out);for j,w:=range v.want{if out[j]!=w{panic(fmt.Sprintf("Go vector=%%d lane=%%d got=%%x want=%%x",i,j,out[j],w))}}};fmt.Println("complete barrel-shifter values/NZCV passed")}
`, 2*len(cases), 2*len(cases), goVectors.String(), 2*len(cases))
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
int main(void){for(unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++){uint32_t out[%d]={0};oracle(vectors[i].args[0],vectors[i].args[1],vectors[i].args[2],vectors[i].args[3],out);for(unsigned j=0;j<%d;j++)if(out[j]!=vectors[i].want[j]){fprintf(stderr,"LLVM vector=%%u lane=%%u got=%%x want=%%x\n",i,j,out[j],vectors[i].want[j]);return 1;}}return 0;}
`, 2*len(cases), cVectors.String(), 2*len(cases), 2*len(cases))
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "barrel_shifter", "armv7-unknown-linux-gnueabihf", ir, cMain,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
	t.Logf("actual Go/LLVM: %d source forms x %d independent vectors", len(cases), len(inputs))
}
