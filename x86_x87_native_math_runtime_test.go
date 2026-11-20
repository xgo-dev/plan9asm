package plan9asm

import (
	"encoding/base64"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

type x87NativeMathRuntimeCase struct {
	name, op string
	inputs   int
	second   bool
}

func x87NativeMathRuntimeCases() []x87NativeMathRuntimeCase {
	var cases []x87NativeMathRuntimeCase
	for _, op := range []string{"F2XM1", "FCOS", "FSIN", "FPATAN", "FPREM", "FPREM1", "FPTAN", "FSCALE", "FSINCOS", "FXTRACT", "FYL2X", "FYL2XP1"} {
		inputs := 2
		if op == "F2XM1" || op == "FCOS" || op == "FSIN" || op == "FPTAN" || op == "FSINCOS" || op == "FXTRACT" {
			inputs = 1
		}
		cases = append(cases, x87NativeMathRuntimeCase{op, op, inputs, false})
		if op == "FPTAN" || op == "FSINCOS" || op == "FXTRACT" {
			cases = append(cases, x87NativeMathRuntimeCase{op + "Second", op, inputs, true})
		}
	}
	return cases
}

func x87NativeMathRuntimeProgram(t *testing.T) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	for _, row := range x87NativeMathRuntimeCases() {
		name := "Math" + row.name
		declaration := fmt.Sprintf("func %s(cw uint16,a,b int16) float64\n", name)
		pkg := mustGoPackage(t, "nativemath", "package nativemath\n"+declaration)
		sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil || len(sig.Frame.Params) != 3 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != LLVMType("double") {
			t.Fatal("actual native math declaration layout", name, sig, err)
		}
		result := sig.Frame.Results[0].Offset
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\n", name, result+8, sig.Frame.Params[0].Offset)
		if row.inputs == 2 {
			fmt.Fprintf(&source, "FMOVW b+%d(FP),F0\n", sig.Frame.Params[2].Offset)
		}
		fmt.Fprintf(&source, "FMOVW a+%d(FP),F0\n%s\n", sig.Frame.Params[1].Offset, row.op)
		pair := row.op == "FPTAN" || row.op == "FSINCOS" || row.op == "FXTRACT"
		if row.second {
			source.WriteString("FMOVDP F0,F0\n")
		}
		fmt.Fprintf(&source, "FMOVDP F0,ret+%d(FP)\n", result)
		if pair && !row.second || row.inputs == 2 && row.op != "FPATAN" && row.op != "FYL2X" && row.op != "FYL2XP1" {
			source.WriteString("FMOVDP F0,F0\n")
		}
		source.WriteString("RET\n")
		declarations.WriteString(declaration)
	}
	return source.String(), declarations.String()
}

type x87NativeMathRuntimeInput struct {
	kernel int
	a, b   int16
}

func x87NativeMathRuntimeInputs() []x87NativeMathRuntimeInput {
	var inputs []x87NativeMathRuntimeInput
	for kernel, row := range x87NativeMathRuntimeCases() {
		if row.inputs == 1 {
			values := []int16{0, 1, -1, 2, -2, 7, -7, 32767, -32768}
			if row.op == "F2XM1" {
				values = []int16{-1, 0, 1} // The instruction's defined finite domain.
			}
			for _, a := range values {
				inputs = append(inputs, x87NativeMathRuntimeInput{kernel: kernel, a: a})
			}
			continue
		}
		for _, pair := range [][2]int16{{0, 0}, {1, 1}, {-1, 1}, {1, -1}, {-1, -1}, {2, 3}, {3, 2}, {7, 0}, {0, -1}, {-7, 3}, {32767, -2}, {-32768, 2}} {
			inputs = append(inputs, x87NativeMathRuntimeInput{kernel, pair[0], pair[1]})
		}
	}
	return inputs
}

func x87NativeMathRuntimeDrivers() (string, string) {
	var functions, goRows, cPrototypes, cRows strings.Builder
	for _, row := range x87NativeMathRuntimeCases() {
		fmt.Fprintf(&functions, "Math%s,\n", row.name)
		fmt.Fprintf(&cPrototypes, "extern double Math%s(uint16_t,int16_t,int16_t);\n", row.name)
	}
	for _, row := range x87NativeMathRuntimeInputs() {
		fmt.Fprintf(&goRows, "{%d,%d,%d},\n", row.kernel, row.a, row.b)
		fmt.Fprintf(&cRows, "{Math%s,%d,%d},\n", x87NativeMathRuntimeCases()[row.kernel].name, row.a, row.b)
	}
	goDriver := `package main
import ("encoding/binary";"math";"os";"runtime";"unsafe")
func SaveState(*byte)
func RestoreState(*byte)
func main() {
 runtime.LockOSThread()
 var saved,after [528]byte
 savedOffset:=(-uintptr(unsafe.Pointer(&saved[0])))&15
 afterOffset:=(-uintptr(unsafe.Pointer(&after[0])))&15
 SaveState(&saved[savedOffset])
 defer RestoreState(&saved[savedOffset])
 kernels:=[]func(uint16,int16,int16)float64{` + functions.String() + `}
 inputs:=[]struct{kernel int;a,b int16}{` + goRows.String() + `}
 var output [8]byte
 for _,in:=range inputs {
  for _,pc:=range []uint16{0,0x200,0x300} {
   for rc:=uint16(0);rc<4;rc++ {
    value:=kernels[in.kernel](0x7f|pc|rc<<10,in.a,in.b)
    SaveState(&after[afterOffset])
    if after[afterOffset+4]!=0 || after[afterOffset+3]&0x38!=0 {panic("native math left an unbalanced x87 stack")}
    binary.LittleEndian.PutUint64(output[:],math.Float64bits(value))
    if _,err:=os.Stdout.Write(output[:]);err!=nil {panic(err)}
   }
  }
 }
}
`
	cDriver := `#include <stdint.h>
#include <stdio.h>
` + cPrototypes.String() + `
typedef unsigned char State[512] __attribute__((aligned(16)));
static const struct {double (*call)(uint16_t,int16_t,int16_t);int16_t a,b;} inputs[]={
` + cRows.String() + `};
int main(void) {
 State saved,after;
 __asm__ volatile("fxsave %0" : "=m"(saved) : : "memory");
 int failed=0;
 const unsigned precision[]={0,0x200,0x300};
 for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0])&&!failed;i++) {
  for(unsigned pc=0;pc<3&&!failed;pc++) {
   for(unsigned rc=0;rc<4;rc++) {
    union {double value;uint64_t bits;} result;
    result.value=inputs[i].call((uint16_t)(0x7f|precision[pc]|rc<<10),inputs[i].a,inputs[i].b);
    __asm__ volatile("fxsave %0" : "=m"(after) : : "memory");
    if(after[4] || (after[3]&0x38) || fwrite(&result.bits,8,1,stdout)!=1) {failed=1;break;}
   }
  }
 }
 __asm__ volatile("fxrstor %0" : : "m"(saved) : "memory");
 return failed;
}
`
	return goDriver, cDriver
}

func TestX86X87NativeMathNumericalArtifacts(t *testing.T) {
	source, declarations := x87NativeMathRuntimeProgram(t)
	goDriver, cDriver := x87NativeMathRuntimeDrivers()
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86X87InitializedWordAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api, X87Hardware)
		if err != nil || ir == "" {
			t.Fatal("complete initialized native mathematical source", api, err)
		}
		t.Log("X87_NATIVE_MATH_" + api + "_IR_BASE64=" + base64.StdEncoding.EncodeToString([]byte(ir)))
	}
	for name, value := range map[string]string{"SOURCE": source, "DECL": declarations, "GO": goDriver, "C": cDriver, "STATE": x86X87NativeStateAssembly("amd64")} {
		t.Log("X87_NATIVE_MATH_" + name + "_BASE64=" + base64.StdEncoding.EncodeToString([]byte(value)))
	}
	t.Logf("native math artifact inputs=%d checks=%d; artifact generation is not native execution", len(x87NativeMathRuntimeInputs()), len(x87NativeMathRuntimeInputs())*12)
}
