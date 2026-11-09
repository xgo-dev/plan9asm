package plan9asm

import (
	"encoding/base64"
	"fmt"
	"go/types"
	"math"
	"strings"
	"testing"
)

type x86X87NativeArithmeticCase struct {
	name, op, typ, form string
}

// These are numerical fixtures, not instruction permissions. The independent
// original Go program executes the same complete bodies as public lowering.
func x86X87NativeArithmeticCases(t *testing.T) []x86X87NativeArithmeticCase {
	t.Helper()
	var rows []x86X87NativeArithmeticCase
	for _, stem := range []string{"FADD", "FMUL", "FSUB", "FSUBR", "FDIV", "FDIVR"} {
		for _, width := range []struct{ suffix, typ string }{{"W", "int16"}, {"L", "int32"}, {"F", "float32"}, {"D", "float64"}} {
			rows = append(rows, x86X87NativeArithmeticCase{stem + width.suffix + "Memory", stem + width.suffix, width.typ, "memory"})
		}
		for _, shape := range []struct{ name, suffix, form string }{
			{"RegToF0", "D", "register-source"}, {"F0ToReg", "D", "register-destination"},
			{"PopToReg", "DP", "pop"}, {"Alias", "D", "alias"}, {"PopAlias", "DP", "pop-alias"},
		} {
			rows = append(rows, x86X87NativeArithmeticCase{stem + shape.name, stem + shape.suffix, "float64", shape.form})
		}
	}
	if len(rows) != 54 {
		t.Fatal("complete six arithmetic stems/four memory/three register/two alias forms changed")
	}
	return rows
}

func x86X87NativeArithmeticBundle(t *testing.T, arch string) (source, declarations string) {
	t.Helper()
	var assembly, goSource strings.Builder
	for _, row := range x86X87NativeArithmeticCases(t) {
		declaration := fmt.Sprintf("func Value%s(cw uint16,left float64,right %s) float64", row.name, row.typ)
		pkg := mustGoPackage(t, "nativearithmetic", "package nativearithmetic\n"+declaration)
		sig, err := DeriveGoFuncABI0Signature("Value"+row.name, pkg.Types.Scope().Lookup("Value"+row.name).(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil || len(sig.Frame.Params) != 3 || len(sig.Frame.Results) != 1 {
			t.Fatal("actual arithmetic declaration layout", row.name, err)
		}
		cw, left, right, result := sig.Frame.Params[0].Offset, sig.Frame.Params[1].Offset, sig.Frame.Params[2].Offset, sig.Frame.Results[0].Offset
		fmt.Fprintf(&assembly, "TEXT ·Value%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\n", row.name, result+8, cw)
		loadLeft := fmt.Sprintf("FMOVD left+%d(FP),F0\n", left)
		loadRight := fmt.Sprintf("FMOVD right+%d(FP),F0\n", right)
		store := fmt.Sprintf("FMOVDP F0,ret+%d(FP)\n", result)
		switch row.form {
		case "memory":
			assembly.WriteString(loadLeft)
			fmt.Fprintf(&assembly, "%s right+%d(FP),F0\n%s", row.op, right, store)
		case "register-source":
			assembly.WriteString(loadRight + loadLeft + row.op + " F1,F0\n" + store + "FMOVDP F0,F0\n")
		case "register-destination":
			assembly.WriteString(loadLeft + loadRight + row.op + " F0,F1\nFMOVDP F0,F0\n" + store)
		case "pop":
			assembly.WriteString(loadLeft + loadRight + row.op + " F0,F1\n" + store)
		case "alias":
			assembly.WriteString(loadLeft + row.op + " F0,F0\n" + store)
		case "pop-alias":
			assembly.WriteString(loadRight + loadLeft + row.op + " F0,F0\n" + store)
		}
		assembly.WriteString("RET\n")
		goSource.WriteString(declaration + "\n")
	}
	return assembly.String(), goSource.String()
}

type x86X87NativeArithmeticInput struct {
	left, right uint64
	integer     int64
}

var x86X87NativeArithmeticInputs = []x86X87NativeArithmeticInput{
	{0x3ff0000000000000, math.Float64bits(0x1p-54), 1},
	{0x3ff0000000000000, math.Float64bits(0x1p-63), -1},
	{0x3ff8000000000000, 0xc004000000000000, 32767},
	{1, 0x3fe0000000000000, -32768},
	{0x7fefffffffffffff, 0x4000000000000000, 2147483647},
	{0x7ff0000000000000, 0, -2147483648},
	{0x7ff8000000001234, 0x3ff0000000000000, 2},
	{0x8000000000000000, 0x3ff0000000000000, -2},
}

func x86X87NativeArithmeticOriginalDriver(t *testing.T, declarations string) string {
	t.Helper()
	var calls, inputs strings.Builder
	for _, input := range x86X87NativeArithmeticInputs {
		fmt.Fprintf(&inputs, "{0x%x,0x%x,%d},\n", input.left, input.right, input.integer)
	}
	for _, row := range x86X87NativeArithmeticCases(t) {
		right := "math.Float64frombits(in.right)"
		if row.typ == "float32" {
			right = "float32(" + right + ")"
		} else if row.typ == "int16" || row.typ == "int32" {
			right = row.typ + "(in.integer)"
		}
		fmt.Fprintf(&calls, "for _,pc:=range []uint16{0,0x200,0x300}{for rc:=uint16(0);rc<4;rc++{for _,in:=range inputs{value:=Value%s(0x7f|pc|rc<<10,math.Float64frombits(in.left),%s);binary.LittleEndian.PutUint64(out[:],math.Float64bits(value));if _,err:=os.Stdout.Write(out[:]);err!=nil{panic(err)}}}}\n", row.name, right)
	}
	return "package main\nimport(\"encoding/binary\";\"math\";\"os\";\"runtime\";\"unsafe\")\n" + declarations + `
func SaveState(*byte)
func RestoreState(*byte)
func main(){
runtime.LockOSThread()
var saved,after [528]byte
savedOffset:=(-uintptr(unsafe.Pointer(&saved[0])))&15
afterOffset:=(-uintptr(unsafe.Pointer(&after[0])))&15
SaveState(&saved[savedOffset])
defer func(){
 RestoreState(&saved[savedOffset]);SaveState(&after[afterOffset])
 a,b:=saved[savedOffset:],after[afterOffset:]
 for i:=0;i<5;i++{if a[i]!=b[i]{panic("caller x87 state not restored")}}
 top:=(a[3]>>3)&7
 for i:=0;i<8;i++{if a[4]&(1<<((top+byte(i))&7))!=0{for j:=0;j<10;j++{if a[32+16*i+j]!=b[32+16*i+j]{panic("caller live x87 value not restored")}}}}
}()
inputs:=[]struct{left,right uint64;integer int64}{` + inputs.String() + `}
var out [8]byte
` + calls.String() + `}
`
}

func x86X87NativeStateAssembly(arch string) string {
	word, move, suffix := 8, "MOVQ", "64"
	if arch == "386" {
		word, move, suffix = 4, "MOVL", ""
	}
	return fmt.Sprintf("#include \"textflag.h\"\nTEXT ·SaveState(SB),NOSPLIT,$0-%d\n%s state+0(FP),AX\nFXSAVE%s (AX)\nRET\nTEXT ·RestoreState(SB),NOSPLIT,$0-%d\n%s state+0(FP),AX\nFXRSTOR%s (AX)\nRET\n", word, move, suffix, word, move, suffix)
}

func TestX86X87NativeArithmeticNumericalArtifacts(t *testing.T) {
	source, declarations := x86X87NativeArithmeticBundle(t, "amd64")
	// Source/data artifacts are not execution evidence. Each runtime consumer
	// must pair the exact original Go binary records with this complete source.
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86X87InitializedWordAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api, X87Hardware)
		if err != nil || ir == "" {
			t.Fatal("complete native arithmetic family", api, err)
		}
		t.Log("X87_BINARY80_ARITHMETIC_" + api + "_IR_BASE64=" + base64.StdEncoding.EncodeToString([]byte(ir)))
	}
	t.Log("X87_BINARY80_ARITHMETIC_SOURCE_BASE64=" + base64.StdEncoding.EncodeToString([]byte(source)))
	t.Log("X87_BINARY80_ARITHMETIC_GO_BASE64=" + base64.StdEncoding.EncodeToString([]byte(x86X87NativeArithmeticOriginalDriver(t, declarations))))
	t.Log("X87_BINARY80_ARITHMETIC_STATE_BASE64=" + base64.StdEncoding.EncodeToString([]byte(x86X87NativeStateAssembly("amd64"))))
}

func TestX86X87NativeArithmeticFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		source, declarations := x86X87NativeArithmeticBundle(t, target.arch)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, target.arch, target.triple, api, X87Hardware)
			if err != nil || ir == "" {
				t.Fatal("complete arithmetic family", target.triple, api, err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(target.triple+"/"+api+"/"+level, func(t *testing.T) {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				})
			}
		}
	}
}

func x86X87NativeArithmeticCDriver(t *testing.T) string {
	t.Helper()
	var prototypes, inputs, calls strings.Builder
	for _, input := range x86X87NativeArithmeticInputs {
		narrow := math.Float32bits(float32(math.Float64frombits(input.right)))
		fmt.Fprintf(&inputs, "{UINT64_C(0x%x),UINT64_C(0x%x),INT64_C(%d),UINT32_C(0x%x)},\n", input.left, input.right, input.integer, narrow)
	}
	for _, row := range x86X87NativeArithmeticCases(t) {
		typ, right := "double", "((Double){.bits=inputs[i].right}).value"
		switch row.typ {
		case "int16":
			typ, right = "int16_t", "(int16_t)inputs[i].integer"
		case "int32":
			typ, right = "int32_t", "(int32_t)inputs[i].integer"
		case "float32":
			typ, right = "float", "((Float){.bits=inputs[i].narrow}).value"
		}
		fmt.Fprintf(&prototypes, "extern double Value%s(uint16_t,double,%s);\n", row.name, typ)
		fmt.Fprintf(&calls, `for(unsigned pc=0;pc<3;pc++)for(unsigned rc=0;rc<4;rc++)for(unsigned i=0;i<8;i++) {
  Double actual={.value=Value%s((uint16_t)(0x7f|precision[pc]|rc<<10),((Double){.bits=inputs[i].left}).value,%s)};
  uint64_t expected=0;
  if(fread(&expected,sizeof(expected),1,reference)!=1||actual.bits!=expected) {
    fprintf(stderr,"original Go/LLVM %s PC=%%u RC=%%u input=%%u got=%%016llx want=%%016llx\n",pc==0?24:pc==1?53:64,rc,i,(unsigned long long)actual.bits,(unsigned long long)expected);
    failed=1;goto done;
  }
  checks++;
}
`, row.name, right, row.name)
	}
	return `#include <stdint.h>
#include <stdio.h>
typedef union {uint64_t bits;double value;} Double;
typedef union {uint32_t bits;float value;} Float;
` + prototypes.String() + `
static const struct {uint64_t left,right;int64_t integer;uint32_t narrow;} inputs[]={
` + inputs.String() + `};
int main(int argc,char **argv) {
  if(argc!=2)return 1;
  FILE *reference=fopen(argv[1],"rb");
  if(!reference)return 2;
  unsigned char saved[512] __attribute__((aligned(16))),after[512] __attribute__((aligned(16)));
  __asm__ volatile("fxsave %0":"=m"(saved)::"memory");
  const uint16_t precision[]={0,0x200,0x300};
  unsigned checks=0;
  int failed=0;
` + calls.String() + `
  if(fgetc(reference)!=EOF||ferror(reference)||checks!=5184)failed=3;
done:
  __asm__ volatile("fxsave %0":"=m"(after)::"memory");
  if(after[4]!=0||(after[3]&0x38)!=0)failed=4;
  __asm__ volatile("fxrstor %0"::"m"(saved):"memory");
  if(fclose(reference)!=0)failed=5;
  if(failed)return failed;
  printf("binary80 arithmetic original-Go/LLVM checks=%u\n",checks);
  return 0;
}
`
}
