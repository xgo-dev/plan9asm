package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ExplicitMultiplyDeclaredBytesAndFlags(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, goTest, reference strings.Builder
	declarations.WriteString("package explicitmul\n")
	goTest.WriteString(`package explicitmul
import "testing"

func signed(value uint64,bits int) int64 {
 if bits==16 { return int64(int16(value)) }
 if bits==32 { return int64(int32(value)) }
 return int64(value)
}
func expected(a,b uint64,bits int) (uint64,uint8) {
 x,y:=signed(a,bits),signed(b,bits)
 product:=uint64(x)*uint64(y)
 flag:=uint8(0)
 if bits<64 {
  wide:=x*y
  if signed(product,bits)!=wide { flag=3 }
 } else if x!=0 {
  low:=int64(product)
  if x==-1&&y==(-1<<63)||low/x!=y { flag=3 }
 }
 if bits==16 { product=b&^uint64(65535)|uint64(uint16(product)) }
 if bits==32 { product=uint64(uint32(product)) }
 return product,flag
}
func TestOriginal(t *testing.T) {
 for sample:=uint64(0);sample<257;sample++ {
  x:=sample*0x9e3779b97f4a7c15
  y:=sample*0xd1b54a32d192ed03^0xfaceb00c01234567
`)
	reference.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int64_t signed_bits(uint64_t value,int bits) {
 if(bits==16) return (int16_t)value;
 if(bits==32) return (int32_t)value;
 return (int64_t)value;
}
static uint64_t expected(uint64_t a,uint64_t b,int bits,uint8_t *flags) {
 __int128 wide=(__int128)signed_bits(a,bits)*signed_bits(b,bits);
 uint64_t low=(uint64_t)wide;
 *flags=signed_bits(low,bits)!=wide?3:0;
 if(bits==16) low=(b&~UINT64_C(65535))|(uint16_t)low;
 if(bits==32) low=(uint32_t)low;
 return low;
}
`)
	var checks strings.Builder
	kinds := []string{"Reg", "Alias", "FP", "AUTO", "Imm8", "Imm32", "ThreeReg", "ThreeFP", "ThreeAUTO"}
	immediates := make(map[string]x86IMULImmediateCase)
	for _, literal := range x86IMULImmediateCases {
		if literal.only386 {
			continue // This numerical execution is AMD64; every 386 row has object/byte coverage.
		}
		for _, prefix := range []string{"TwoLiteral", "ThreeLiteral"} {
			kind := prefix + literal.name
			kinds = append(kinds, kind)
			immediates[kind] = literal
		}
	}
	for _, bits := range []int{16, 32, 64} {
		suffix := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
		for _, kind := range kinds {
			name := fmt.Sprintf("Mul%d%s", bits, kind)
			operation, a, b := "IMUL"+suffix+" AX,BX", "x", "y"
			switch kind {
			case "Reg":
				// The register form is the initialized default above.
			case "Alias":
				operation, a = "IMUL"+suffix+" BX,BX", "y"
			case "FP":
				operation = "IMUL" + suffix + " x+0(FP),BX"
			case "AUTO":
				operation = "IMUL" + suffix + " value-16(SP),BX"
			case "Imm8":
				operation, a = "IMUL"+suffix+" $-7,BX", "uint64(0xfffffffffffffff9)"
			case "Imm32":
				operation, a = "IMUL"+suffix+" $2147483648,BX", "uint64(0xffffffff80000000)"
			case "ThreeReg", "ThreeFP", "ThreeAUTO":
				source := map[string]string{"ThreeReg": "AX", "ThreeFP": "x+0(FP)", "ThreeAUTO": "value-16(SP)"}[kind]
				operation, a, b = "IMUL3"+suffix+" $65537,"+source+",BX", "uint64(65537)", "x"
			default:
				literal := immediates[kind]
				// The independent mathematical references use the architectural
				// signed immediate, not the production descriptor or formatter.
				a = fmt.Sprintf("uint64(0x%x)", uint64(int64(int32(literal.value))))
				operation = "IMUL" + suffix + " $" + literal.literal + ",BX"
				if strings.HasPrefix(kind, "ThreeLiteral") {
					operation, b = "IMUL3"+suffix+" $"+literal.literal+",AX,BX", "x"
				}
			}
			// Word results preserve the old destination's high bytes, not the
			// source's. Both references supply that independently below.
			for _, flags := range []bool{false, true} {
				function, typ, size := name, "uint64", 24
				if flags {
					function, typ, size = name+"Flags", "uint8", 17
				}
				fmt.Fprintf(&declarations, "func %s(x,y uint64) %s\n", function, typ)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$32-%d\nMOVQ x+0(FP),AX\nMOVQ y+8(FP),BX\nMOVQ AX,value-16(SP)\n%s\n", function, size, operation)
				if flags {
					assembly.WriteString("MOVL $0,DX\nSETCS DX\nSETOS AX\nMOVBLZX DX,DX\nMOVBLZX AX,AX\nADDL AX,AX\nORL AX,DX\nMOVB DX,ret0+16(FP)\nRET\n")
				} else {
					assembly.WriteString("MOVQ BX,ret0+16(FP)\nRET\n")
				}
			}
			fmt.Fprintf(&goTest, "{ want,flags:=expected(%s,%s,%d);", a, b, bits)
			if bits == 16 {
				goTest.WriteString("want=y&^uint64(65535)|uint64(uint16(want));")
			}
			fmt.Fprintf(&goTest, "if got:=%s(x,y);got!=want { t.Fatalf(\"%s sample%%d got%%x want%%x\",sample,got,want) };if got:=%sFlags(x,y);got!=flags { t.Fatalf(\"%s flags sample%%d got%%x want%%x\",sample,got,flags) }}\n", name, name, name, name)
			fmt.Fprintf(&reference, "extern uint64_t %s(uint64_t,uint64_t);\nextern uint8_t %sFlags(uint64_t,uint64_t);\n", name, name)
			ca := strings.ReplaceAll(a, "uint64(", "UINT64_C(")
			cb := strings.ReplaceAll(b, "uint64(", "UINT64_C(")
			fmt.Fprintf(&checks, "{ uint8_t flags;uint64_t want=expected(%s,%s,%d,&flags);", ca, cb, bits)
			if bits == 16 {
				checks.WriteString("want=(y&~UINT64_C(65535))|(uint16_t)want;")
			}
			fmt.Fprintf(&checks, "struct {uint64_t before,value,after;} out={UINT64_C(0x1122334455667788),%s(x,y),UINT64_C(0x8877665544332211)};if(out.value!=want||%sFlags(x,y)!=flags||out.before!=UINT64_C(0x1122334455667788)||out.after!=UINT64_C(0x8877665544332211)) {fprintf(stderr,\"%s sample%%llu got%%llx want%%llx flags%%u\\n\",(unsigned long long)sample,(unsigned long long)out.value,(unsigned long long)want,flags);return 1;}}\n", name, name, name)
		}
	}
	goTest.WriteString("}\n}\n")
	reference.WriteString("int main(void) {for(uint64_t sample=0;sample<257;sample++){uint64_t x=sample*UINT64_C(0x9e3779b97f4a7c15),y=sample*UINT64_C(0xd1b54a32d192ed03)^UINT64_C(0xfaceb00c01234567);\n" + checks.String() + "}\nreturn 0;}\n")
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module explicitmul\n\ngo 1.20\n", "mul.go": declarations.String(),
		"mul_amd64.s": assembly.String(), "mul_test.go": goTest.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	binary := filepath.Join(dir, "original.test")
	command := exec.Command("go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	output := execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatalf("original Go explicit multiplication has no successful terminal: %s", output)
	}
	pkg := mustGoPackage(t, "example.invalid/explicitmul", declarations.String())
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); err != nil {
			t.Fatal(err)
		}
		sigs[name] = sig
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "typed-multiply", ir, reference.String(), level)
		})
	}
	if !t.Failed() {
		t.Logf("original Go/LLVM %d initialized multiplication forms plus %d CF/OF kernels ×257 inputs; full word aliases, scalar results and canaries; no frame/caller/source permission", 3*len(kinds), 3*len(kinds))
	}
}
