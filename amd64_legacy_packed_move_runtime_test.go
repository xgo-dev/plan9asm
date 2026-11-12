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

func TestCrossLinuxRuntimeMatrixX86LegacyPackedMoveOriginalBytesAndCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, goTest, reference, checks strings.Builder
	declarations.WriteString("package packedmove\nfunc ReadCSR() uint32\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\n")
	goTest.WriteString(`package packedmove
import (
 "testing"
 "unsafe"
)
func aligned(value *[80]byte) (*[16]byte,int) {
 offset:=16+int((-uintptr(unsafe.Pointer(&value[16])))&15)
 return (*[16]byte)(unsafe.Pointer(&value[offset])),offset
}
func TestOriginal(t *testing.T) {
 for sample:=0;sample<257;sample++ { for _,seed:=range []uint64{0,0x8d5} {
  var x,y,out [80]byte
  xp,_:=aligned(&x);yp,_:=aligned(&y);op,offset:=aligned(&out)
  for i:=range x { x[i]=byte(sample*71+i*37);y[i]=byte(sample*19+i*11);out[i]=0xa5 }
  originalX,originalY:=x,y
`)
	reference.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
struct Aligned { _Alignas(16) uint8_t before[16],value[16],after[16]; };
`)
	for _, op := range x86LegacyPackedMoveTestNames {
		for _, kind := range []string{"Register", "Alias", "Load", "Store"} {
			name := op + kind
			operation, input := op+" X1,X0\nMOVOU X0,(DX)", "xp"
			switch kind {
			case "Alias":
				operation, input = op+" X0,X0\nMOVOU X0,(DX)", "yp"
			case "Load":
				operation = op + " (AX),X0\nMOVOU X0,(DX)"
			case "Store":
				operation = op + " X1,(DX)"
			}
			fmt.Fprintf(&declarations, "func %s(out,x,y *[16]byte,flags *uint64,seed uint64)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DX\nMOVQ x+8(FP),AX\nMOVQ y+16(FP),CX\nMOVOU (AX),X1\nMOVOU (CX),X0\nPUSHQ seed+32(FP)\nPOPFQ\n%s\nPUSHFQ\nPOPQ BX\nMOVQ flags+24(FP),SI\nMOVQ BX,(SI)\nRET\n", name, operation)
			fmt.Fprintf(&goTest, `{
   for i:=range out { out[i]=0xa5 }
   box:=struct{before,value,after uint64}{0x1122334455667788,0,0x8877665544332211}
   csr:=ReadCSR()
   %s(op,xp,yp,&box.value,seed)
   if box.value&0x8d5!=seed||box.before!=0x1122334455667788||box.after!=0x8877665544332211||ReadCSR()!=csr||x!=originalX||y!=originalY { t.Fatalf("%s state/canary sample%%d flags%%x",sample,box.value) }
   for i,value:=range out {
    want:=byte(0xa5)
    if i>=offset&&i<offset+16 { want=%s[i-offset] }
    if value!=want { t.Fatalf("%s sample%%d byte%%d got%%x want%%x",sample,i,value,want) }
   }
  }
`, name, name, input, name)
			fmt.Fprintf(&reference, "extern void %s(uint8_t*,uint8_t*,uint8_t*,uint64_t*,uint64_t);\n", name)
			cinput := "x.value"
			if kind == "Alias" {
				cinput = "y.value"
			}
			fmt.Fprintf(&checks, `{
 memset(&out,0xa5,sizeof(out));
 struct {uint64_t before,value,after;} flags={UINT64_C(0x1122334455667788),0,UINT64_C(0x8877665544332211)};
 uint32_t csr=_mm_getcsr();
 %s(out.value,x.value,y.value,&flags.value,seed);
 if((flags.value&UINT64_C(0x8d5))!=seed||flags.before!=UINT64_C(0x1122334455667788)||flags.after!=UINT64_C(0x8877665544332211)||_mm_getcsr()!=csr||memcmp(&x,&originalX,sizeof(x))||memcmp(&y,&originalY,sizeof(y))) {fprintf(stderr,"%s flags/input/MXCSR sample%%d flags%%llx\n",sample,(unsigned long long)flags.value);return 1;}
 for(int i=0;i<16;i++) if(out.value[i]!=%s[i]||out.before[i]!=0xa5||out.after[i]!=0xa5) {fprintf(stderr,"%s full-byte/canary sample%%d byte%%d\n",sample,i);return 2;}
}
`, name, name, cinput, name)
		}
	}
	goTest.WriteString("}}\n}\n")
	reference.WriteString(`int main(void) {
 for(int sample=0;sample<257;sample++) { for(int status=0;status<2;status++) {
  uint64_t seed=status?UINT64_C(0x8d5):0;
  struct Aligned x,y,out;
  for(int i=0;i<sizeof(x);i++) {((uint8_t*)&x)[i]=(uint8_t)(sample*71+i*37);((uint8_t*)&y)[i]=(uint8_t)(sample*19+i*11);}
  struct Aligned originalX=x,originalY=y;
` + checks.String() + "}}\nreturn 0;}\n")
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module packedmove\n\ngo 1.20\n", "move.go": declarations.String(),
		"move_amd64.s": assembly.String(), "move_test.go": goTest.String(),
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
		t.Fatalf("original Go whole-128 moves have no successful terminal: %s", output)
	}
	pkg := mustGoPackage(t, "example.invalid/packedmove", declarations.String())
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
		sigs[name] = sig
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "legacy-packed-move", ir, reference.String(), level)
		})
	}
	if !t.Failed() {
		t.Log("28 original-Go/LLVM kernels ×257 initialized aligned samples ×2 six-flag seeds; full 16 bytes, MXCSR, inputs and canaries. Rosetta execution is diagnostic, not native AMD64/386 or unaligned fault proof.")
	}
}

func TestX86LegacyPackedMoveWiderSoftwareAliasPreservation(t *testing.T) {
	// This directly initialized LLVM-shadow fixture is not an execution of
	// original Go Z-register code and grants no physical bank or ABI input.
	execution := x86FloatCompareExecutionTools(t)
	var ir, reference, checks strings.Builder
	ir.WriteString("target triple = \"" + execution.triple + "\"\n")
	reference.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	constant := func(multiplier, addend int) string {
		var values []string
		for index := 0; index < 64; index++ {
			values = append(values, fmt.Sprintf("i8 %d", byte(index*multiplier+addend)))
		}
		return "<" + strings.Join(values, ",") + ">"
	}
	for _, op := range x86LegacyPackedMoveTestNames {
		ins := Instr{Op: Op(op), Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}}
		fn := Func{Instrs: []Instr{
			{Op: "VMOVUPS", Args: []Operand{{Kind: OpReg, Reg: "Z0"}, {Kind: OpReg, Reg: "Z1"}}}, ins,
		}}
		ctx, output := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Ret: Void}, nil)
		if err := ctx.storeZ("Z0", constant(37, 11)); err != nil {
			t.Fatal(err)
		}
		if err := ctx.storeZ("Z1", constant(19, 71)); err != nil {
			t.Fatal(err)
		}
		known, term, err := ctx.lowerFP(ins.Op, ins)
		if !known {
			known, term, err = ctx.lowerVec(ins.Op, ins)
		}
		if !known || term || err != nil {
			t.Fatal("legacy lowerer did not consume its typed X-bank shape", known, term, err)
		}
		first, err := ctx.loadZ("Z0")
		if err != nil {
			t.Fatal(err)
		}
		second, err := ctx.loadZ("Z1")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&ir, "define void @%sShadow(ptr %%out) {\n%s  store <64 x i8> %s, ptr %%out, align 1\n  %%next = getelementptr i8, ptr %%out, i64 64\n  store <64 x i8> %s, ptr %%next, align 1\n  ret void\n}\n", op, output.String(), first, second)
		fmt.Fprintf(&reference, "extern void %sShadow(uint8_t*);\n", op)
		fmt.Fprintf(&checks, "{memset(out,0xa5,sizeof(out));%sShadow(out+16);for(int i=0;i<64;i++){uint8_t want=(uint8_t)(i<16?i*19+71:i*37+11);if(out[16+i]!=want||out[80+i]!=(uint8_t)(i*19+71)){fprintf(stderr,\"%s shadow byte%%d\\n\",i);return 1;}}for(int i=0;i<16;i++)if(out[i]!=0xa5||out[144+i]!=0xa5)return 2;}\n", op, op)
	}
	reference.WriteString("int main(void){uint8_t out[160];\n" + checks.String() + "return 0;}\n")
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "legacy-packed-move-alias", ir.String(), reference.String(), level)
		})
	}
}
