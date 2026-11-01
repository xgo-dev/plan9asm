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

// Independent mathematical attributes, not emitted from the production specs.
var x86LegacyIntegerArithmeticTestBytes = []int{1, 2, 4, 4, 8, 1, 2, 1, 2, 1, 2, 4, 8, 1, 2, 1, 2}
var x86LegacyIntegerArithmeticTestModes = []int{0, 0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2}

const x86LegacyIntegerArithmeticGoMath = `
func lane(value []byte) uint64 {
 var result uint64
 for i,b := range value { result |= uint64(b)<<uint(i*8) }
 return result
}
func math(a,b uint64,n,mode int,subtract bool) uint64 {
 if mode==0 {
  if subtract { return b-a }
  return b+a
 }
 if mode==2 {
  max := (uint64(1)<<uint(n*8))-1
  if subtract {
   if b<a { return 0 }
   return b-a
  }
  if a>max-b { return max }
  return a+b
 }
 sign := int64(1)<<uint(n*8-1)
 left,right := int64(a),int64(b)
 if left&sign!=0 { left-=sign*2 }
 if right&sign!=0 { right-=sign*2 }
 result := right+left
 if subtract { result=right-left }
 if result < -sign { result=-sign }
 if result > sign-1 { result=sign-1 }
 return uint64(result)
}
func fill(value []byte,n,sample,side int) {
 max := ^uint64(0)
 if n<8 { max=(uint64(1)<<uint(n*8))-1 }
 choices := []uint64{0,1,max,max>>1,(max>>1)+1,max-1,2,(max>>1)-1}
 for offset:=0;offset<16;offset+=n {
  number:=uint64(sample*71+offset*37+side*19)*0x11223344556677
  if sample<64 { number=choices[(sample/(1+side*7)+offset/n)%len(choices)] }
  for j:=0;j<n;j++ { value[offset+j]=byte(number>>uint(j*8)) }
 }
}
`

const x86LegacyIntegerArithmeticCMath = `
static uint64_t lane(const uint8_t *value,int n) {
 uint64_t result=0;
 for(int i=0;i<n;i++) result|=(uint64_t)value[i]<<(i*8);
 return result;
}
static uint64_t math(uint64_t a,uint64_t b,int n,int mode,int subtract) {
 if(!mode) return subtract?b-a:b+a;
 if(mode==2) {
  uint64_t max=(UINT64_C(1)<<(n*8))-1;
  if(subtract) return b<a?0:b-a;
  return a>max-b?max:a+b;
 }
 int64_t sign=INT64_C(1)<<(n*8-1),left=(int64_t)a,right=(int64_t)b;
 if(left&sign) left-=sign*2;
 if(right&sign) right-=sign*2;
 int64_t result=subtract?right-left:right+left;
 if(result< -sign) result= -sign;
 if(result>sign-1) result=sign-1;
 return (uint64_t)result;
}
static void fill(uint8_t *value,int n,int sample,int side) {
 uint64_t max=n==8?UINT64_MAX:(UINT64_C(1)<<(n*8))-1;
 uint64_t choices[]={0,1,max,max>>1,(max>>1)+1,max-1,2,(max>>1)-1};
 for(int offset=0;offset<16;offset+=n) {
  uint64_t number=(uint64_t)(sample*71+offset*37+side*19)*UINT64_C(0x11223344556677);
  if(sample<64) number=choices[(sample/(1+side*7)+offset/n)%8];
  for(int j=0;j<n;j++) value[offset+j]=(uint8_t)(number>>(j*8));
 }
}
`

func TestCrossLinuxRuntimeMatrixX86LegacyIntegerArithmeticOriginalMathFlagsAndCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, goTable, cTable, cDeclarations strings.Builder
	declarations.WriteString("package packedarithmetic\nfunc ReadCSR() uint32\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\n")
	for index, op := range x86LegacyIntegerArithmeticTestNames {
		for _, kind := range []string{"Register", "Alias", "Memory"} {
			name := op + kind
			source := "X1"
			if kind == "Alias" {
				source = "X0"
			} else if kind == "Memory" {
				source = "(AX)"
			}
			fmt.Fprintf(&declarations, "func %s(out,x,y *[16]byte,flags *uint64,seed uint64)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DX\nMOVQ x+8(FP),AX\nMOVQ y+16(FP),CX\nMOVOU (AX),X1\nMOVOU (CX),X0\nPUSHQ seed+32(FP)\nPOPFQ\n%s %s,X0\nMOVOU X0,(DX)\nPUSHFQ\nPOPQ BX\nMOVQ flags+24(FP),SI\nMOVQ BX,(SI)\nRET\n", name, op, source)
			fmt.Fprintf(&goTable, "{%q,%s,%d,%d,%t,%t},\n", name, name,
				x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestModes[index], index >= 9, kind == "Alias")
			fmt.Fprintf(&cDeclarations, "extern void %s(uint8_t*,uint8_t*,uint8_t*,uint64_t*,uint64_t);\n", name)
			fmt.Fprintf(&cTable, "{%q,%s,%d,%d,%d,%d},\n", name, name,
				x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestModes[index], x86FloatAddSubBoolInt(index >= 9), x86FloatAddSubBoolInt(kind == "Alias"))
		}
	}
	goTest := `package packedarithmetic
import (
 "testing"
 "unsafe"
)
` + x86LegacyIntegerArithmeticGoMath + `
func aligned(value *[80]byte) (*[16]byte,int) {
 offset:=16+int((-uintptr(unsafe.Pointer(&value[16])))&15)
 return (*[16]byte)(unsafe.Pointer(&value[offset])),offset
}

func TestOriginal(t *testing.T) {
 kernels:=[]struct {
  name string
  call func(*[16]byte,*[16]byte,*[16]byte,*uint64,uint64)
  n,mode int
  subtract,alias bool
 }{
` + goTable.String() + ` }
 for _,kernel:=range kernels {
  for sample:=0;sample<257;sample++ {
   var x,y,out [80]byte
   xp,_:=aligned(&x);yp,_:=aligned(&y);op,offset:=aligned(&out)
   for i:=range x { x[i]=0xb9;y[i]=0xa7 }
   fill(xp[:],kernel.n,sample,0);fill(yp[:],kernel.n,sample,1)
   originalX,originalY:=x,y
   for _,seed:=range []uint64{0,0x8d5} {
    for i:=range out { out[i]=0xa5 }
    box:=struct{before,value,after uint64}{0x1122334455667788,0,0x8877665544332211}
    csr:=ReadCSR()
    kernel.call(op,xp,yp,&box.value,seed)
    if box.value&0x8d5!=seed||box.before!=0x1122334455667788||box.after!=0x8877665544332211||ReadCSR()!=csr||x!=originalX||y!=originalY {
     t.Fatalf("%s state/canary sample%d flags%x",kernel.name,sample,box.value)
    }
    var want [16]byte
    for i:=0;i<16;i+=kernel.n {
     a,b:=lane(xp[i:i+kernel.n]),lane(yp[i:i+kernel.n])
     if kernel.alias { a=b }
     value:=math(a,b,kernel.n,kernel.mode,kernel.subtract)
     for j:=0;j<kernel.n;j++ { want[i+j]=byte(value>>uint(j*8)) }
    }
    for i,value:=range out {
     expected:=byte(0xa5)
     if i>=offset&&i<offset+16 { expected=want[i-offset] }
     if value!=expected { t.Fatalf("%s sample%d byte%d got%x want%x",kernel.name,sample,i,value,expected) }
    }
   }
  }
 }
}
`
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
struct Aligned { _Alignas(16) uint8_t before[16],value[16],after[16]; };
` + cDeclarations.String() + x86LegacyIntegerArithmeticCMath + `
static const struct Kernel {
 const char *name;
 void (*call)(uint8_t*,uint8_t*,uint8_t*,uint64_t*,uint64_t);
 int n,mode,subtract,alias;
} kernels[]={
` + cTable.String() + `};
int main(void) {
 for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++) {
  const struct Kernel *kernel=&kernels[k];
  for(int sample=0;sample<257;sample++) {
   struct Aligned x,y,out;
   memset(&x,0xb9,sizeof(x));memset(&y,0xa7,sizeof(y));
   fill(x.value,kernel->n,sample,0);fill(y.value,kernel->n,sample,1);
   struct Aligned originalX=x,originalY=y;
   for(int status=0;status<2;status++) {
    uint64_t seed=status?UINT64_C(0x8d5):0;
    memset(&out,0xa5,sizeof(out));
    struct {uint64_t before,value,after;} flags={UINT64_C(0x1122334455667788),0,UINT64_C(0x8877665544332211)};
    uint32_t csr=_mm_getcsr();
    kernel->call(out.value,x.value,y.value,&flags.value,seed);
    if((flags.value&UINT64_C(0x8d5))!=seed||flags.before!=UINT64_C(0x1122334455667788)||flags.after!=UINT64_C(0x8877665544332211)||_mm_getcsr()!=csr||memcmp(&x,&originalX,sizeof(x))||memcmp(&y,&originalY,sizeof(y))) {
     fprintf(stderr,"%s state/input/canary sample%d flags%llx\n",kernel->name,sample,(unsigned long long)flags.value);return 1;
    }
    for(int i=0;i<16;i+=kernel->n) {
     uint64_t a=lane(x.value+i,kernel->n),b=lane(y.value+i,kernel->n);
     if(kernel->alias) a=b;
     uint64_t expected=math(a,b,kernel->n,kernel->mode,kernel->subtract);
     for(int j=0;j<kernel->n;j++) if(out.value[i+j]!=(uint8_t)(expected>>(j*8))) {
      fprintf(stderr,"%s sample%d byte%d got%x want%x\n",kernel->name,sample,i+j,out.value[i+j],(unsigned)(uint8_t)(expected>>(j*8)));return 2;
     }
    }
    for(int i=0;i<16;i++) if(out.before[i]!=0xa5||out.after[i]!=0xa5) return 3;
   }
  }
 }
 return 0;
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module packedarithmetic\n\ngo 1.20\n", "arithmetic.go": declarations.String(),
		"arithmetic_amd64.s": assembly.String(), "arithmetic_test.go": goTest,
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
		t.Fatalf("original Go legacy arithmetic lacks successful terminal: %s", output)
	}
	pkg := mustGoPackage(t, "example.invalid/packedarithmetic", declarations.String())
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
			execution.compileAndRunLLVM(t, "legacy-integer-arithmetic", ir, main, level)
		})
	}
	if !t.Failed() {
		t.Log("51 original-Go/LLVM XMM kernels ×257 initialized boundary/random samples ×2 full-six-flag seeds, complete bytes/inputs/MXCSR/canaries; Darwin/Rosetta is not native AMD64/386 fault proof.")
	}
}

func TestCrossLinuxRuntimeMatrixX86LegacyIntegerArithmeticOriginalMMXBank(t *testing.T) {
	// Go's GP-looking source is an MMX ModRM spelling, not an ABI GP input.
	// This original-Go-only oracle does not initialize the LLVM/MMX observer.
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, table strings.Builder
	declarations.WriteString("package packedmmx\nfunc ReadCSR() uint32\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\n")
	spellings := []string{"M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for opIndex, op := range x86LegacyIntegerArithmeticTestNames {
		if !strings.HasPrefix(op, "PADD") || op == "PADDQ" {
			continue
		}
		for index, spelling := range spellings {
			name := fmt.Sprintf("%sBank%d", op, index)
			fmt.Fprintf(&declarations, "func %s(a,b,c,d,e,f,v,h uint64,flags *uint64,seed uint64) uint64\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-88\n", name)
			for bank, parameter := range []string{"a", "b", "c", "d", "e", "f", "v", "h"} {
				fmt.Fprintf(&assembly, "MOVQ %s+%d(FP),M%d\n", parameter, bank*8, bank)
			}
			// Do not change native SP/BP/g. Other GP values deliberately do not
			// match any initialized MMX value.
			for _, reg := range []string{"AX", "CX", "DX", "BX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"} {
				fmt.Fprintf(&assembly, "MOVQ $0x5a5a5a5a,%s\n", reg)
			}
			fmt.Fprintf(&assembly, "PUSHQ seed+72(FP)\nPOPFQ\n%s %s,M7\nMOVQ M7,ret0+80(FP)\nEMMS\nPUSHFQ\nPOPQ AX\nMOVQ flags+64(FP),DX\nMOVQ AX,(DX)\nRET\n", op, spelling)
			fmt.Fprintf(&table, "{%q,%s,%d,%d,%d},\n", name, name, index&7,
				x86LegacyIntegerArithmeticTestBytes[opIndex], x86LegacyIntegerArithmeticTestModes[opIndex])
		}
	}
	goTest := `package packedmmx
import "testing"
` + x86LegacyIntegerArithmeticGoMath + `
func TestOriginal(t *testing.T) {
 kernels:=[]struct {
  name string
  call func(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,*uint64,uint64) uint64
  bank,n,mode int
 }{
` + table.String() + ` }
 for _,kernel:=range kernels {
  for sample:=0;sample<33;sample++ {
   var values [8]uint64
   for bank:=range values {
    var bytes [16]byte
    fill(bytes[:],kernel.n,sample,bank)
    values[bank]=lane(bytes[:8])
   }
   var want uint64
   for offset:=0;offset<8;offset+=kernel.n {
    mask:=(uint64(1)<<uint(kernel.n*8))-1
    a:=(values[kernel.bank]>>uint(offset*8))&mask
    b:=(values[7]>>uint(offset*8))&mask
    value:=math(a,b,kernel.n,kernel.mode,false)&mask
    want|=value<<uint(offset*8)
   }
   for _,seed:=range []uint64{0,0x8d5} {
    box:=struct{before,value,after uint64}{0x123456789abcdef0,0,0xfedcba9876543210}
    csr:=ReadCSR()
    got:=kernel.call(values[0],values[1],values[2],values[3],values[4],values[5],values[6],values[7],&box.value,seed)
    if got!=want||box.value&0x8d5!=seed||ReadCSR()!=csr||box.before!=0x123456789abcdef0||box.after!=0xfedcba9876543210 {
     t.Fatalf("%s sample%d result%x want%x flags%x",kernel.name,sample,got,want,box.value)
    }
   }
  }
 }
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module packedmmx\n\ngo 1.20\n", "mmx.go": declarations.String(),
		"mmx_amd64.s": assembly.String(), "mmx_test.go": goTest,
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
		t.Fatalf("original Go MMX bank oracle lacks successful terminal: %s", output)
	}
	t.Log("192 initialized original-Go MMX/GP-spelling kernels ×33 samples ×2 flags; no LLVM MMX/caller/native admission.")
}

func TestX86LegacyIntegerArithmeticWiderSoftwareAliasPreservation(t *testing.T) {
	// A directly initialized software shadow, not native Go Z-register code.
	execution := x86ScalarCountHostExecution(t)
	var ir, reference, checks strings.Builder
	profiles := make(map[string]string)
	ir.WriteString("target triple = \"" + execution.triple + "\"\n")
	reference.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + x86LegacyIntegerArithmeticCMath)
	constant := func(multiplier, addend int) string {
		var values []string
		for index := 0; index < 64; index++ {
			values = append(values, fmt.Sprintf("i8 %d", byte(index*multiplier+addend)))
		}
		return "<" + strings.Join(values, ",") + ">"
	}
	for index, op := range x86LegacyIntegerArithmeticTestNames {
		profiles[op+"Shadow"] = ""
		ins := Instr{Op: Op(op), Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}}
		fn := Func{Instrs: []Instr{{Op: "VMOVUPS", Args: []Operand{{Kind: OpReg, Reg: "Z0"}, {Kind: OpReg, Reg: "Z1"}}}, ins}}
		ctx, output := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Ret: Void}, nil)
		ctx.goarch = "amd64"
		if err := ctx.storeZ("Z0", constant(37, 11)); err != nil {
			t.Fatal(err)
		}
		if err := ctx.storeZ("Z1", constant(19, 71)); err != nil {
			t.Fatal(err)
		}
		known, term, err := ctx.lowerPackedIntegerAdd(ins.Op, ins)
		if !known {
			known, term, err = ctx.lowerPackedIntegerSubtract(ins.Op, ins)
		}
		if !known || term || err != nil {
			t.Fatal("legacy lowerer did not consume typed X bank", known, term, err)
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
		fmt.Fprintf(&checks, ` {
  memset(out,0xa5,sizeof(out));
  %sShadow(out+16);
  uint8_t a[64],b[64];
  for(int i=0;i<64;i++){a[i]=(uint8_t)(i*19+71);b[i]=(uint8_t)(i*37+11);}
  for(int offset=0;offset<16;offset+=%d){
   uint64_t value=math(lane(a+offset,%d),lane(b+offset,%d),%d,%d,%d);
   for(int j=0;j<%d;j++)b[offset+j]=(uint8_t)(value>>(j*8));
  }
  if(memcmp(out+16,b,64)||memcmp(out+80,a,64)){fprintf(stderr,"%s alias\n");return 1;}
  for(int i=0;i<16;i++)if(out[i]!=0xa5||out[144+i]!=0xa5)return 2;
 }
`, op, x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestBytes[index], x86LegacyIntegerArithmeticTestModes[index], x86FloatAddSubBoolInt(index >= 9), x86LegacyIntegerArithmeticTestBytes[index], op)
	}
	reference.WriteString("int main(void){uint8_t out[160];\n" + checks.String() + "return 0;}\n")
	// The private shadow has no ISA attributes. Use the same strict body guard
	// as public portable oracles so new native effects cannot silently enter it.
	text, err := x86PackedShiftPortableFeatureProjection(ir.String(), profiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("amd64-object", func(t *testing.T) {
		const triple = "x86_64-unknown-linux-gnu"
		crossIR := strings.Replace(text, "target triple = \""+execution.triple+"\"\n",
			"target triple = \""+triple+"\"\n", 1)
		x86ResultInitializationObject(t, execution.llc, triple, crossIR, "legacy-integer-arithmetic-alias")
	})
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "legacy-integer-arithmetic-alias", text, reference.String(), level)
		})
	}
	t.Log("17 historical software-shadow operations retain all 128 alias bytes and canaries; host execution and AMD64 object, not public/native opcode execution")
}
