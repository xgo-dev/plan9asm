package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86SADNumericCase struct {
	op, bank            string
	width, imm, masking int
	memory              bool
}

func x86SADNumericCases() []x86SADNumericCase {
	var cases []x86SADNumericCase
	for _, op := range []string{"PSADBW", "VPSADBW", "MPSADBW", "VMPSADBW", "VDBPSADBW"} {
		for widthIndex, bank := range []string{"X", "Y", "Z"} {
			if !strings.HasPrefix(op, "V") && bank != "X" || op == "VMPSADBW" && bank == "Z" {
				continue
			}
			controls := []int{0}
			if strings.Contains(op, "MPS") || op == "VDBPSADBW" {
				controls = []int{0, 1, 2, 3, 4, 5, 6, 7, 27, 37, 85, 170, 228, 255}
			}
			for _, control := range controls {
				for _, memory := range []bool{false, true} {
					for mask := 0; mask < 3; mask++ {
						if mask != 0 && op != "VDBPSADBW" {
							continue
						}
						cases = append(cases, x86SADNumericCase{op, bank, 16 << widthIndex, control, mask, memory})
					}
				}
			}
		}
	}
	return cases
}

func (row x86SADNumericCase) instruction() string {
	first := row.bank + "0"
	if row.memory {
		first = "(CX)"
	}
	op := row.op
	if row.masking == 2 {
		op += ".Z"
	}
	if op == "PSADBW" {
		return op + " " + first + ",X2"
	}
	if op == "MPSADBW" {
		return fmt.Sprintf("%s $%d,%s,X2", op, row.imm, first)
	}
	if op == "VPSADBW" {
		return fmt.Sprintf("%s %s,%s1,%s2", op, first, row.bank, row.bank)
	}
	mask := ""
	if row.masking != 0 {
		mask = "K1,"
	}
	return fmt.Sprintf("%s $%d,%s,%s1,%s%s2", op, row.imm, first, row.bank, mask, row.bank)
}

func x86SADOriginalLegacyOracle(t *testing.T) {
	t.Helper()
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package sad\n")
	tests.WriteString(`package sad
import("testing";"encoding/binary")
func TestOriginal(t *testing.T) {
 var a,b [64]byte
 for sample:=0;sample<32;sample++ {
  for i:=range a {a[i]=byte(i*17+sample*31);b[i]=byte(i*73-sample*19)}
`)
	// Actual stock Go executes every legacy imm8, in both register and
	// m128 forms. It does not execute AVX512 or the Z-alias observation program.
	for _, op := range []string{"PSADBW", "MPSADBW"} {
		controls := 1
		if op == "MPSADBW" {
			controls = 256
		}
		for imm := 0; imm < controls; imm++ {
			for _, memory := range []bool{false, true} {
				name := fmt.Sprintf("original%d", strings.Count(declarations.String(), "func "))
				fmt.Fprintf(&declarations, "func %s(out *[24]byte,a,b *[64]byte,flags uint64)\n", name)
				row := x86SADNumericCase{op: op, bank: "X", width: 16, imm: imm, memory: memory}
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVUPS (CX),X0\nMOVUPS (DX),X2\nPUSHQ flags+24(FP)\nPOPFQ\n%s\nMOVUPS X2,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,16(AX)\nRET\n", name, row.instruction())
				fmt.Fprintf(&tests, `{
 var out [24]byte
 beforeA,beforeB:=a,b
 flags:=uint64(2)
 if sample&1!=0 {flags|=0x8d5}
 %s(&out,&a,&b,flags)
 want:=[8]uint16{}
`, name)
				if op == "PSADBW" {
					tests.WriteString("for i:=0;i<16;i++ {d:=int(a[i])-int(b[i]);if d<0 {d=-d};want[i/8*4]+=uint16(d)}\n")
				} else {
					fmt.Fprintf(&tests, "for word:=0;word<8;word++ {for i:=0;i<4;i++ {d:=int(a[%d+i])-int(b[%d+word+i]);if d<0 {d=-d};want[word]+=uint16(d)}}\n", (imm&3)*4, (imm>>2&1)*4)
				}
				fmt.Fprintf(&tests, "for i,w:=range want {if g:=binary.LittleEndian.Uint16(out[i*2:]);g!=w {t.Fatalf(\"%s sample%%d word%%d got%%d want%%d\",sample,i,g,w)}}\n", name)
				tests.WriteString("if binary.LittleEndian.Uint64(out[16:])&0x8d5!=flags&0x8d5 || a!=beforeA || b!=beforeB {t.Fatal(\"flags/input canary\")}\n}\n")
			}
		}
	}
	tests.WriteString("}\n}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module sad\n\ngo 1.20\n", "sad.go": declarations.String(), "sad_amd64.s": assembly.String(), "sad_test.go": tests.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual original legacy SAD oracle: %v\n%s", err, output)
	}
	t.Logf("actual original SSE %d kernels x 32 initialized samples; full status flags and unchanged input canaries", strings.Count(declarations.String(), "func "))
}

func TestCrossLinuxRuntimeMatrixX86PackedSADOriginalVEXUpperAliases(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package sad\n")
	tests.WriteString(`package sad
import("testing";"encoding/binary")
func TestOriginal(t *testing.T) {
 var a,b,old [64]byte
 for sample:=0;sample<32;sample++ {
  for i:=range a {a[i]=byte(i*17+sample*31);b[i]=byte(i*73-sample*19);old[i]=byte(0x91+i*11)}
`)
	kernels := 0
	for _, op := range []string{"PSADBW", "MPSADBW", "VPSADBW", "VMPSADBW"} {
		controls := []int{0}
		if strings.Contains(op, "MPS") {
			controls = []int{0, 1, 2, 3, 4, 5, 6, 7, 27, 37, 85, 170, 228, 255}
		}
		for _, imm := range controls {
			for _, memory := range []bool{false, true} {
				name := fmt.Sprintf("alias%d", kernels)
				kernels++
				row := x86SADNumericCase{op: op, bank: "X", width: 16, imm: imm, memory: memory}
				fmt.Fprintf(&declarations, "func %s(out *[48]byte,a,b,old *[64]byte,flags uint64)\n", name)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nMOVUPS (CX),X0\nMOVUPS (DX),X1\nVMOVUPS (R8),Y2\n", name)
				legacy := !strings.HasPrefix(op, "V")
				if legacy {
					assembly.WriteString("MOVUPS (DX),X2\n")
				}
				fmt.Fprintf(&assembly, "PUSHQ flags+32(FP)\nPOPFQ\n%s\nVMOVUPS Y2,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,32(AX)\nRET\n", row.instruction())
				fmt.Fprintf(&tests, "{\n var out,want [48]byte\n for i:=range out {out[i]=0xc3;want[i]=0xc3}\n beforeA,beforeB,beforeOld:=a,b,old\n flags:=uint64(2)\n if sample&1!=0 {flags|=0x8d5}\n %s(&out,&a,&b,&old,flags)\n sums:=[8]uint16{}\n", name)
				if strings.Contains(op, "MPS") {
					fmt.Fprintf(&tests, "for word:=0;word<8;word++ {for i:=0;i<4;i++ {d:=int(a[%d+i])-int(b[%d+word+i]);if d<0 {d=-d};sums[word]+=uint16(d)}}\n", (imm&3)*4, (imm>>2&1)*4)
				} else {
					tests.WriteString("for i:=0;i<16;i++ {d:=int(a[i])-int(b[i]);if d<0 {d=-d};sums[i/8*4]+=uint16(d)}\n")
				}
				tests.WriteString("for i,w:=range sums {binary.LittleEndian.PutUint16(want[2*i:],w)}\n")
				if legacy {
					tests.WriteString("copy(want[16:32],old[16:32])\n")
				} else {
					tests.WriteString("for i:=16;i<32;i++ {want[i]=0}\n")
				}
				tests.WriteString("observed:=binary.LittleEndian.Uint64(out[32:40])\n binary.LittleEndian.PutUint64(want[32:40],observed)\n")
				fmt.Fprintf(&tests, "if out!=want || observed&0x8d5!=flags&0x8d5 || a!=beforeA || b!=beforeB || old!=beforeOld {t.Fatalf(\"%s sample%%d actual%%x want%%x flags%%x\",sample,out,want,observed)}\n}\n", name)
			}
		}
	}
	tests.WriteString("}\n}\n")
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module sad\n\ngo 1.20\n", "sad.go": declarations.String(), "sad_amd64.s": assembly.String(), "sad_test.go": tests.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual original SSE/VEX upper-alias oracle: %v\n%s", err, output)
	}
	t.Logf("actual original SSE/VEX %d kernels x 32 initialized samples; all 32 output bytes, six status flags and canaries; no EVEX instruction executed", kernels)
}

func TestCrossLinuxRuntimeMatrixX86PackedSADIndependentWholeBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	x86SADOriginalLegacyOracle(t)
	var declarations, assembly, table strings.Builder
	declarations.WriteString("package sad\n")
	cases := x86SADNumericCases()
	for index, row := range cases {
		name := fmt.Sprintf("sad%d", index)
		fmt.Fprintf(&declarations, "func %s(out *[72]byte,a,b,old *[64]byte,mask,flags uint64)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-48\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nMOVQ mask+32(FP),R9\nVMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (R8),Z2\nKMOVQ R9,K1\n", name)
		if !strings.HasPrefix(row.op, "V") {
			assembly.WriteString("MOVUPS (DX),X2\n")
		}
		// Isolate the SAD preservation contract from arithmetic flag producers.
		// Both seeds still demand all six defined status bits, including AF.
		fmt.Fprintf(&assembly, "PUSHQ flags+40(FP)\nPOPFQ\n%s\nVMOVUPS Z2,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,64(AX)\nRET\n", row.instruction())
		kind := 0
		if strings.Contains(row.op, "MPS") {
			kind = 1
		} else if row.op == "VDBPSADBW" {
			kind = 2
		}
		legacy := 0
		if !strings.HasPrefix(row.op, "V") {
			legacy = 1
		}
		fmt.Fprintf(&table, "{sad%d,%d,%d,%d,%d,%d},\n", index, kind, row.width, row.imm, row.masking, legacy)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	pkg := mustGoPackage(t, "sad", declarations.String())
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for index := range cases {
		name := fmt.Sprintf("sad%d", index)
		sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sigs[name] = sig
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, Options{
		Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	var main strings.Builder
	main.WriteString(`#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef void (*kernel)(void*,const void*,const void*,const void*,uint64_t,uint64_t);
`)
	for index := range cases {
		fmt.Fprintf(&main, "extern void sad%d(void*,const void*,const void*,const void*,uint64_t,uint64_t);\n", index)
	}
	main.WriteString("static const struct {kernel run;int kind,width,imm,masking,legacy;} cases[]={\n" + table.String() + "};\n")
	main.WriteString(`
static unsigned diff(unsigned a,unsigned b) {return a>b ? a-b : b-a;}
static void reference(uint8_t *out,int kind,int width,int imm,const uint8_t *a,const uint8_t *b) {
 memset(out,0,width);
 uint16_t sums[32]={0};
 if(kind==0) {
  for(int i=0;i<width;++i) sums[i/8*4]+=diff(a[i],b[i]);
 } else if(kind==1) {
  for(int lane=0;lane<width/16;++lane) {
   int select=imm>>(3*lane),block=lane*16+(select&3)*4,window=lane*16+((select>>2)&1)*4;
   for(int word=0;word<8;++word) for(int i=0;i<4;++i) sums[lane*8+word]+=diff(a[block+i],b[window+word+i]);
  }
 } else {
  for(int lane=0;lane<width/16;++lane) {
   uint8_t shuffled[16];
   for(int d=0;d<4;++d) memcpy(shuffled+4*d,a+lane*16+((imm>>(2*d))&3)*4,4);
   for(int word=0;word<8;++word) for(int i=0;i<4;++i)
    sums[lane*8+word]+=diff(shuffled[(word/4)*8+word%4+i],b[lane*16+(word/4)*8+(word%4/2)*4+i]);
  }
 }
 for(int word=0;word<width/2;++word) {out[2*word]=sums[word]&255;out[2*word+1]=sums[word]>>8;}
}
int main(void) {
 for(unsigned row=0;row<sizeof(cases)/sizeof(cases[0]);++row) for(unsigned sample=0;sample<32;++sample) {
  _Alignas(64) uint8_t aa[96],bb[96],old[64];uint8_t out[80],want[80],beforeA[96],beforeB[96],result[64];
  memset(aa,0xa7,sizeof(aa));memset(bb,0xb9,sizeof(bb));memset(out,0xc3,sizeof(out));memcpy(want,out,sizeof(out));
  uint8_t *a=aa+16,*b=bb+16;
  for(int i=0;i<64;++i) {a[i]=(uint8_t)(i*17+sample*31);b[i]=(uint8_t)(i*73-sample*19);old[i]=(uint8_t)(0x91+i*11);}
  memcpy(beforeA,aa,sizeof(aa));memcpy(beforeB,bb,sizeof(bb));
  uint64_t mask=sample%4==0 ? 0 : sample%4==1 ? UINT64_MAX : sample%4==2 ? UINT64_C(0xaaaaaaaaaaaaaaaa) : UINT64_C(0x5555555555555555);
  uint64_t seededFlags=2|(sample&1 ? 0x8d5 : 0);
  cases[row].run(out+1,a,b,old,mask,seededFlags);
  reference(result,cases[row].kind,cases[row].width,cases[row].imm,a,b);
  for(int i=0;i<64;++i) {
   uint8_t value=i<cases[row].width ? result[i] : cases[row].legacy ? old[i] : 0;
   if(i<cases[row].width && cases[row].masking && !(mask>>(i/2)&1)) value=cases[row].masking==2 ? 0 : old[i];
   want[1+i]=value;
  }
  uint64_t flags;memcpy(&flags,out+65,8);memcpy(want+65,&flags,8);
  if((flags&0x8d5)!=(seededFlags&0x8d5) || memcmp(out,want,sizeof(out)) || memcmp(aa,beforeA,sizeof(aa)) || memcmp(bb,beforeB,sizeof(bb))) {
   fprintf(stderr,"SAD row=%u kind=%d width=%d imm=%d masking=%d legacy=%d sample=%u flags=%llx\n",row,cases[row].kind,cases[row].width,cases[row].imm,cases[row].masking,cases[row].legacy,sample,(unsigned long long)flags);
   for(int i=0;i<80;++i) if(out[i]!=want[i]) fprintf(stderr,"byte%d got=%u want=%u\n",i,out[i],want[i]);
   return 1;
  }
 }
 return 0;
}
`)
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			ir := module.String()
			if optimized {
				ir = x86MulDivRoundOptimize(t, ir)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "sad-independent-whole-bytes", triple, ir, main.String(), prefix)
			t.Logf("%d initialized kernels x 32 inputs; all 64 alias bytes, merge/zero masks, six status flags and canaries", len(cases))
		})
	}
	// These are LLVM software-lowering numerical tests plus actual original
	// SSE execution. Z source acceptance/objects do not prove native AVX512.
}
