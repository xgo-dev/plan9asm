package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This matrix is independent of the production operand/predicate registries.
// All six native VEX widths have every predicate and both first-source roles;
// destination aliases rotate through both sources and an independent register.
func x86FloatCompareVEXOracleCases() []x86FloatCompareOracleCase {
	var cases []x86FloatCompareOracleCase
	for _, fixture := range x86FloatCompareOriginalVectors() {
		bank := "X"
		if fixture.width == 32 {
			bank = "Y"
		}
		for predicate := 0; predicate < 32; predicate++ {
			for _, memory := range []bool{false, true} {
				first := bank + "1"
				if memory {
					first = "(CX)"
				}
				cases = append(cases, x86FloatCompareOracleCase{
					row:  fmt.Sprintf("%s $%d,%s,%s0,%s%d", fixture.opcode, predicate, first, bank, bank, predicate%3),
					bits: fixture.bits, width: fixture.width, predicate: predicate,
					scalar: fixture.scalar, memory: memory, destination: predicate % 3,
				})
			}
		}
	}
	return cases
}

func x86FloatCompareVEXOracleAssembly(cases []x86FloatCompareOracleCase) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, fixture := range cases {
		name := fmt.Sprintf("vex_compare%d", index)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-24
MOVQ out+0(FP),AX
MOVQ a+8(FP),BX
MOVQ b+16(FP),CX
VMOVUPS (BX),Y0
VMOVUPS (BX),Y2
`, name)
		if !fixture.memory {
			source.WriteString("VMOVUPS (CX),Y1\n")
		}
		source.WriteString("STC\n" + fixture.row + "\n")
		// Z is a translated shadow-view observation, not a native AVX512
		// instruction in the original-opcode reference. The expected high bytes
		// are independently zero for VEX X/Y writes. No EVEX compare is run.
		fmt.Fprintf(&source, "VMOVUPS Z%d,8(AX)\nSETCS 72(AX)\nRET\n", fixture.destination)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}}}
	}
	return source.String(), sigs
}

// Emit the actual requested whole VCMP opcode and full native memory tuple.
// Its MXCSR is an independent original-instruction reference, not a union of
// per-lane quiet/signaling representatives. IEEE truth remains integer-only.
func x86FloatCompareVEXWholeReferenceC() string {
	var source strings.Builder
	source.WriteString(x86FloatCompareIndependentC)
	for index, fixture := range x86FloatCompareOriginalVectors() {
		for variant := 0; variant < 2; variant++ {
			fmt.Fprintf(&source, `
__attribute__((target("avx"))) static void reference%d(uint8_t *out,const uint8_t *a,const uint8_t *b,unsigned predicate,unsigned csr,unsigned *after){
 typedef uint8_t vector __attribute__((vector_size(%d)));
 vector left,right,result;
 memcpy(&left,a,sizeof(left));memcpy(&right,b,sizeof(right));
 unsigned saved;uint8_t carry;
 __asm__ volatile("stmxcsr %%0":"=m"(saved));
 __asm__ volatile("ldmxcsr %%0"::"m"(csr));
 switch(predicate){
`, index*2+variant, fixture.width)
			operand := "\"x\"(right)"
			if variant == 1 {
				bytes := fixture.width
				if fixture.scalar {
					bytes = fixture.bits / 8
				}
				operand = fmt.Sprintf("\"m\"(*(const uint8_t(*)[%d])b)", bytes)
			}
			for predicate := 0; predicate < 32; predicate++ {
				fmt.Fprintf(&source, " case %d: __asm__ volatile(\"stc; %s $%d,%%3,%%2,%%0; setc %%1\":\"=x\"(result),\"=qm\"(carry):\"x\"(left),%s:\"cc\");break;\n",
					predicate, strings.ToLower(fixture.opcode), predicate, operand)
			}
			source.WriteString(` }
 __asm__ volatile("stmxcsr %0":"=m"(*after));
 __asm__ volatile("ldmxcsr %0"::"m"(saved));
 memset(out,0,64);memcpy(out,&result,sizeof(result));out[64]=carry;
}
`)
		}
	}
	source.WriteString("typedef void(*reference_fn)(uint8_t*,const uint8_t*,const uint8_t*,unsigned,unsigned,unsigned*);\nstatic reference_fn references[]={")
	for index := 0; index < 12; index++ {
		fmt.Fprintf(&source, "reference%d,", index)
	}
	source.WriteString("};\n")
	return source.String()
}

func x86FloatCompareVEXWholeMain(cases []x86FloatCompareOracleCase) string {
	var declarations, descriptors strings.Builder
	for index, fixture := range cases {
		fmt.Fprintf(&declarations, "extern void vex_compare%d(void*,const void*,const void*);\n", index)
		fmt.Fprintf(&descriptors, "{vex_compare%d,%d,%d,%d,%d,%d},\n", index, index/64*2+x86FloatAddSubBoolInt(fixture.memory),
			fixture.bits, fixture.width, fixture.predicate, x86FloatAddSubBoolInt(fixture.scalar))
	}
	return x86FloatCompareVEXWholeReferenceC() + declarations.String() + `
typedef void(*translated_fn)(void*,const void*,const void*);
struct comparison{translated_fn call;unsigned reference,bits,width,predicate,scalar;};
static const struct comparison comparisons[]={
` + descriptors.String() + `
};
int main(void){
 unsigned saved;__asm__ volatile("stmxcsr %0":"=m"(saved));
 uint64_t samples=0;
 for(unsigned index=0;index<sizeof(comparisons)/sizeof(comparisons[0]);index++){
  const struct comparison *c=comparisons+index;
  unsigned bytes=c->bits/8;const uint64_t *edges=bytes==4?edges32:edges64;
  for(unsigned mode=0;mode<2;mode++)for(unsigned i=0;i<18;i++)for(unsigned j=0;j<18;j++)for(unsigned control=0;control<6;control++){
   uint8_t aStorage[192],bStorage[192],out[81],expected[65],truth[64];
   uint8_t *a=aStorage+65,*b=bStorage+65;
   memset(aStorage,0xa7,sizeof(aStorage));memset(bStorage,0xb9,sizeof(bStorage));memset(out,0xc3,sizeof(out));
   for(unsigned lane=0;lane<64/bytes;lane++){
    uint64_t av=edges[(i+(mode?lane:0))%18],bv=edges[(j+(mode?lane*5:0))%18];
    memcpy(a+lane*bytes,&av,bytes);memcpy(b+lane*bytes,&bv,bytes);
   }
   uint8_t beforeA[192],beforeB[192];memcpy(beforeA,aStorage,192);memcpy(beforeB,bStorage,192);
   unsigned csr=controls[control],expectedCSR,after;
   references[c->reference](expected,a,b,c->predicate,csr,&expectedCSR);
   memset(truth,0,64);if(c->scalar)memcpy(truth,a,16);
   unsigned compared=c->scalar?bytes:c->width;
   for(unsigned lane=0;lane<compared;lane+=bytes){
    int value=independent_compare(c->bits,read_bits(a+lane,bytes),read_bits(b+lane,bytes),c->predicate,csr);
    memset(truth+lane,value?255:0,bytes);
   }
   if(memcmp(truth,expected,64)||expected[64]!=1){
    fprintf(stderr,"original VEX truth/CF index=%u pred=%u mode=%u i=%u j=%u csr=%x\n",index,c->predicate,mode,i,j,csr);return 10;
   }
   __asm__ volatile("ldmxcsr %0"::"m"(csr));
   c->call(out,a,b);
   __asm__ volatile("stmxcsr %0":"=m"(after));
   __asm__ volatile("ldmxcsr %0"::"m"(saved));
   if(after!=expectedCSR||memcmp(aStorage,beforeA,192)||memcmp(bStorage,beforeB,192)){
    fprintf(stderr,"translated VEX MXCSR/input index=%u pred=%u mode=%u i=%u j=%u csr=%x got=%x want=%x\n",index,c->predicate,mode,i,j,csr,after,expectedCSR);return 11;
   }
   for(unsigned byte=0;byte<81;byte++){
    uint8_t want=byte>=8&&byte<=72?expected[byte-8]:0xc3;
    if(out[byte]!=want){
     fprintf(stderr,"translated VEX alias/canary index=%u pred=%u mode=%u i=%u j=%u byte=%u got=%x want=%x\n",index,c->predicate,mode,i,j,byte,out[byte],want);return 12;
    }
   }
   samples++;
  }
 }
 __asm__ volatile("ldmxcsr %0"::"m"(saved));
 printf("384 VEX forms, %llu full IEEE/MXCSR/CF/64-alias/canary samples\n",(unsigned long long)samples);
 return samples==UINT64_C(1492992)?0:13;
}
`
}

func TestX86FloatingCompareVEXWholeOracleInventory(t *testing.T) {
	cases := x86FloatCompareVEXOracleCases()
	if len(cases) != 384 {
		t.Fatalf("VEX forms=%d want384", len(cases))
	}
	source, _ := x86FloatCompareVEXOracleAssembly(cases)
	if strings.Contains(source, "KMOV") || strings.Contains(source, ".SAE") || strings.Contains(source, ".BCST") {
		t.Fatal("non-VEX compare prerequisites entered native VEX oracle")
	}
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	if strings.Contains(x86FloatCompareVEXWholeMain(cases), "original_effect(") {
		// The shared relation source declares this older diagnostic helper but
		// the whole-vector driver must not call it or substitute sample values.
		main := strings.Split(x86FloatCompareVEXWholeMain(cases), "int main(void){")[1]
		if strings.Contains(main, "original_effect(") || strings.Contains(main, "is_denormal(") {
			t.Fatal("whole native effect reference was replaced by a class/lane policy")
		}
	}
}

func TestX86FloatingCompareVEXWholeEffectsIR(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	cases := x86FloatCompareVEXOracleCases()
	var physicalSource strings.Builder
	var physicalBytes strings.Builder
	for index, fixture := range cases {
		name := fmt.Sprintf("physical_vex%d", index)
		fmt.Fprintf(&physicalSource, "TEXT %s(SB),4,$0-0\n", name)
		for _, b := range x86FloatCompareVEXOriginalBytes(t, fixture.row) {
			fmt.Fprintf(&physicalSource, "BYTE $%d\n", b)
			fmt.Fprintf(&physicalBytes, "0x%02x ", b)
		}
		physicalBytes.WriteString("\n")
		// This is only a physical mode32 format harness. Unknown incoming
		// pointers cannot borrow a native return contract from that byte marker.
		physicalSource.WriteString("UNDEF\n")
	}
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=i386-unknown-linux-gnu", "--mattr=+avx")
	command.Stdin = strings.NewReader(physicalBytes.String())
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go mode32 byte validation: %v\n%s", err, output)
	}
	physical := regexp.MustCompile(`(?m)^\s+vcmp[a-z0-9_]*(ps|pd|ss|sd)\s+`).FindAll(output, -1)
	if len(physical) != 384 || strings.Contains(string(output), "warning:") {
		t.Fatalf("original AMD64 Go bytes lack complete physical mode32 LLVM-MC identity:\n%s", output)
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-macosx"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source, sigs := x86FloatCompareVEXOracleAssembly(cases)
			if target.arch == "386" {
				// The original mode32 byte fixture has neither initialized
				// vectors nor native pointer inputs. Keep its original Go
				// objects and public Context controls, then check only its
				// complete physical syntax through the private emitter.
				ir := x86FloatingCompareUnboundFormatObject(t, physicalSource.String(), target.arch, target.triple)
				if strings.Contains(ir, " = fcmp ") || strings.Count(ir, "asm sideeffect \"vcmp") != len(cases) ||
					strings.Count(ir, "asm sideeffect \"ud2\"") != len(cases) {
					t.Fatal("physical mode32 VEX formats lost original comparison side effects")
				}
				compileLLVMToObject(t, llc, target.triple, "vex-whole-format.ll", "vex-whole-format.o", ir)
				return
			}
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir := func() string {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs})
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				return module.String()
			}()
			if strings.Contains(ir, " = fcmp ") || strings.Count(ir, "asm sideeffect") < 384 {
				t.Fatal("full native VEX predicate/width side effects were replaced by relation-only fcmp")
			}
			compileLLVMToObject(t, llc, target.triple, "vex-whole.ll", "vex-whole.o", ir)
		})
	}
}

func x86FloatCompareVEXOriginalBytes(t *testing.T, row string) []byte {
	t.Helper()
	listing, err := x86ScalarLiteralGoListing(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
	if err != nil {
		t.Fatalf("original Go VEX encoding: %v\n%s", err, listing)
	}
	length := 0
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[len(fields)-1] == "RET" {
			length, err = strconv.Atoi(fields[1])
			if err != nil || length < 1 || length > 15 {
				t.Fatalf("original VEX native width: %v\n%s", err, listing)
			}
		}
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if length == 0 || len(fields) <= length || fields[0] != "0x0000" || len(fields[1]) != 2 {
			continue
		}
		code := make([]byte, length)
		for index := range code {
			value, err := strconv.ParseUint(fields[index+1], 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			code[index] = byte(value)
		}
		return code
	}
	t.Fatalf("original VEX machine bytes unavailable:\n%s", listing)
	return nil
}

func TestX86FloatingCompareVEXWholeOriginalCObject(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source, object := filepath.Join(dir, "original.c"), filepath.Join(dir, "original.o")
	contents := x86FloatCompareVEXWholeMain(x86FloatCompareVEXOracleCases())
	// These two headers belong to older fault fixtures, not this numerical
	// reference. Keep the ordinary C object portable to Windows as well.
	contents = strings.NewReplacer("#include <sys/mman.h>\n", "", "#include <unistd.h>\n", "").Replace(contents)
	if err := os.WriteFile(source, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	arguments := append(append([]string(nil), execution.compiler...), "-O2", "-c", source, "-o", object)
	command := exec.Command(arguments[0], arguments[1:]...)
	x86FloatCompareCaptureCommand(t, command)
}

func x86FloatCompareVEXWholeRuntime(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution.requireAVX(t)
	x86FloatCompareVerifyArguments(t, execution)
	cases := x86FloatCompareVEXOracleCases()
	source, sigs := x86FloatCompareVEXOracleAssembly(cases)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir := func() string {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := TranslateModuleInContext(ctx, file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil {
			t.Fatal(err)
		}
		return module.String()
	}()
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "vex-whole-compare", ir, x86FloatCompareVEXWholeMain(cases), level)
			const expected = "384 VEX forms, 1492992 full IEEE/MXCSR/CF/64-alias/canary samples"
			if strings.TrimSpace(string(output)) != expected {
				t.Fatalf("whole native VEX oracle output: %q", output)
			}
			t.Logf("%s: %s transport=%v", level, expected, execution.prefix)
		})
	}
	t.Log("384 register/memory VEX forms ×3888 full Cartesian/mixed-lane samples per optimization level; no EVEX execution")
}
