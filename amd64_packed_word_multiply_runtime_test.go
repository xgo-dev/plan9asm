package plan9asm

import (
	"bytes"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86WordMultiplyReservedZeroMaskGoObservation(t *testing.T, source, name string) {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "reserved.s"), filepath.Join(dir, "reserved.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "oracle", "-o", object, asm)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), err == nil, "amd64"); failure != nil {
		t.Fatalf("actual zero-mask source observation: %v\n%s", failure, output)
	}
	if err != nil {
		if !bytes.Contains(output, []byte("mask register must be specified for .Z instructions")) {
			t.Fatalf("unknown original-Go rejection: %s", output)
		}
		return
	}
	// Go1.20 can emit the reserved EVEX.z=1/aaa=0 pattern. This is an
	// accepted object observation, never authority to execute or translate it.
	opcode := map[string]byte{"VPMULLW": 0xd5, "VPMULHW": 0xe5, "VPMULHUW": 0xe4, "VPMULHRSW": 0x0b}[name]
	mapByte := byte(0xf1)
	if name == "VPMULHRSW" {
		mapByte = 0xf2
	}
	code := []byte{0x62, mapByte, 0x75, 0x88, opcode, 0x10}
	listing := make([]string, 0, len(code)+1)
	for _, value := range append(append([]byte(nil), code...), 0xc3) {
		listing = append(listing, fmt.Sprintf("%02x", value))
	}
	if !bytes.Contains(output, []byte(strings.Join(listing, " "))) {
		t.Fatalf("actual accepted reserved bytes changed: %s", output)
	}
	if _, _, recognized, err := decodedX86PackedMultiplyInstruction(code, 64); !recognized || err == nil {
		t.Fatal("reserved physical bytes acquired valid semantics")
	}
	t.Log("actual Go accepts reserved zero-mask bytes; named/raw validation still rejects, and no #UD code is executed")
}

// Independent integer arithmetic: neither reference reads a production mode,
// emitter, descriptor or LLVM intrinsic. Rounded signed high is deliberately
// wrapping, including (-32768)*(-32768) -> 0x8000, not saturation.
const x86WordMultiplyGoReference = `func product(a,b uint16,mode int) uint16 {
 if mode==0 {return uint16(uint32(a)*uint32(b))}
 if mode==2 {return uint16((uint32(a)*uint32(b))>>16)}
 x,y:=int64(int16(a)),int64(int16(b))
 value,shift:=x*y,uint(16)
 if mode==3 {value+=16384;shift=15}
 return uint16(value>>shift)
}
`

const x86WordMultiplyOriginalGoTestHeader = `package oracle
import ("testing";"unsafe";"runtime")
` + x86WordMultiplyGoReference + `
func aligned(value *[160]byte) (*[64]byte,int) {
 offset:=16+int((-uintptr(unsafe.Pointer(&value[16])))&15)
 return (*[64]byte)(unsafe.Pointer(&value[offset])),offset
}
func TestOriginal(t *testing.T) {
 runtime.LockOSThread();defer runtime.UnlockOSThread()
 edges:=[...]uint16{0,1,2,0x3fff,0x4000,0x4001,0x7fff,0x8000,0x8001,0xbfff,0xc000,0xfffe,0xffff}
 saved:=ReadCSR();defer SetCSR(saved)
 for sample:=0;sample<257;sample++ {for _,seed:=range []uint64{0,0x8d5} {
 var a,b,out [160]byte
 ap,_:=aligned(&a);bp,_:=aligned(&b);op,offset:=aligned(&out)
 for i:=range a {a[i]=0xa7;b[i]=0xb9}
 for i:=0;i<64;i+=2 {
  x,y:=edges[(sample+i/2)%13],edges[(sample/13+i/2*3)%13]
  if sample>169 {x=uint16(sample*71+i*7919);y=uint16(sample*13+i*37)}
  ap[i],ap[i+1]=byte(x),byte(x>>8);bp[i],bp[i+1]=byte(y),byte(y>>8)
 }
 originalA,originalB:=a,b
 profile:=uint32(0x1f80|((sample%4)<<13)|(sample%64))
 SetCSR(profile)
`

const x86WordMultiplyCReference = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
static uint16_t word(const uint8_t *p) {return (uint16_t)p[0]|(uint16_t)p[1]<<8;}
static uint16_t product(uint16_t a,uint16_t b,int mode) {
 if(mode==0) return (uint16_t)((uint32_t)a*(uint32_t)b);
 if(mode==2) return (uint16_t)(((uint32_t)a*(uint32_t)b)>>16);
 int64_t x=a<32768?a:(int64_t)a-65536,y=b<32768?b:(int64_t)b-65536;
 int64_t value=x*y,divisor=65536;
 if(mode==3) {value+=16384;divisor=32768;}
 // Mathematical floor division, independent of C's signed-shift policy.
 return (uint16_t)(value<0?-((-value+divisor-1)/divisor):value/divisor);
}
static const uint16_t edge[]={0,1,2,0x3fff,0x4000,0x4001,0x7fff,0x8000,0x8001,0xbfff,0xc000,0xfffe,0xffff};
static const uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaa55555555),UINT64_MAX};
struct Aligned {_Alignas(64) uint8_t before[64],value[64],after[64];};
typedef void (*Program)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t*,uint32_t*,uint64_t,uint64_t);
static int check(Program program,const char *name,int width,int legacy,int alias,int mode,int masking) {
 for(int sample=0;sample<257;sample++) for(int status=0;status<2;status++) for(int m=0;m<4;m++) {
  struct Aligned a,b,out;
  memset(&a,0xa7,sizeof(a));memset(&b,0xb9,sizeof(b));memset(&out,0xc3,sizeof(out));
  for(int i=0;i<64;i+=2) {
   uint16_t x=edge[(sample+i/2)%13],y=edge[(sample/13+i/2*3)%13];
   if(sample>169) {x=(uint16_t)(sample*71+i*7919);y=(uint16_t)(sample*13+i*37);}
   a.value[i]=(uint8_t)x;a.value[i+1]=(uint8_t)(x>>8);
   b.value[i]=(uint8_t)y;b.value[i+1]=(uint8_t)(y>>8);
  }
  struct Aligned originalA=a,originalB=b;
  struct {uint64_t before,value,after;} flags={UINT64_C(0x1122334455667788),0,UINT64_C(0x8877665544332211)};
  struct {uint32_t before,value,after;} csr={0x11223344,0,0x44332211};
  uint32_t saved=_mm_getcsr(),profile=(uint32_t)(0x1f80|((sample%4)<<13)|(sample%64));
  _mm_setcsr(profile);
  uint64_t seed=status?UINT64_C(0x8d5):0;
  program(out.value,a.value,b.value,&flags.value,&csr.value,seed,masks[m]);
  _mm_setcsr(saved);
  if((flags.value&UINT64_C(0x8d5))!=seed||flags.before!=UINT64_C(0x1122334455667788)||flags.after!=UINT64_C(0x8877665544332211)||
     csr.value!=profile||csr.before!=0x11223344||csr.after!=0x44332211||memcmp(&a,&originalA,sizeof(a))||memcmp(&b,&originalB,sizeof(b))) {
   fprintf(stderr,"%s state sample%d flags%llx CSR%x/%x\n",name,sample,(unsigned long long)flags.value,csr.value,profile);return 1;
  }
  for(int i=0;i<64;i++) {
   uint16_t value=product(word((alias?b.value:a.value)+(i&~1)),word(b.value+(i&~1)),mode);
   int active=!masking||((masks[m]>>(i/2))&1);
   uint8_t want=i<width?(active?(uint8_t)(value>>((i&1)*8)):(masking==2?0:b.value[i])):(legacy?b.value[i]:0);
   if(out.value[i]!=want||out.before[i]!=0xc3||out.after[i]!=0xc3) {
    fprintf(stderr,"%s sample%d mask%llx byte%d got%x want%x\n",name,sample,(unsigned long long)masks[m],i,out.value[i],want);return 2;
   }
  }
 }
 return 0;
}
`

func x86WordMultiplyReferenceMode(name string) int {
	switch strings.TrimPrefix(name, "V") {
	case "PMULLW":
		return 0
	case "PMULHW":
		return 1
	case "PMULHUW":
		return 2
	case "PMULHRSW":
		return 3
	default:
		panic("unknown independent word multiply reference name")
	}
}

func x86WordMultiplySignature(t *testing.T, pkg GoPackage, name string) FuncSig {
	t.Helper()
	sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestCrossLinuxRuntimeMatrixX86PackedWordMultiplyOriginalGo(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\nfunc ReadCSR() uint32\nfunc SetCSR(value uint32)\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\nTEXT ·SetCSR(SB),4,$0-4\nLDMXCSR value+0(FP)\nRET\n")
	tests.WriteString(x86WordMultiplyOriginalGoTestHeader)
	count := 0
	for _, name := range x86WordMultiplyNames[:4] {
		for _, bank := range []string{"X", "M"} {
			if bank == "M" && name == "PMULHRSW" {
				continue
			}
			kinds := []string{"Register", "Alias", "Memory"}
			if bank == "M" {
				kinds = append(kinds, "AXBank", "R14Bank")
			}
			for _, kind := range kinds {
				fn := fmt.Sprintf("F%d", count)
				count++
				move, width, source := "MOVOU", 16, bank+"0"
				if bank == "M" {
					move, width = "MOVQ", 8
				}
				alias := 0
				if kind == "Alias" {
					source, alias = bank+"1", 1
				}
				if kind == "Memory" {
					source = "(DI)"
				}
				if kind == "AXBank" {
					source = "AX"
				}
				if kind == "R14Bank" {
					source = "R14"
				}
				fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed uint64,profile uint32)\n", fn)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-56\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\nMOVQ flags+24(FP),CX\nMOVQ csr+32(FP),BX\n%s (DI),%s0\n%s (SI),%s1\n", fn, move, bank, move, bank)
				if kind == "R14Bank" {
					assembly.WriteString("MOVQ (DI),M6\n")
				}
				fmt.Fprintf(&assembly, "LDMXCSR profile+48(FP)\nPUSHQ seed+40(FP)\nPOPFQ\n%s %s,%s1\n%s %s1,(DX)\n", name, source, bank, move, bank)
				if bank == "M" {
					assembly.WriteString("EMMS\n")
				}
				assembly.WriteString("PUSHFQ\nPOPQ AX\nMOVQ AX,(CX)\nSTMXCSR (BX)\nRET\n")
				fmt.Fprintf(&tests, `{
 for i:=range out {out[i]=0xc3}
 flags:=struct{before,value,after uint64}{0x1122334455667788,0,0x8877665544332211}
 csr:=struct{before,value,after uint32}{0x11223344,0,0x44332211}
 %s(op,ap,bp,&flags.value,&csr.value,seed,profile)
 if flags.value&0x8d5!=seed||flags.before!=0x1122334455667788||flags.after!=0x8877665544332211||csr.value!=profile||csr.before!=0x11223344||csr.after!=0x44332211||ReadCSR()!=profile||a!=originalA||b!=originalB {t.Fatalf("%s flags/CSR/input/canary sample%%d flags%%x csr%%x/%%x",sample,flags.value,csr.value,profile)}
 for i,value:=range out {
  want:=byte(0xc3)
  if i>=offset&&i<offset+%d {
   index:=i-offset;ai:=index&^1
   x,y:=uint16(ap[ai])|uint16(ap[ai+1])<<8,uint16(bp[ai])|uint16(bp[ai+1])<<8
   if %d!=0 {x=y}
   want=byte(product(x,y,%d)>>uint((index&1)*8))
  }
  if value!=want {t.Fatalf("%s full-byte/canary sample%%d byte%%d got%%x want%%x",sample,i,value,want)}
 }
}
`, fn, fn, width, alias, x86WordMultiplyReferenceMode(name), fn)
			}
		}
	}
	tests.WriteString("}}\n}\n")
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), tests.String())
	t.Logf("%d actual original SSE/MMX kernels ×257 initialized samples ×2 all-six-flag seeds, full MXCSR, bytes/input/canaries; MMX GP spellings observe the physical bank only, not a new LLVM permission. Rosetta is not native AMD64 evidence.", count)
}

func x86WordMultiplyRunOriginalGo(t *testing.T, execution x86FloatCompareExecution, declarations, assembly, tests string) {
	t.Helper()
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations, "value_amd64.s": assembly, "value_test.go": tests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original.test")
	command := exec.Command("go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	output := execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatal("original Go had no successful terminal", string(output))
	}
}

func TestCrossLinuxRuntimeMatrixX86PackedWordMultiplySoftwareAllWidths(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, reference, checks strings.Builder
	declarations.WriteString("package oracle\n")
	reference.WriteString(x86WordMultiplyCReference)
	count := 0
	for _, name := range x86WordMultiplyNames {
		widths := []int{16}
		if strings.HasPrefix(name, "V") {
			widths = append(widths, 32, 64)
		}
		for _, width := range widths {
			for _, memory := range []bool{false, true} {
				for _, alias := range []bool{false, true} {
					for _, masking := range []int{0, 1, 2} {
						if !strings.HasPrefix(name, "V") && masking != 0 {
							continue
						}
						fn := fmt.Sprintf("W%d", count)
						count++
						bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
						source := bank + "0"
						if alias {
							source = bank + "1"
						}
						if memory {
							source = "(DI)"
						}
						inputAlias := alias && !memory
						op, args := name, source+","+bank+"1"
						if strings.HasPrefix(name, "V") {
							if masking != 0 {
								args += ",K1"
							}
							if masking == 2 {
								op += ".Z"
							}
							args += "," + bank + "1"
						}
						fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed,mask uint64)\n", fn)
						fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-56\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\nMOVQ flags+24(FP),CX\nMOVQ csr+32(FP),BX\nVMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\n", fn)
						if masking != 0 {
							assembly.WriteString("MOVQ mask+48(FP),AX\nKMOVQ AX,K1\n")
						}
						assembly.WriteString("PUSHQ seed+40(FP)\nPOPFQ\n")
						fmt.Fprintf(&assembly, "%s %s\nVMOVUPS Z1,(DX)\nPUSHFQ\nPOPQ AX\nMOVQ AX,(CX)\nSTMXCSR (BX)\nRET\n", op, args)
						fmt.Fprintf(&reference, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t*,uint32_t*,uint64_t,uint64_t);\n", fn)
						legacy, a := 0, 0
						if !strings.HasPrefix(name, "V") {
							legacy = 1
						}
						if inputAlias {
							a = 1
						}
						fmt.Fprintf(&checks, "if(check(%s,%q,%d,%d,%d,%d,%d)) return 1;\n", fn, name+" "+args, width, legacy, a, x86WordMultiplyReferenceMode(name), masking)
					}
				}
			}
		}
	}
	reference.WriteString("int main(void) {\n" + checks.String() + "return 0;}\n")
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	pkg := mustGoPackage(t, "oracle", declarations.String())
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{}
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		sigs[name] = x86WordMultiplySignature(t, pkg, name)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs, ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "word-multiply-all-widths", ir, reference.String(), level)
		})
	}
	t.Logf("%d initialized LLVM software kernels ×257 samples ×2 seeds ×4 masks; full64-byte aliases, six flags, MXCSR/input/canaries. Original-Go accepted source/object is separate; this does NOT execute original AVX/AVX512 instructions or prove native EVEX capability.", count)
}

func TestCrossLinuxRuntimeMatrixX86PackedWordMultiplySoftwareMaskedMemory(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, name := range x86WordMultiplyNames[4:] {
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, zero := range []bool{false, true} {
				fn := fmt.Sprintf("M%d", count)
				count++
				op, zeroInt := name, 0
				if zero {
					op, zeroInt = op+".Z", 1
				}
				fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed,mask uint64)\n", fn)
				fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-56
MOVQ out+0(FP),DX
MOVQ a+8(FP),DI
MOVQ b+16(FP),SI
MOVQ flags+24(FP),CX
MOVQ csr+32(FP),BX
MOVQ mask+48(FP),AX
KMOVQ AX,K1
VMOVUPS (SI),Z1
PUSHQ seed+40(FP)
POPFQ
%s (DI),%s1,K1,%s1
VMOVUPS Z1,(DX)
PUSHFQ
POPQ AX
MOVQ AX,(CX)
STMXCSR (BX)
RET
`, fn, op, bank, bank)
				fmt.Fprintf(&checks, "if(checkMasked(%s,%q,%d,%d,%d,p)) return 1;\n", fn, op, width, zeroInt, x86WordMultiplyReferenceMode(name))
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	pkg := mustGoPackage(t, "oracle", declarations.String())
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{}
	var external strings.Builder
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		sigs[name] = x86WordMultiplySignature(t, pkg, name)
		fmt.Fprintf(&external, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t*,uint32_t*,uint64_t,uint64_t);\n", name)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	const maskedReference = `
static int checkMasked(Program program,const char *name,int width,int zero,int mode,const uint8_t *pageTail) {
 const uint64_t mask[]={0,1,UINT64_C(1)<<32};
 for(int state=0;state<2;state++) for(int m=0;m<3;m++) {
  struct Aligned b,out;
  memset(&b,0xb9,sizeof(b));memset(&out,0xc3,sizeof(out));
  struct Aligned before=b;
  struct {uint64_t before,value,after;} flags={0x11223344,0,0x44332211};
  struct {uint32_t before,value,after;} csr={0x55667788,0,0x88776655};
  uint64_t seed=state?UINT64_C(0x8d5):0;
  uint32_t saved=_mm_getcsr(),profile=0x1fbf;
  _mm_setcsr(profile);
  program(out.value,m==1?pageTail:NULL,b.value,&flags.value,&csr.value,seed,mask[m]);
  _mm_setcsr(saved);
  if((flags.value&UINT64_C(0x8d5))!=seed||flags.before!=0x11223344||flags.after!=0x44332211||
     csr.value!=profile||csr.before!=0x55667788||csr.after!=0x88776655||memcmp(&b,&before,sizeof(b))) return 2;
  for(int i=0;i<64;i++) {
   uint8_t want=0;
   if(i<width) {
    if(m==1&&i<2) want=(uint8_t)(product(0x8000,word(b.value),mode)>>(i*8));
    else if(!zero) want=b.value[i];
   }
   if(out.value[i]!=want||out.before[i]!=0xc3||out.after[i]!=0xc3) {
    fprintf(stderr,"%s masked read byte%d mask%llx got%x want%x\n",name,i,(unsigned long long)mask[m],out.value[i],want);return 3;
   }
  }
 }
 return 0;
}
`
	main := x86WordMultiplyCReference + external.String() + x86TestGuardPagesC + maskedReference + `
int main(void) {
 if (setup_guard() || page < 64) return 5;
 uint8_t *p = guard + page - 2;
 p[0] = 0;
 p[1] = 0x80;
` + checks.String() + `
 if (free_guard()) return 6;
 return 0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "word-multiply-masked-memory", ir, main, level)
		})
	}
	t.Logf("%d software EVEX kernels: inactive NULL, guard-page first word, irrelevant high mask bits, two flag seeds/full bytes/MXCSR/canaries. These semantics do not grant source/caller memory permission or native EVEX execution.", count)
}
