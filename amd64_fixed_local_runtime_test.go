//go:build unix

package plan9asm

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixedLocalCompleteFixture(t *testing.T, target string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options, string) {
	t.Helper()
	_, request := goAMD64FrameSourceFixture(t)
	request.Target = target
	var declarations, assembly strings.Builder
	declarations.WriteString("package framefixture\n")
	for index, operation := range fixedLocalNativeOperations {
		fmt.Fprintf(&declarations, "func Value%d(a, b, c, d uint64) uint64\n", index)
		source, _, _ := x86PrivateAlignedFrameAuditFixture(t, operation)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	for name, content := range map[string]string{"value.go": declarations.String(), "value_amd64.s": assembly.String()} {
		if err := os.WriteFile(filepath.Join(request.Directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "value.go", declarations.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check("example.invalid/framefixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range typed.Scope().Names() {
		sig, err := DeriveGoFuncABI0Signature(typed.Path()+"."+name, typed.Scope().Lookup(name).(*types.Func), "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		sigs[sig.Name] = sig
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", typed.Path()+".", 1) }
	triple := "x86_64-unknown-linux-gnu"
	if strings.HasPrefix(target, "darwin/") {
		triple = "x86_64-apple-darwin"
	}
	if strings.HasPrefix(target, "windows/") {
		triple = "x86_64-pc-windows-msvc"
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}, request, file,
		Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}, declarations.String()
}

// Integer-only independent expected values; the comparison inputs remain raw
// IEEE bits, including signed zero, infinities, NaNs and subnormals.
const fixedLocalGoMath = `
func equalBits(a,b uint64,bits uint, daz bool) bool {
 exp,frac,sign:=uint64(0x7ff0000000000000),uint64(0xfffffffffffff),uint64(1)<<63
 if bits==32 { exp,frac,sign=0x7f800000,0x7fffff,1<<31; a=uint64(uint32(a)); b=uint64(uint32(b)) }
 if a&exp==exp && a&frac!=0 || b&exp==exp && b&frac!=0 { return false }
 if daz && a&exp==0 { a &= sign }; if daz && b&exp==0 { b &= sign }
 return a==b || a&^sign==0 && b&^sign==0
}
func expected(op int,a,c uint64) uint64 {
 if op<4 {
  width:=uint(8)<<uint(op); var result uint64
  mask:=^uint64(0); if width<64 { mask=(uint64(1)<<width)-1 }
  for shift:=uint(0);shift<64;shift+=width { result|=((a>>shift)+(c>>shift))&mask<<shift }
  return result
 }
 if op==4 {
  var result uint64
  for shift:=uint(0);shift<64;shift+=32 {
   x,y:=int64(int16(a>>shift)),int64(int16(a>>(shift+16)))
   u,v:=int64(int16(c>>shift)),int64(int16(c>>(shift+16)))
   result|=uint64(uint32(x*u+y*v))<<shift
  }; return result
 }
 if op==5 {
  var result uint64
  for shift:=uint(0);shift<64;shift+=32 { if equalBits(a>>shift,c>>shift,32,false) { result|=uint64(0xffffffff)<<shift } }
  return result
 }
 if equalBits(a,c,64,false) { return ^uint64(0) }; return 0
}
`

func fixedLocalOriginalGoValues(t *testing.T, request GoAMD64FrameCaptureRequest, declarations string) {
	t.Helper()
	dir := t.TempDir()
	assembly, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	var calls strings.Builder
	for index := range fixedLocalNativeOperations {
		fmt.Fprintf(&calls, "if got:=Value%d(input.data[0],input.data[1],input.data[2],input.data[3]); got!=expected(%d,input.data[0],input.data[2]) || snapshot(&input)!=before { t.Fatalf(\"original opcode %d seed=%%d got=%%x\",seed,got) }\n", index, index, index)
	}
	testSource := `package framefixture
import "testing"
type guarded struct { before [4]uint64; data [4]uint64; after [4]uint64 }
//go:noinline
func snapshot(p *guarded) guarded { return *p }
` + fixedLocalGoMath + `
func TestOriginalLocalNativeValues(t *testing.T) {
 values:=[]uint64{0,1,^uint64(0),0x8000800080008000,0x7fff7fff7fff7fff,0x3f8000003f800000,0x7fc012347f801234,0x3ff0000000000000,0x8000000000000000,0x123456789abcdef0}
 for seed:=0;seed<128;seed++ {
  input:=guarded{before:[4]uint64{11,17,29,53},data:[4]uint64{values[seed%len(values)],values[(seed+1)%len(values)],values[(seed*3)%len(values)],values[(seed*7+1)%len(values)]},after:[4]uint64{0xaabbccdd,0x12345678,0x87654321,^uint64(0)}}
  before:=snapshot(&input)
` + calls.String() + `
 }
}
`
	for name, data := range map[string][]byte{
		"go.mod": []byte("module example.invalid/framefixture\ngo 1.20\n"), "value.go": []byte(declarations),
		"value_amd64.s": assembly, "value_test.go": []byte(testSource),
	} {
		if strings.HasSuffix(name, ".go") {
			data, err = format.Source(data)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("safe first-party original Go local-frame math/canaries: %v\n%s", err, output)
	}
	t.Log("original Go: 896 actual scalar-ABI calls, integer/IEEE-bit independent expectations and noinline full guarded-memory snapshots; not an external-library runtime witness")
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalNativeBackingMathAndBuffers(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 fixed-local counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang missing")
	}
	pkg, request, file, options, declarations := fixedLocalCompleteFixture(t, runtime.GOOS+"/amd64")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, bound)
	if err != nil {
		t.Fatal(err)
	}
	fixedLocalOriginalGoValues(t, request, declarations)
	var declarationsC strings.Builder
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	for index := range fixedLocalNativeOperations {
		fmt.Fprintf(&declarationsC, "extern uint64_t value%d(uint64_t,uint64_t,uint64_t,uint64_t) __asm__(\"%sexample.invalid/framefixture.Value%d\");\n", index, prefix, index)
	}
	main := fixedLocalCOracle(declarationsC.String())
	var runPrefix []string
	if crossRosetta {
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fixed-local-native", options.TargetTriple, ir, main, runPrefix)
	t.Log("LLVM/C: exact SSE opcode results+complete MXCSR compared for 4 RC ×4 DAZ/FTZ ×3 sticky seeds ×128 inputs ×7 operations; volatile whole input/canary memory reread")
	if crossRosetta {
		t.Log("Darwin/Rosetta diagnostic, not native Intel fault/trap proof")
	}
}

func fixedLocalCOracle(declarations string) string {
	var cases, opcodes strings.Builder
	for index, operation := range fixedLocalNativeOperations {
		mnemonic := strings.ToLower(strings.Fields(operation)[0])
		if mnemonic == "paddl" {
			mnemonic = "paddd"
		}
		if mnemonic == "pmaddwl" {
			mnemonic = "pmaddwd"
		}
		immediate := ""
		if strings.HasPrefix(mnemonic, "cmp") {
			immediate = "$0, "
		}
		fmt.Fprintf(&opcodes, "case %d: __asm__ volatile(\"%s %s%%1,%%0\" : \"+x\"(value) : \"m\"(input) : \"memory\"); break;\n", index, mnemonic, immediate)
		fmt.Fprintf(&cases, "case %d: got=value%d(data[0],data[1],data[2],data[3]); break;\n", index, index)
	}
	return `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <immintrin.h>
` + declarations + `
static __attribute__((noinline)) uint64_t readword(const volatile uint64_t *p) { return *p; }
static __attribute__((noinline)) uint64_t reference(int op,const uint64_t *data) {
 _Alignas(16) uint64_t input[2]={data[0],data[1]};
 __m128i value=_mm_set_epi64x((long long)data[3],(long long)data[2]);
 switch(op) {
` + opcodes.String() + `
 }
 return (uint64_t)_mm_cvtsi128_si64(value);
}
int main(void) {
 const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000800080008000),UINT64_C(0x7fff7fff7fff7fff),UINT64_C(0x3f8000003f800000),UINT64_C(0x7fc012347f801234),UINT64_C(0x3ff0000000000000),UINT64_C(0x8000000000000000),UINT64_C(0x123456789abcdef0)};
 unsigned saved=_mm_getcsr();
 /* Controlled first-party storage realizes all four word-aligned source
    residues. This is an independent exact-SSE witness of the refused alias
    fragment, not a claim that these are the actual Go runtime entry SPs. */
 const uint64_t aliasWant[4][2]={{6,10},{7,8},{7,10},{7,10}};
 for(int residue=0;residue<4;residue++) {
  _Alignas(32) unsigned char memory[256]={0};
  unsigned char *sp=memory+32+residue*8;
  unsigned char *aligned=(unsigned char*)(((uintptr_t)sp&~(uintptr_t)31)+32);
  uint64_t input[2]={2,3}, other[2]={5,7}, one=1, observed[2];
  memcpy(aligned+16,input,16); memcpy(aligned+48,other,16);
  memcpy(sp+48,&one,8);
  __m128i vector; memcpy(&vector,aligned+48,16);
  __asm__ volatile("paddq %1,%0" : "+x"(vector) : "m"(*(const unsigned char (*)[16])(aligned+16)) : "memory");
  memcpy(observed,&vector,16);
  if(observed[0]!=aliasWant[residue][0] || observed[1]!=aliasWant[residue][1]) return 3;
 }
 for(int seed=0;seed<128;seed++) {
  volatile uint64_t guarded[12]={11,17,29,53,values[seed%10],values[(seed+1)%10],values[(seed*3)%10],values[(seed*7+1)%10],0xaabbccdd,0x12345678,0x87654321,UINT64_MAX};
  uint64_t data[4],before[12];
  for(int i=0;i<12;i++) before[i]=readword(&guarded[i]);
  for(int i=0;i<4;i++) data[i]=readword(&guarded[i+4]);
  for(int op=0;op<7;op++) for(int rc=0;rc<4;rc++) for(int ctl=0;ctl<4;ctl++) for(int sticky=0;sticky<3;sticky++) {
   unsigned start=0x1f80u|(unsigned)rc<<13|(ctl&1?0x40u:0)|(ctl&2?0x8000u:0)|(sticky==1?1u:sticky==2?0x3fu:0);
   _mm_setcsr(start); uint64_t want=reference(op,data); unsigned wantCSR=_mm_getcsr();
   _mm_setcsr(start); uint64_t got=0;
   switch(op) {
` + cases.String() + `
   }
   unsigned gotCSR=_mm_getcsr();
   if(got!=want || gotCSR!=wantCSR) { fprintf(stderr,"op=%d seed=%d RC=%d ctl=%d sticky=%d got=%llx/%x want=%llx/%x\n",op,seed,rc,ctl,sticky,(unsigned long long)got,gotCSR,(unsigned long long)want,wantCSR); return 1; }
   for(int i=0;i<12;i++) if(readword(&guarded[i])!=before[i]) return 2;
  }
 }
 _mm_setcsr(saved); return 0;
}
`
}
