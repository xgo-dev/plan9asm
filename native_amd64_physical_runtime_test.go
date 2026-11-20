package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

// The descriptor is a first-party physical C ABI fixture, not a Go function
// signature. Its independent C layout checks every assembly byte offset.
func nativeAMD64PhysicalABIFixture() (string, string) {
	var source strings.Builder
	source.WriteString("#include \"textflag.h\"\nTEXT dispatch<>(SB),NOSPLIT,$224\nMOVQ R12,208(SP)\nMOVQ DI,216(SP)\nMOVQ DI,R11\n")
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&source, "MOVQ %d(R11),X%d\n", 264+8*i, i)
	}
	for i, reg := range []string{"DI", "SI", "DX", "CX", "R8", "R9"} {
		fmt.Fprintf(&source, "MOVQ %d(R11),%s\n", 8+8*i, reg)
	}
	for i := 0; i < 26; i++ {
		fmt.Fprintf(&source, "MOVQ %d(R11),R12\nMOVQ R12,%d(SP)\n", 56+8*i, 8*i)
	}
	source.WriteString("MOVQ 0(R11),R10\nCALL R10\nMOVQ 216(SP),DI\nMOVQ AX,328(DI)\nMOVQ DX,336(DI)\nMOVQ X0,344(DI)\nMOVQ X1,352(DI)\nMOVQ 208(SP),R12\nRET\nGLOBL ·entry(SB),RODATA|NOPTR,$8\nDATA ·entry(SB)/8,$dispatch<>(SB)\n")
	var code strings.Builder
	code.WriteString(`#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
typedef struct { uintptr_t fn; uint64_t a[32]; double f[8]; uint64_t r[4]; } Args;
typedef struct { double lo,hi; } Floats;
typedef struct { uint64_t lo; double hi; } Mixed;
_Static_assert(sizeof(uintptr_t)==8 && offsetof(Args,f)==264 && offsetof(Args,r)==328,"physical layout");
#if defined(__APPLE__)
extern void *entry __asm("_probe.entry");
#else
extern void *entry __asm("probe.entry");
#endif
#define ALIGNED() do { if ((uintptr_t)__builtin_frame_address(0)&15) abort(); } while(0)
static uint64_t bits(double value) { uint64_t result; memcpy(&result,&value,8); return result; }
`)
	for _, count := range []int{6, 7, 32} {
		var args, lo, hi []string
		for i := 0; i < count; i++ {
			args = append(args, fmt.Sprintf("uint64_t a%d", i))
			lo = append(lo, fmt.Sprintf("a%d*%d", i, i+1))
			hi = append(hi, fmt.Sprintf("a%d*%d", i, 33-i))
		}
		fmt.Fprintf(&code, "static __attribute__((noinline)) __uint128_t ints%d(%s){ ALIGNED(); return ((__uint128_t)(%s)<<64)|(%s); }\n", count, strings.Join(args, ","), strings.Join(hi, "+"), strings.Join(lo, "+"))
	}
	for _, count := range []int{8, 9} {
		var args, lo, hi []string
		for i := 0; i < count; i++ {
			args = append(args, fmt.Sprintf("double f%d", i))
			lo = append(lo, fmt.Sprintf("f%d*%d", i, i+1))
			hi = append(hi, fmt.Sprintf("f%d*%d", i, 10-i))
		}
		fmt.Fprintf(&code, "static __attribute__((noinline)) Floats floats%d(%s){ ALIGNED(); return (Floats){%s,%s}; }\n", count, strings.Join(args, ","), strings.Join(lo, "+"), strings.Join(hi, "+"))
	}
	var mixedArgs, mixedInt, mixedFloat []string
	for i := 0; i < 24; i++ {
		mixedArgs = append(mixedArgs, fmt.Sprintf("uint64_t a%d", i))
		mixedInt = append(mixedInt, fmt.Sprintf("a%d*%d", i, i+1))
	}
	for i := 0; i < 8; i++ {
		mixedArgs = append(mixedArgs, fmt.Sprintf("double f%d", i))
		mixedFloat = append(mixedFloat, fmt.Sprintf("f%d*%d", i, i+1))
	}
	fmt.Fprintf(&code, "static __attribute__((noinline)) Mixed mixed32(%s){ ALIGNED(); return (Mixed){%s,%s}; }\n", strings.Join(mixedArgs, ","), strings.Join(mixedInt, "+"), strings.Join(mixedFloat, "+"))
	code.WriteString(`static void invoke(Args *args) {
 register uint64_t kept __asm("r12")=UINT64_C(0x912837465abcdeff);
 __asm__ volatile("" : "+r"(kept));
 ((void (*)(Args *))entry)(args);
 __asm__ volatile("" : "+r"(kept));
 if(kept!=UINT64_C(0x912837465abcdeff)) abort();
}
int main(void) {
 for(unsigned seed=0;seed<32;seed++) for(unsigned kind=0;kind<6;kind++) {
  struct { uint64_t before; Args args; uint64_t after; } box;
  memset(&box,0xa5,sizeof(box));
  box.before=UINT64_C(0xfedcba9876543210); box.after=UINT64_C(0x123456789abcdef0);
  for(unsigned i=0;i<32;i++) box.args.a[i]=seed*19+i*7+1;
  for(unsigned i=0;i<8;i++) box.args.f[i]=seed+i*.25+.5;
  uint64_t lo=0,hi=0; double flo=0,fhi=0;
  if(kind<3) {
   unsigned count=kind==0?6:kind==1?7:32;
   for(unsigned i=0;i<count;i++){ lo+=box.args.a[i]*(i+1); hi+=box.args.a[i]*(33-i); }
   box.args.fn=kind==0?(uintptr_t)ints6:kind==1?(uintptr_t)ints7:(uintptr_t)ints32;
  } else if(kind<5) {
   unsigned count=kind==3?8:9;
   double ninth=seed+2.5;
   if(count==9) box.args.a[6]=bits(ninth);
   for(unsigned i=0;i<count;i++){ double value=i==8?ninth:box.args.f[i]; flo+=value*(i+1);fhi+=value*(10-i); }
   box.args.fn=kind==3?(uintptr_t)floats8:(uintptr_t)floats9;
  } else {
   for(unsigned i=0;i<24;i++) lo+=box.args.a[i]*(i+1);
   for(unsigned i=0;i<8;i++) fhi+=box.args.f[i]*(i+1);
   box.args.fn=(uintptr_t)mixed32;
  }
  invoke(&box.args);
  if(box.before!=UINT64_C(0xfedcba9876543210)||box.after!=UINT64_C(0x123456789abcdef0)) return 1;
  if(kind<3 && (box.args.r[0]!=lo||box.args.r[1]!=hi)) return 2;
  if(kind>=3&&kind<5 && (box.args.r[2]!=bits(flo)||box.args.r[3]!=bits(fhi))) return 3;
  if(kind==5 && (box.args.r[0]!=lo||box.args.r[2]!=bits(fhi))) return 4;
 }
 return 0;
}
`)
	return source.String(), code.String()
}

func TestCrossLinuxRuntimeMatrixX86NativePhysicalABIArguments(t *testing.T) {
	if !SupportsNativeTarget(runtime.GOOS, "amd64") {
		t.Skip("SysV native execution requires Linux or Darwin; mandatory Linux/amd64 counterpart: TestCrossLinuxRuntimeMatrixX86NativePhysicalABIArguments")
	}
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	source, mainC := nativeAMD64PhysicalABIFixture()
	nativeAMD64OriginalObject(t, runtime.GOOS, source)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	mod, err := TranslateNativeModule(ctx, []byte(source), NativeOptions{GOOS: runtime.GOOS, GOARCH: "amd64", PackagePath: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Dispose()
	for _, optimize := range []bool{false, true} {
		ir := mod.String()
		if optimize {
			ir = x86DwordProductIROptimize(t, ir)
		}
		for _, backend := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR-O2-%t/backend-O%d", optimize, backend), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang, "-target", triple}, "native-physical-args", triple, ir, mainC, prefix, backend)
			})
		}
	}
}
