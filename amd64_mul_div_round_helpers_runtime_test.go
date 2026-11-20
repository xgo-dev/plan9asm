package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86MulDivRoundHelperFixtureIR() string {
	var ir strings.Builder
	ir.WriteString("declare i128 @llvm.ctlz.i128(i128, i1)\n")
	for _, bits := range []int{32, 64} {
		emitX86FloatMulDivRoundingHelper(&ir, bits)
		fmt.Fprintf(&ir, "define i%d @mul_div%d(i%d %%a, i%d %%b, i32 %%divide, i32 %%mode, i32 %%mxcsr) {\n", bits, bits, bits, bits)
		ir.WriteString("  %is_divide = icmp ne i32 %divide, 0\n")
		fmt.Fprintf(&ir, "  %%value = call i%d @__plan9asm_mul_div_round_f%d(i%d %%a, i%d %%b, i1 %%is_divide, i32 %%mode, i32 %%mxcsr)\n", bits, bits, bits, bits)
		fmt.Fprintf(&ir, "  ret i%d %%value\n}\n", bits)
	}
	return ir.String()
}

func x86MulDivRoundOptimize(t *testing.T, ir string) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	return module.String()
}

func TestCrossLinuxRuntimeMatrixX86FloatMulDivIntegerRoundingExtremes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	ir := x86MulDivRoundHelperFixtureIR()
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2-%t", optimized), func(t *testing.T) {
			source := ir
			if optimized {
				source = x86MulDivRoundOptimize(t, source)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "integer-mul-div-round", triple, source, x86MulDivRoundSSEOracle, prefix)
		})
	}
}

func TestX86FloatMulDivIntegerRoundingOriginalSSEObjects(t *testing.T) {
	for _, row := range []struct {
		opcode string
		prefix byte
		code   byte
	}{
		{"MULSS", 0xf3, 0x59}, {"MULSD", 0xf2, 0x59},
		{"DIVSS", 0xf3, 0x5e}, {"DIVSD", 0xf2, 0x5e},
	} {
		listing := x86InsertExtractGoListing(t, "amd64", "TEXT f(SB),4,$0-0\n"+row.opcode+" X1,X0\nRET\n")
		var actual []byte
		for _, line := range strings.Split(string(listing), "\n") {
			actual = append(actual, x86InsertExtractListedBytes(line)...)
		}
		want := []byte{row.prefix, 0x0f, row.code, 0xc1, 0xc3}
		if !bytes.Equal(actual, want) {
			t.Fatalf("actual Go %s object %x, want independent native SSE oracle %x", row.opcode, actual, want)
		}
	}
}

func TestX86FloatMulDivIntegerRoundingOnlyIntegerArithmeticAndBoundedDivision(t *testing.T) {
	for _, optimized := range []bool{false, true} {
		ir := x86MulDivRoundHelperFixtureIR()
		if optimized {
			ir = x86MulDivRoundOptimize(t, ir)
		}
		for _, forbidden := range []string{
			`\b(fadd|fsub|fmul|fdiv|frem|fcmp|fptosi|fptoui|sitofp|uitofp)\b`,
			`\b(udiv|sdiv|urem|srem)\b`, `@llvm\.(fma|experimental\.constrained)`,
		} {
			if regexp.MustCompile(forbidden).MatchString(ir) {
				t.Fatalf("O2=%t: fixed-round SAE helper contains forbidden arithmetic %s", optimized, forbidden)
			}
		}
		if !optimized {
			for _, limit := range []string{"icmp eq i32 %next_iteration, 26", "icmp eq i32 %next_iteration, 55"} {
				if !strings.Contains(ir, limit) {
					t.Fatalf("missing exact restoring-division bound %s", limit)
				}
			}
		}
	}
}

func TestX86FloatMulDivIntegerRoundingFiveLLVM22Targets(t *testing.T) {
	llc, nm := findLLVM22Tool("llc"), findLLVM22Tool("llvm-nm")
	if llc == "" || nm == "" {
		t.Fatal("LLVM22 llc/llvm-nm required")
	}
	for _, optimized := range []bool{false, true} {
		ir := x86MulDivRoundHelperFixtureIR()
		backendLevel := "-O0"
		if optimized {
			ir = x86MulDivRoundOptimize(t, ir)
			backendLevel = "-O2"
		}
		for _, triple := range []string{
			"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
			"i386-unknown-linux-gnu", "i686-pc-windows-msvc",
		} {
			t.Run(fmt.Sprintf("O2-%t/%s", optimized, triple), func(t *testing.T) {
				dir := t.TempDir()
				source, object := filepath.Join(dir, "integer-round.ll"), filepath.Join(dir, "integer-round.o")
				assembly := filepath.Join(dir, "integer-round.s")
				if err := os.WriteFile(source, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				out, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, llc, backendLevel, "-mtriple="+triple, "-filetype=obj", source, "-o", object))
				cancel()
				if err != nil {
					t.Fatalf("LLVM22 object: %v\n%s", err, out)
				}
				ctx, cancel = runtimeOracleStageContext(t)
				out, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, nm, "--undefined-only", object))
				cancel()
				if err != nil {
					t.Fatalf("LLVM22 nm: %v\n%s", err, out)
				}
				for _, line := range strings.Split(string(out), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 {
						continue
					}
					// COFF's CRT floating-point marker has an extra C-name
					// prefix in mode32. It is not an arithmetic libcall.
					marker := "_fltused"
					if strings.HasPrefix(triple, "i686-") {
						marker = "__fltused"
					}
					if !strings.Contains(triple, "windows") || len(fields) != 2 || fields[0] != "U" || fields[1] != marker {
						t.Fatalf("integer helper has unresolved arithmetic dependency: %s", line)
					}
				}
				ctx, cancel = runtimeOracleStageContext(t)
				out, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, llc, backendLevel, "-mtriple="+triple, "-filetype=asm", source, "-o", assembly))
				cancel()
				if err != nil {
					t.Fatalf("LLVM22 machine assembly: %v\n%s", err, out)
				}
				machine, err := os.ReadFile(assembly)
				if err != nil {
					t.Fatal(err)
				}
				// Includes every helper and its actual call sites. An integer
				// IR body alone does not close a float-return x87 C ABI.
				floating := regexp.MustCompile(`(?m)^[\t ]+(f[a-z]+|v?(add|sub|mul|div|sqrt|comi|ucomi)(ss|sd|ps|pd))(\s|$)`)
				if instruction := floating.Find(machine); instruction != nil {
					t.Fatalf("SAE bit carrier emits floating instruction %q", instruction)
				}
			})
		}
	}
}

const x86MulDivRoundSSEOracle = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint32_t mul_div32(uint32_t,uint32_t,unsigned,unsigned,unsigned);
extern uint64_t mul_div64(uint64_t,uint64_t,unsigned,unsigned,unsigned);
static unsigned mismatches;
static uint64_t state=UINT64_C(0x372bd0ae71d94285);
static uint64_t random_bits(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}

/* Independent physical SSE. Language arithmetic, production classification,
   integer helpers and AVX512 are not used to compute expected result bits. */
__attribute__((noinline)) static uint64_t native_sse(unsigned width,uint64_t a,uint64_t b,unsigned divide,unsigned csr){
 unsigned saved;__asm__ volatile("stmxcsr %0":"=m"(saved)::"memory");
 __asm__ volatile("ldmxcsr %0"::"m"(csr):"memory");
 uint64_t result=0;
 if(width==32){
  uint32_t aa=a,bb=b,out;float left,right;memcpy(&left,&aa,4);memcpy(&right,&bb,4);
  if(divide)__asm__ volatile("divss %1,%0":"+x"(left):"x"(right));
  else __asm__ volatile("mulss %1,%0":"+x"(left):"x"(right));
  memcpy(&out,&left,4);result=out;
 }else{
  double left,right;memcpy(&left,&a,8);memcpy(&right,&b,8);
  if(divide)__asm__ volatile("divsd %1,%0":"+x"(left):"x"(right));
  else __asm__ volatile("mulsd %1,%0":"+x"(left):"x"(right));
  memcpy(&result,&left,8);
 }
 __asm__ volatile("ldmxcsr %0"::"m"(saved):"memory");return result;
}

static int check(unsigned width,uint64_t a,uint64_t b,unsigned divide,unsigned mode,unsigned ambient,unsigned control){
 unsigned actualCSR=control|(ambient<<13),referenceCSR=control|(mode<<13),saved,after;
 __asm__ volatile("stmxcsr %0":"=m"(saved)::"memory");
 __asm__ volatile("ldmxcsr %0"::"m"(actualCSR):"memory");
 uint64_t want=native_sse(width,a,b,divide,referenceCSR);
 uint64_t got=width==32?mul_div32(a,b,divide,mode,actualCSR):mul_div64(a,b,divide,mode,actualCSR);
 __asm__ volatile("stmxcsr %0":"=m"(after)::"memory");
 __asm__ volatile("ldmxcsr %0"::"m"(saved):"memory");
 if(got!=want||after!=actualCSR){
  if(mismatches++<8)fprintf(stderr,"integer MUL/DIV width/divide/mode/ambient/control=%u/%u/%u/%u/%x a=%llx b=%llx got=%llx want=%llx CSR=%x want=%x\n",width,divide,mode,ambient,control,(unsigned long long)a,(unsigned long long)b,(unsigned long long)got,(unsigned long long)want,after,actualCSR);
  return 1;
 }
 return 0;
}

static int matrix(unsigned width,uint64_t a,uint64_t b){
 const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};
 int failed=0;
 for(unsigned divide=0;divide<2;divide++)for(unsigned mode=0;mode<4;mode++)
  for(unsigned ambient=0;ambient<4;ambient++)for(unsigned c=0;c<6;c++)
   failed|=check(width,a,b,divide,mode,ambient,controls[c]);
 return failed;
}

int main(void){
 int failed=0;
 /* The first focused RED independently observes RU, not ambient RN. */
 failed|=check(32,0x3f800001,0x3f800001,0,2,0,0x1f80);
 failed|=check(64,UINT64_C(0x3ff0000000000000),UINT64_C(0x4008000000000000),1,2,0,0x1f80);
 /* Tiny before rounding, even though RU would produce minimum normal. */
 failed|=check(32,0x00800000,0x3f800001,1,2,0,0x9f80);
 failed|=check(64,UINT64_C(0x0010000000000000),UINT64_C(0x3ff0000000000001),1,2,0,0x9f80);
 const uint64_t edges32[]={0,0x80000000,1,0x80000001,0x7fffff,0x807fffff,0x800000,0x80800000,
  0x800001,0x7f7fffff,0xff7fffff,0x3f000000,0xbf000000,0x3f800000,0xbf800000,0x3f800001,
  0xbf800001,0x3f800002,0x40400000,0xc0400000,0x7f800000,0xff800000,0x7fc12345,0xffc45678,
  0x7f812345,0xff845678,0x00800000,0x40000000};
 const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),1,UINT64_C(0x8000000000000001),
  UINT64_C(0xfffffffffffff),UINT64_C(0x800fffffffffffff),UINT64_C(0x10000000000000),UINT64_C(0x8010000000000000),
  UINT64_C(0x10000000000001),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),
  UINT64_C(0x3fe0000000000000),UINT64_C(0xbfe0000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),
  UINT64_C(0x3ff0000000000001),UINT64_C(0xbff0000000000001),UINT64_C(0x3ff0000000000002),
  UINT64_C(0x4008000000000000),UINT64_C(0xc008000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),
  UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff8fedcba987654),UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff0fedcba987654),
  UINT64_C(0x10000000000000),UINT64_C(0x4000000000000000)};
 for(unsigned i=0;i<sizeof(edges32)/sizeof(edges32[0]);i++)for(unsigned j=0;j<sizeof(edges32)/sizeof(edges32[0]);j++)failed|=matrix(32,edges32[i],edges32[j]);
 for(unsigned i=0;i<sizeof(edges64)/sizeof(edges64[0]);i++)for(unsigned j=0;j<sizeof(edges64)/sizeof(edges64[0]);j++)failed|=matrix(64,edges64[i],edges64[j]);
 for(unsigned sample=0;sample<1024;sample++){
  uint64_t a=random_bits(),b=random_bits();failed|=matrix(32,(uint32_t)a,(uint32_t)b);failed|=matrix(64,a,b);
 }
 if(failed)fprintf(stderr,"MUL/DIV total mismatches=%u\n",mismatches);
 return failed;
}
`
