package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func x86ScalarFPBitRuntimeSources() (string, string) {
	var declarations, assembly strings.Builder
	declarations.WriteString("package bitview\n")
	for _, fixture := range x86ScalarFPBitFixtures() {
		if strings.Contains(fixture.name, "byte-fields") || strings.Contains(fixture.name, "-fields-") {
			continue // Independent-field byte layouts have separate object coverage.
		}
		name := strings.ReplaceAll(fixture.name, "-", "_")
		if name[0] >= '0' && name[0] <= '9' {
			name = "bits_" + name
		}
		declarations.WriteString(strings.Replace(fixture.declaration, "view(", name+"(", 1))
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n%s\nRET\n", name, fixture.args, fixture.body)
	}
	return declarations.String(), assembly.String()
}

func x86ScalarFPOriginalGoBits(t *testing.T) {
	t.Helper()
	declarations, assembly := x86ScalarFPBitRuntimeSources()
	// Execute original baseline SSE only. The VEX/mask source objects are
	// independently assembled; their LLVM logical-byte oracle needs no AVX ISA.
	const driver = `package bitview
import (
 "math"
 "testing"
)

// A bodyless call with an actual buffer address makes all canary bytes
// observable to the compiler; these are not constant-folded local arrays.
func observe(memory *[64]byte)
func getCSR() uint32
func setCSR(value uint32)

func TestOriginalBits(t *testing.T) {
 savedCSR:=getCSR()
 defer setCSR(savedCSR)
 state := uint64(0x7182329ab3293821)
 edges := []uint64{0,1,^uint64(0),0x8000000000000000,
  0x7ff0000000000001,0xfff8456781234567,0x80000001,0x7f812345}
 for iteration:=0;iteration<256;iteration++ {
  state ^= state<<13; state ^= state>>7; state ^= state<<17
  x,y:=state,state^0x8192736455aaccff
  if iteration<len(edges) { x=edges[iteration] }
  var canary [64]byte
  for i:=range canary { canary[i]=byte(i*19+iteration) }
  before:=canary
  csr:=uint32(0x1f80)|uint32(iteration&63)|uint32(iteration&3)<<13
  if iteration&4!=0 { csr|=1<<6 }
  if iteration&8!=0 { csr|=1<<15 }
  setCSR(csr)
  observe(&canary)
  if got:=low_int64(x);got!=uint32(x) { t.Fatalf("low %x",got) }
  if got:=high_int64(int64(x));got!=uint32(x>>32) { t.Fatalf("high %x",got) }
  if got:=cross_uint32(uint32(x),uint32(y));got!=uint64(uint32(x))|uint64(uint32(y))<<32 { t.Fatalf("cross %x",got) }
  want:=x&^uint64(0xffffffff0000)|uint64(uint32(y))<<16
  if got:=store_subword(x,y);got!=want { t.Fatalf("store got=%x want=%x",got,want) }
  if got:=read_written_result(x);got!=^uint32(0) { t.Fatalf("result %x",got) }
  if got:=inverse32(math.Float32frombits(uint32(x)));got!=uint32(x) { t.Fatalf("inverse32 %x",got) }
  if got:=inverse64(math.Float64frombits(x));got!=x { t.Fatalf("inverse64 %x",got) }
  if got:=getCSR();got!=csr { t.Fatalf("MXCSR got=%x want=%x",got,csr) }
  observe(&canary)
  if canary!=before { t.Fatal("full memory canary changed") }
 }
}
`
	formatted, err := format.Source([]byte(driver))
	if err != nil {
		t.Fatal(err)
	}
	// This observation helper is not translated or granted a caller contract.
	assembly += "TEXT ·observe(SB),4,$0-8\nMOVQ memory+0(FP),AX\nMOVOU (AX),X0\nMOVOU 16(AX),X0\nMOVOU 32(AX),X0\nMOVOU 48(AX),X0\nRET\n"
	assembly += "TEXT ·getCSR(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\nTEXT ·setCSR(SB),4,$0-4\nLDMXCSR value+0(FP)\nRET\n"
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module bitview\n\ngo 1.20\n", "value.go": declarations,
		"value_amd64.s": assembly, "value_test.go": string(formatted),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	driverPath, _ := x86LEAActualSDKDriver(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driverPath, "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go scalar bit views: %v\n%s", err, output)
	} else {
		t.Logf("original Go baseline SSE/GP: 7 kernels x 256 bit patterns, full observable canary: %s", output)
	}
}

const x86ScalarFPBitCOracle = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <xmmintrin.h>
extern uint32_t low_int64(uint64_t),high_int64(uint64_t),read_written_result(uint64_t);
extern uint64_t cross_uint32(uint32_t,uint32_t),store_subword(uint64_t,uint64_t);
extern uint32_t vex_low_int64(uint64_t),vex_high_int64(uint64_t),vex_read_written_result(uint64_t);
extern uint64_t vex_cross_uint32(uint32_t,uint32_t),vex_store_subword(uint64_t,uint64_t);
extern uint32_t masked_load_0_zerofalse(uint64_t,uint64_t),masked_load_0_zerotrue(uint64_t,uint64_t);
extern uint32_t masked_load_1_zerofalse(uint64_t,uint64_t),masked_load_1_zerotrue(uint64_t,uint64_t);
extern uint64_t masked_store_0(uint64_t,uint64_t),masked_store_1(uint64_t,uint64_t);
extern uint64_t masked_double_load_0_zerofalse(uint64_t,uint64_t),masked_double_load_0_zerotrue(uint64_t,uint64_t);
extern uint64_t masked_double_load_1_zerofalse(uint64_t,uint64_t),masked_double_load_1_zerotrue(uint64_t,uint64_t);
extern uint64_t masked_double_store_0(uint64_t,uint64_t),masked_double_store_1(uint64_t,uint64_t);
extern uint32_t inverse32(float);
extern uint64_t inverse64(double);

int main(void) {
 unsigned savedCSR=_mm_getcsr();
 uint64_t state=UINT64_C(0x7182329ab3293821);
 const uint64_t edges[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
  UINT64_C(0x7ff0000000000001),UINT64_C(0xfff8456781234567),0x80000001,0x7f812345};
 for (unsigned iteration=0;iteration<256;iteration++) {
  state^=state<<13;
  state^=state>>7;
  state^=state<<17;
  uint64_t x=state,y=state^UINT64_C(0x8192736455aaccff);
  if (iteration<sizeof(edges)/sizeof(edges[0])) {
   x=edges[iteration];
  }
  volatile uint8_t canary[64];
  uint8_t before[64];
  for (unsigned i=0;i<64;i++) {
   before[i]=(uint8_t)(i*19+iteration);
   canary[i]=before[i];
  }
  uint64_t cross=(uint64_t)(uint32_t)x|((uint64_t)(uint32_t)y<<32);
  uint64_t patched=x&~UINT64_C(0xffffffff0000)|((uint64_t)(uint32_t)y<<16);
  uint32_t low=(uint32_t)x;
  float single;
  double pair;
  memcpy(&single,&low,sizeof(single));
  memcpy(&pair,&x,sizeof(pair));
  unsigned csr=0x1f80|(iteration&63)|((iteration&3)<<13);
  if (iteration&4) {
   csr|=1<<6;
  }
  if (iteration&8) {
   csr|=1<<15;
  }
  _mm_setcsr(csr);
  if (inverse32(single)!=low || inverse64(pair)!=x) {
   return 5;
  }
  if (low_int64(x)!=(uint32_t)x || high_int64(x)!=(uint32_t)(x>>32) ||
      cross_uint32((uint32_t)x,(uint32_t)y)!=cross || store_subword(x,y)!=patched ||
      read_written_result(x)!=UINT32_MAX) {
   return 1;
  }
  if (vex_low_int64(x)!=(uint32_t)x || vex_high_int64(x)!=(uint32_t)(x>>32) ||
      vex_cross_uint32((uint32_t)x,(uint32_t)y)!=cross || vex_store_subword(x,y)!=patched ||
      vex_read_written_result(x)!=UINT32_MAX) {
   return 2;
  }
  if (masked_load_0_zerofalse(x,y)!=(uint32_t)y || masked_load_0_zerotrue(x,y)!=0 ||
      masked_load_1_zerofalse(x,y)!=(uint32_t)(x>>32) ||
      masked_load_1_zerotrue(x,y)!=(uint32_t)(x>>32) ||
      masked_store_0(x,y)!=x || masked_store_1(x,y)!=patched) {
   return 3;
  }
  if (masked_double_load_0_zerofalse(x,y)!=y || masked_double_load_0_zerotrue(x,y)!=0 ||
      masked_double_load_1_zerofalse(x,y)!=x || masked_double_load_1_zerotrue(x,y)!=x ||
      masked_double_store_0(x,y)!=x || masked_double_store_1(x,y)!=y) {
   return 6;
  }
  if (_mm_getcsr()!=csr) {
   return 7;
  }
  for (unsigned i=0;i<64;i++) {
   if (canary[i]!=before[i]) {
    return 4;
   }
  }
 }
 _mm_setcsr(savedCSR);
 puts("24 kernels x 256 patterns; full bit and canary equality");
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86ScalarFPBitViewsOriginalBitsAndCanaries(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	x86ScalarFPOriginalGoBits(t)
	declarations, assembly := x86ScalarFPBitRuntimeSources()
	declarations = strings.TrimPrefix(declarations, "package bitview\n")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"0", "2"} {
				t.Run("O"+level, func(t *testing.T) {
					text := ir
					if level == "2" {
						text = x86SignedIntegerFloatOptimize(t, text)
					}
					x86ScalarFPBitRuntime(t, llc, clang, triple, text, "-O"+level, prefix)
				})
			}
		})
	}
}

func x86ScalarFPBitRuntime(t *testing.T, llc, clang, triple, ir, level string, prefix []string) {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "view.ll"), filepath.Join(dir, "view.o")
	source, executable := filepath.Join(dir, "oracle.c"), filepath.Join(dir, gotoolchain.HostExecutable("oracle"))
	process := runtimeOracleProcessSource(t, dir)
	for path, text := range map[string]string{input: ir, source: x86ScalarFPBitCOracle} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []*exec.Cmd{
		exec.Command(llc, level, "-mtriple="+triple, "-filetype=obj", input, "-o", object),
		exec.Command(clang, "-target", triple, level, object, source, process, "-o", executable),
	} {
		x86FloatCompareCaptureCommand(t, command)
	}
	arguments := runtimeOracleGuestArguments(t, prefix, executable)
	output := x86FloatCompareCaptureCommand(t, exec.Command(arguments[0], arguments[1:]...))
	if string(output) != "24 kernels x 256 patterns; full bit and canary equality\n" {
		t.Fatalf("unexpected scalar bit oracle receipt: %q", output)
	}
	t.Logf("LLVM22 %s logical byte execution: %s", level, output)
}
