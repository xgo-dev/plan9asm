package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every ISA partition executes the original Go opcode and LLVM lowering on
// its required execution owner. This checks integer flags and whole inputs;
// separate COMI status/fault oracles check MXCSR and exceptional effects.
const x86ScalarCompareAFGoReference = `package scalarstatus

import (
 "encoding/binary"
 "math"
 "testing"
)

type kernel struct {
 fn func(*[96]byte, *[16]byte, *[16]byte, uint64)
 width int
 alias bool
}

func TestOriginalScalarCompareStatus(t *testing.T) {
 values := []float64{math.Inf(-1), -2, -1, math.Copysign(0,-1), 0, 1, 2, math.Inf(1), math.NaN()}
 for n,k := range kernels {
  for _,a := range values {
   for _,b := range values {
    var left,right [16]byte
    for i := range left { left[i]=byte(0x41+i); right[i]=byte(0xb1+i) }
    if k.width==32 {
     binary.LittleEndian.PutUint32(left[:],math.Float32bits(float32(a)))
     binary.LittleEndian.PutUint32(right[:],math.Float32bits(float32(b)))
    } else {
     binary.LittleEndian.PutUint64(left[:],math.Float64bits(a))
     binary.LittleEndian.PutUint64(right[:],math.Float64bits(b))
    }
    originalLeft,originalRight:=left,right
    comparedRight:=b
    expectedRight:=right
    if k.alias { comparedRight=a; expectedRight=left }
    want:=uint64(0)
    if math.IsNaN(a)||math.IsNaN(comparedRight) { want=0x45 } else if a==comparedRight { want=0x40 } else if a<comparedRight { want=1 }
    for _,seed:=range []uint64{0,0x8d5} {
     var out [96]byte
     for i:=range out { out[i]=0xa7 }
     k.fn(&out,&left,&right,seed)
     flags:=binary.LittleEndian.Uint64(out[:])&0x8d5
     if flags!=want||out[8]!=byte(want)|2 { t.Fatalf("kernel%d width%d a=%g b=%g seed=%x flags=%x lahf=%x want=%x",n,k.width,a,b,seed,flags,out[8],want) }
     expected:=[]byte{byte(want&1),byte(want>>2&1),byte(want>>6&1),0,0,0}
     for i,v:=range expected { if out[9+i]!=v { t.Fatalf("kernel%d SETcc%d",n,i) } }
     for i:=0;i<16;i++ { if out[32+i]!=left[i]||out[48+i]!=expectedRight[i] { t.Fatalf("kernel%d input vector clobber",n) } }
     if left!=originalLeft||right!=originalRight { t.Fatalf("kernel%d original input changed",n) }
     for i,v:=range out { if (i>=15&&i<32||i>=64)&&v!=0xa7 { t.Fatalf("kernel%d canary%d",n,i) } }
    }
   }
  }
 }
}
`

func TestCrossLinuxRuntimeMatrixX86ScalarCompareAFOriginalGo(t *testing.T) {
	x86ScalarCompareAFOriginalGo(t, x86FloatCompareSSE)
}

func x86ScalarCompareAFRuntimeCases(axis x86FloatCompareRuntimeISA) []x86ScalarCompareAFCase {
	var cases []x86ScalarCompareAFCase
	for _, row := range x86ScalarCompareAFCases("amd64", true) {
		owner := x86FloatCompareSSE
		if strings.HasPrefix(row.op, "V") {
			owner = x86FloatCompareVEX
			if row.dst >= 16 || row.src >= 16 || strings.HasSuffix(row.op, ".SAE") {
				owner = x86FloatCompareEVEX
			}
		}
		if owner == axis {
			cases = append(cases, row)
		}
	}
	return cases
}

func x86ScalarCompareAFOriginalGo(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	x86FloatCompareRuntimeTools(t, axis)
	dir := t.TempDir()
	for name, contents := range x86ScalarCompareAFOriginalFiles(axis) {
		data := []byte(contents)
		if strings.HasSuffix(name, ".go") {
			var err error
			data, err = format.Source(data)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	driver, _ := x86LEAActualSDKDriver(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go ISA%d status: %v\n%s", axis, err, output)
	}
	t.Logf("%d original ISA%d kernels ×81 pairs ×2 AF seeds, all six status bits/LAHF/SETcc and full input/output canaries", len(x86ScalarCompareAFRuntimeCases(axis)), axis)
}

func x86ScalarCompareAFOriginalFiles(axis x86FloatCompareRuntimeISA) map[string]string {
	cases := x86ScalarCompareAFRuntimeCases(axis)
	var declarations, kernels strings.Builder
	kernels.WriteString("var kernels=[]kernel{\n")
	for _, row := range cases {
		fmt.Fprintf(&declarations, "func %s(*[96]byte,*[16]byte,*[16]byte,uint64)\n", row.name)
		fmt.Fprintf(&kernels, "{%s,%d,%t},\n", row.name, row.bits, row.dst == row.src)
	}
	kernels.WriteString("}\n")
	return map[string]string{
		"go.mod":         "module scalarstatus\n\ngo 1.20\n",
		"status.go":      "package scalarstatus\n" + declarations.String(),
		"status_amd64.s": x86ScalarCompareAFAssembly("amd64", cases),
		"status_test.go": x86ScalarCompareAFGoReference + kernels.String(),
	}
}

const x86ScalarCompareAFCReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
typedef void (*kernel)(uint8_t*,uint8_t*,uint8_t*,uint64_t);

static int check(kernel fn, unsigned width, unsigned n, unsigned alias,
                 double a, double b, uint64_t seed) {
 uint8_t left[16], right[16], out[96], oldLeft[16], oldRight[16];
 for(unsigned i=0; i<16; i++) {
  left[i] = 0x41+i;
  right[i] = 0xb1+i;
 }
 if(width == 32) {
  float l=a, r=b;
  memcpy(left, &l, 4);
  memcpy(right, &r, 4);
 } else {
  memcpy(left, &a, 8);
  memcpy(right, &b, 8);
 }
 memcpy(oldLeft, left, 16);
 memcpy(oldRight, right, 16);
 memset(out, 0xa7, 96);

 fn(out, left, right, seed);

 double comparedRight = alias ? a : b;
 uint64_t want = isnan(a)||isnan(comparedRight) ? 0x45 :
                 a==comparedRight ? 0x40 : a<comparedRight ? 1 : 0, got;
 memcpy(&got, out, 8);
 got &= 0x8d5;
 if(got != want || out[8] != (want|2)) {
  fprintf(stderr, "scalar status kernel%u width%u a=%g b=%g seed=%llx flags=%llx lahf=%x want=%llx\n",
          n, width, a, b, (unsigned long long)seed, (unsigned long long)got,
          out[8], (unsigned long long)want);
  return 1;
 }

 const uint8_t cc[] = {want&1, (want>>2)&1, (want>>6)&1, 0, 0, 0};
 for(unsigned i=0; i<6; i++) {
  if(out[9+i] != cc[i]) {
   fprintf(stderr, "SETcc%u\n", i);
   return 1;
  }
 }

 if(memcmp(out+32, left, 16) || memcmp(out+48, alias ? left : right, 16) ||
    memcmp(left, oldLeft, 16) || memcmp(right, oldRight, 16)) {
  fprintf(stderr, "vector/input canary\n");
  return 1;
 }
 for(unsigned i=0; i<96; i++) {
  if(((i>=15 && i<32) || i>=64) && out[i] != 0xa7) {
   fprintf(stderr, "output canary%u\n", i);
   return 1;
  }
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86ScalarCompareAFLLVM(t *testing.T) {
	x86ScalarCompareAFLLVM(t, x86FloatCompareSSE)
}

func x86ScalarCompareAFLLVM(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, axis)
	cases := x86ScalarCompareAFRuntimeCases(axis)
	file, err := Parse(ArchAMD64, x86ScalarCompareAFAssembly("amd64", cases))
	if err != nil {
		t.Fatal(err)
	}
	main := x86ScalarCompareAFRuntimeC(cases)
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			ir, err := Translate(file, x86ScalarCompareAFOptions("amd64", execution.triple, cases))
			if err != nil {
				t.Fatal(err)
			}
			if optimized {
				ir = x86MulDivRoundOptimize(t, ir)
			}
			for _, backend := range []string{"-O0", "-O2"} {
				t.Run("backend"+backend, func(t *testing.T) {
					execution.compileAndRunLLVM(t, "scalar-compare-af", ir, main, backend)
				})
			}
			t.Logf("%d translated ISA%d kernels ×81 pairs ×2 AF seeds; integer flags and complete input/output canaries", len(cases), axis)
		})
	}
}

func x86ScalarCompareAFRuntimeC(cases []x86ScalarCompareAFCase) string {
	var declarations, checks strings.Builder
	for i, row := range cases {
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,uint8_t*,uint8_t*,uint64_t);\n", row.name)
		alias := 0
		if row.dst == row.src {
			alias = 1
		}
		fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d,a,b,seed)) {\n return 1;\n}\n", row.name, row.bits, i, alias)
	}
	return x86ScalarCompareAFCReference + declarations.String() + `
int main(void) {
 const double values[] = {-INFINITY, -2, -1, -0.0, 0, 1, 2, INFINITY, NAN};
 for(unsigned i=0; i<9; i++) {
  for(unsigned j=0; j<9; j++) {
   for(unsigned s=0; s<2; s++) {
    double a=values[i], b=values[j];
    uint64_t seed = s ? 0x8d5 : 0;
` + checks.String() + "   }\n  }\n }\n return 0;\n}\n"
}
