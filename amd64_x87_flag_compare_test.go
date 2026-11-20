package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type x87FlagCompareCase struct {
	name string
	op   string
	lane int
}

// Go's complete yfcmv/ycompp direct-EFLAGS compare family: both pop modes,
// both ordered/unordered exception policies, and every ST(i) register.
func x87FlagCompareCases() []x87FlagCompareCase {
	var rows []x87FlagCompareCase
	for _, op := range []string{"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP"} {
		for lane := 0; lane < 8; lane++ {
			rows = append(rows, x87FlagCompareCase{
				name: fmt.Sprintf("x87flags%d", len(rows)), op: op, lane: lane,
			})
		}
	}
	return rows
}

func x87FlagCompareAssembly(arch string) string {
	width, args := "Q", 8
	if arch == "386" {
		width, args = "L", 4
	}
	var source strings.Builder
	for _, row := range x87FlagCompareCases() {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\nFINIT\n", row.name, args, width)
		// Eight real initialized x87 stack entries. Comparing ST(0) to itself
		// needs no missing operand, and pop forms still have valid backing.
		for i := 0; i < 7; i++ {
			source.WriteString("FMOVD 8(DI),F0\n")
		}
		source.WriteString("FMOVD 0(DI),F0\n")
		fmt.Fprintf(&source, "PUSH%s 16(DI)\nPOPF%s\n", width, width)
		if strings.HasPrefix(row.op, "FUCOM") {
			fmt.Fprintf(&source, "%s F0,F%d\n", row.op, row.lane)
		} else {
			fmt.Fprintf(&source, "%s F%d,F0\n", row.op, row.lane)
		}
		fmt.Fprintf(&source, "PUSHF%s\nPOP%s AX\nMOV%s AX,24(DI)\nLAHF\nMOVB AH,32(DI)\n", width, width, width)
		source.WriteString("SETCS 33(DI)\nSETPS 34(DI)\nSETEQ 35(DI)\nSETMI 36(DI)\nSETOS 37(DI)\nSETLT 38(DI)\nFINIT\nRET\n")
	}
	return source.String()
}

func x87FlagCompareOptions(arch, triple string) Options {
	sigs := make(map[string]FuncSig)
	for _, row := range x87FlagCompareCases() {
		sigs[row.name] = FuncSig{
			Name: row.name, Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}
	}
	return Options{
		Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	}
}

func TestX87DirectFlagCompareCompleteGoObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source := x87FlagCompareAssembly(target.arch)
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, x87FlagCompareOptions(target.arch, target.triple))
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "x87flags.ll", "x87flags.o", ir)
		})
	}
}

const x87FlagCompareOriginalReference = `package original

import (
 "encoding/binary"
 "math"
 "testing"
)

type kernel struct {
 call func(*[64]byte)
 lane int
 name string
}

func TestCompleteStatus(t *testing.T) {
 values := []float64{0, math.Copysign(0, -1), -1, 1, -19.75, 19.75,
  math.SmallestNonzeroFloat64, math.MaxFloat64, math.Inf(-1), math.Inf(1), math.NaN()}
 for _, k := range kernels {
  for _, a := range values {
   for _, b := range values {
    for _, seed := range []uint64{0, 0x8d5} {
     var out [64]byte
     for i := range out { out[i] = 0xa7 }
     binary.LittleEndian.PutUint64(out[0:8], math.Float64bits(a))
     binary.LittleEndian.PutUint64(out[8:16], math.Float64bits(b))
     binary.LittleEndian.PutUint64(out[16:24], seed)
     before := out
     k.call(&out)
     right := b
     if k.lane == 0 { right = a }
     want := uint64(0)
     switch {
     case math.IsNaN(a) || math.IsNaN(right): want = 0x45
     case a == right: want = 0x40
     case a < right: want = 1
     }
     flags := binary.LittleEndian.Uint64(out[24:32]) & 0x8d5
     if flags != want || out[32] != byte(want) | 2 {
      t.Fatalf("%s a=%g b=%g seed=%x flags=%x LAHF=%x want=%x", k.name, a, b, seed, flags, out[32], want)
     }
     positions := []uint{0, 2, 6, 7, 11}
     for i, bit := range positions {
      if out[33+i] != byte(want >> bit & 1) { t.Fatalf("%s SETcc %d", k.name, bit) }
     }
     if out[38] != 0 { t.Fatalf("%s SETLT", k.name) }
     for i, value := range out {
      if (i < 24 || i >= 39) && value != before[i] { t.Fatalf("%s canary %d", k.name, i) }
     }
    }
   }
  }
 }
}
`

func TestCrossLinuxRuntimeMatrixX87DirectFlagCompareOriginalGo(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	x87DirectFlagCompareOriginalGo(t, "amd64", nil)
}

func x87DirectFlagCompareOriginalGo(t *testing.T, arch string, runner []string) {
	t.Helper()
	dir := x87FlagCompareOriginalDirectory(t, arch)
	args := []string{"test", "-p=2", "-vet=off", "-count=1"}
	if len(runner) != 0 {
		args = append(args, "-exec", strings.Join(runner, " "))
	}
	args = append(args, ".")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go full x87 status: %v\n%s", err, output)
	}
	t.Log("32 initialized original Go kernels, 121 IEEE value pairs, both AF seeds, all six status flags, LAHF, SETcc and byte canaries")
}

func x87FlagCompareOriginalDirectory(t *testing.T, arch string) string {
	t.Helper()
	var declarations, kernels strings.Builder
	kernels.WriteString("var kernels = []kernel{\n")
	for _, row := range x87FlagCompareCases() {
		fmt.Fprintf(&declarations, "func %s(*[64]byte)\n", row.name)
		fmt.Fprintf(&kernels, "{%s, %d, %q},\n", row.name, row.lane, row.op)
	}
	kernels.WriteString("}\n")
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":                  "module original\n\ngo 1.20\n",
		"original.go":             "package original\n" + declarations.String(),
		"original_" + arch + ".s": x87FlagCompareAssembly(arch),
		"original_test.go":        x87FlagCompareOriginalReference + kernels.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const x87FlagCompareCReference = `
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void (*kernel)(uint8_t *);

static int check(kernel call, const char *name, int lane,
                 double a, double b, uint64_t seed) {
 uint8_t out[64], before[64];
 memset(out, 0xa7, sizeof(out));
 memcpy(out, &a, 8);
 memcpy(out + 8, &b, 8);
 memcpy(out + 16, &seed, 8);
 memcpy(before, out, sizeof(out));
 call(out);

 double right = lane == 0 ? a : b;
 uint64_t want = isnan(a) || isnan(right) ? 0x45 : a == right ? 0x40 : a < right ? 1 : 0;
 uint64_t flags;
 memcpy(&flags, out + 24, 8);
 flags &= 0x8d5;
 if (flags != want || out[32] != ((want & 255) | 2)) {
  fprintf(stderr, "%s lane=%d a=%g b=%g seed=%llx flags=%llx lahf=%x want=%llx\n",
          name, lane, a, b, (unsigned long long)seed,
          (unsigned long long)flags, out[32], (unsigned long long)want);
  return 1;
 }
 const unsigned positions[] = {0, 2, 6, 7, 11};
 for (unsigned i = 0; i < 5; i++) {
  if (out[33+i] != ((want >> positions[i]) & 1)) {
   return 2;
  }
 }
 if (out[38] != 0) {
  return 3;
 }
 for (unsigned i = 0; i < 64; i++) {
  if ((i < 24 || i >= 39) && out[i] != before[i]) {
   return 4;
  }
 }
 return 0;
}
`

func x87DirectFlagCompareRuntime(t *testing.T, arch, triple string, run func(*testing.T, string, string)) {
	x87DirectFlagCompareRuntimeWithMode(t, arch, triple, X87Auto, run)
}

func x87DirectFlagCompareRuntimeWithMode(t *testing.T, arch, triple string, mode X87Mode, run func(*testing.T, string, string)) {
	t.Helper()
	file, err := Parse(ArchAMD64, x87FlagCompareAssembly(arch))
	if err != nil {
		t.Fatal(err)
	}
	var declarations, checks strings.Builder
	for _, row := range x87FlagCompareCases() {
		fmt.Fprintf(&declarations, "extern void %s(uint8_t *);\n", row.name)
		fmt.Fprintf(&checks, "    if (check(%s, %q, %d, a, b, seed)) return 1;\n", row.name, row.op, row.lane)
	}
	main := x87FlagCompareCReference + declarations.String() + `
int main(void) {
 const double values[] = {
  0, -0.0, -1, 1, -19.75, 19.75, 0x1p-1074, 0x1.fffffffffffffp1023,
  -INFINITY, INFINITY, NAN
 };
 for (unsigned left = 0; left < 11; left++) {
  for (unsigned right = 0; right < 11; right++) {
   for (unsigned s = 0; s < 2; s++) {
    double a = values[left], b = values[right];
    uint64_t seed = s ? 0x8d5 : 0;
` + checks.String() + "   }\n  }\n }\n return 0;\n}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			options := x87FlagCompareOptions(arch, triple)
			options.X87Mode = mode
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			if optimized {
				ir = x86MulDivRoundOptimize(t, ir)
			}
			run(t, ir, main)
		})
	}
}

func TestCrossLinuxRuntimeMatrixX87DirectFlagCompareLLVM(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	x87DirectFlagCompareRuntime(t, "amd64", triple, func(t *testing.T, ir, main string) {
		compileAndRunRuntimeTestForTarget(t, llc, clang, "x87-direct-flags", triple, ir, main, prefix)
	})
}
