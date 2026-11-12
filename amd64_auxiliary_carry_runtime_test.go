package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The reference computes carry/borrow using widened arithmetic, including the
// low nibble for AF; it does not repeat the lowerer's XOR-bit implementation.
const x86AuxiliaryGoReference = `package auxiliary

import (
 "encoding/binary"
 "math/bits"
 "testing"
)

type kernel struct {
 fn func(*[64]byte, uint64, uint64, uint64)
 op string
 width, form int
}

func expected(op string, width, form int, a, b, seed uint64) uint64 {
 if width == 0 || (op == "CMPS" || op == "SCAS") && form != 0 {
  return seed & 0x8d5
 }
 mask := ^uint64(0)
 if width < 64 {
  mask = (uint64(1) << width) - 1
 }
 a &= mask
 b &= mask
 if form == 3 {
  b = 1
 }
 carry := uint64(0)
 if op == "ADC" || op == "SBB" {
  carry = seed & 1
 }
 add := op == "ADD" || op == "ADC" || op == "INC" || op == "XADD"
 switch op {
 case "INC", "DEC":
  b = 1
 case "NEG":
  b, a = a, 0
 case "CMPXCHG":
  a, b = b, a
 }

 result := a - b - carry
 cf := a < b || a == b && carry != 0
 af := (a & 15) < (b & 15) + carry
 if add {
  var c uint64
  result, c = bits.Add64(a, b, carry)
  cf = c != 0 || width < 64 && result > mask
  af = (a & 15) + (b & 15) + carry > 15
 }
 result &= mask
 sign := uint64(1) << (width - 1)
 overflow := ((a ^ b) & (a ^ result) & sign) != 0
 if add {
  overflow = ((^(a ^ b)) & (a ^ result) & sign) != 0
 }
 if op == "INC" || op == "DEC" {
  cf = seed & 1 != 0
 }

 f := uint64(0)
 if cf { f |= 1 }
 if bits.OnesCount8(uint8(result)) % 2 == 0 { f |= 4 }
 if af { f |= 16 }
 if result == 0 { f |= 64 }
 if result & sign != 0 { f |= 128 }
 if overflow { f |= 2048 }
 return f
}

func check(t *testing.T, k kernel, a, b, seed uint64) {
 t.Helper()
 var out [64]byte
 for i := range out {
  out[i] = 0xa7
 }
 k.fn(&out, a, b, seed)
 want := expected(k.op, k.width, k.form, a, b, seed)
 got := binary.LittleEndian.Uint64(out[24:32]) & 0x8d5
 if got != want || out[32] != byte(want) | 2 {
  t.Fatalf("%s width=%d form=%d a=%x b=%x seed=%x flags=%x LAHF=%x want=%x", k.op, k.width, k.form, a, b, seed, got, out[32], want)
 }
 flags := []uint64{want & 1, (want >> 2) & 1, (want >> 6) & 1, (want >> 7) & 1, (want >> 11) & 1, ((want >> 7) ^ (want >> 11)) & 1}
 for i, v := range flags {
  if out[33+i] != byte(v) {
   t.Fatalf("%s SETcc %d got=%d want=%d", k.op, i, out[33+i], v)
  }
 }
 for i, v := range out {
  if (i >= 16 && i < 24 || i >= 39) && v != 0xa7 {
   t.Fatalf("%s byte canary %d", k.op, i)
  }
 }
}

func TestOriginalArithmeticStatus(t *testing.T) {
 edges := []uint64{0, 1, 15, 16, 17, 127, 128, 255, 256, 32767, 32768, 65535, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, 0x8000000000000000, ^uint64(0)}
 for _, k := range kernels {
  for _, seed := range []uint64{0, 0x8d5} {
   for a := uint64(0); a < 16; a++ {
    for b := uint64(0); b < 16; b++ {
     check(t, k, a, b, seed)
    }
   }
   for i, a := range edges {
    for _, b := range []uint64{edges[(i+1)%len(edges)], edges[(i+7)%len(edges)]} {
     check(t, k, a, b, seed)
    }
   }
  }
 }
}
`

func TestCrossLinuxRuntimeMatrixX86AuxiliaryCarryOriginalGo(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	var cases []x86AuxiliaryCase
	for _, row := range x86AuxiliaryCases("amd64") {
		if row.op != "CMPXCHG" {
			cases = append(cases, row)
		}
	}
	x86AuxiliaryOriginalGo(t, cases)
}

func TestCrossLinuxRuntimeMatrixX86AuxiliaryCarryCMPXCHGNativeGo(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("original CMPXCHG flags require the native AMD64 cross-runtime job, not Rosetta")
	}
	var cases []x86AuxiliaryCase
	for _, row := range x86AuxiliaryCases("amd64") {
		if row.op == "CMPXCHG" {
			cases = append(cases, row)
		}
	}
	x86AuxiliaryOriginalGo(t, cases)
}

func x86AuxiliaryOriginalGo(t *testing.T, cases []x86AuxiliaryCase) {
	t.Helper()
	var declarations, kernels strings.Builder
	kernels.WriteString("var kernels=[]kernel{\n")
	for _, row := range cases {
		fmt.Fprintf(&declarations, "func %s(*[64]byte,uint64,uint64,uint64)\n", row.name)
		fmt.Fprintf(&kernels, "{%s,%q,%d,%d},\n", row.name, row.op, row.bits, row.form)
	}
	kernels.WriteString("}\n")
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":            "module auxiliary\n\ngo 1.20\n",
		"auxiliary.go":      "package auxiliary\n" + declarations.String(),
		"auxiliary_amd64.s": x86AuxiliaryAssembly("amd64", cases),
		"auxiliary_test.go": x86AuxiliaryGoReference + kernels.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go complete arithmetic status: %v\n%s", err, output)
	}
	t.Logf("%d original Go kernels, exhaustive low nibbles, both CF/AF seeds and signed/unsigned width boundaries", len(cases))
}

const x86AuxiliaryCReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*kernel)(uint8_t *, uint64_t, uint64_t, uint64_t);

static int check(kernel fn, const char *op, int width, int form,
                 uint64_t a, uint64_t b, uint64_t seed) {
 _Alignas(8) uint8_t out[64];
 memset(out, 0xa7, sizeof(out));
 fn(out, a, b, seed);

 uint64_t want = seed & 0x8d5;
 if (width && !((!strcmp(op, "CMPS") || !strcmp(op, "SCAS")) && form)) {
  uint64_t mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
  a &= mask;
  b &= mask;
  if (form == 3) {
   b = 1;
  }
  unsigned carry = !strcmp(op, "ADC") || !strcmp(op, "SBB") ? seed & 1 : 0;
  int add = !strcmp(op, "ADD") || !strcmp(op, "ADC") ||
            !strcmp(op, "INC") || !strcmp(op, "XADD");
  if (!strcmp(op, "INC") || !strcmp(op, "DEC")) {
   b = 1;
  }
  if (!strcmp(op, "NEG")) {
   b = a;
   a = 0;
  }
  if (!strcmp(op, "CMPXCHG")) {
   uint64_t swap = a;
   a = b;
   b = swap;
  }

  __uint128_t wide = add ? (__uint128_t)a + b + carry : (__uint128_t)a - b - carry;
  uint64_t result = (uint64_t)wide & mask;
  unsigned cf = add ? wide > mask : (__uint128_t)a < (__uint128_t)b + carry;
  unsigned af = add ? (a & 15) + (b & 15) + carry > 15 : (a & 15) < (b & 15) + carry;
  uint64_t sign = UINT64_C(1) << (width - 1);
  unsigned of = (add ? (~(a ^ b) & (a ^ result)) : (a ^ b) & (a ^ result)) & sign ? 1 : 0;
  if (!strcmp(op, "INC") || !strcmp(op, "DEC")) {
   cf = seed & 1;
  }
  unsigned ones = 0;
  for (unsigned i = 0; i < 8; i++) {
   ones += (result >> i) & 1;
  }
  want = cf | ((ones % 2 == 0) << 2) | (af << 4) | ((result == 0) << 6) |
         ((!!(result & sign)) << 7) | (of << 11);
 }

 uint64_t flags;
 memcpy(&flags, out + 24, 8);
 flags &= 0x8d5;
 if (flags != want || out[32] != ((want & 255) | 2)) {
  fprintf(stderr, "%s width=%d form=%d flags=%llx lahf=%x want=%llx\n",
          op, width, form, (unsigned long long)flags, out[32], (unsigned long long)want);
  return 1;
 }
 unsigned bits[] = {0, 2, 6, 7, 11};
 for (unsigned i = 0; i < 5; i++) {
  if (out[33+i] != ((want >> bits[i]) & 1)) {
   return 2;
  }
 }
 if (out[38] != (((want >> 7) ^ (want >> 11)) & 1)) {
  return 3;
 }
 for (unsigned i = 16; i < 24; i++) {
  if (out[i] != 0xa7) {
   return 4;
  }
 }
 for (unsigned i = 39; i < 64; i++) {
  if (out[i] != 0xa7) {
   return 5;
  }
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86AuxiliaryCarryLLVM(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	cases := x86AuxiliaryCases("amd64")
	file, err := Parse(ArchAMD64, x86AuxiliaryAssembly("amd64", cases))
	if err != nil {
		t.Fatal(err)
	}
	var declarations, checks strings.Builder
	for _, row := range cases {
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,uint64_t,uint64_t,uint64_t);\n", row.name)
		fmt.Fprintf(&checks, "if(check(%s,%q,%d,%d,a,b,seed))return 1;\n", row.name, row.op, row.bits, row.form)
	}
	main := x86AuxiliaryCReference + declarations.String() + `
int main(void) {
 const uint64_t edges[] = {
  0, 1, 15, 16, 17, 127, 128, 255, 256, 32767, 32768, 65535,
  0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff,
  0x8000000000000000, UINT64_MAX
 };
 for (unsigned s = 0; s < 2; s++) {
  for (unsigned i = 0; i < 292; i++) {
   uint64_t seed = s ? 0x8d5 : 0, a, b;
   if (i < 256) {
    a = i / 16;
    b = i % 16;
   } else {
    a = edges[(i-256)/2];
    b = edges[((i-256)/2 + (i%2 ? 7 : 1))%18];
   }
` + checks.String() + "  }\n }\n return 0;\n}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			ir, err := Translate(file, x86AuxiliaryOptions("amd64", triple, cases))
			if err != nil {
				t.Fatal(err)
			}
			if optimized {
				ir = x86MulDivRoundOptimize(t, ir)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "auxiliary-status", triple, ir, main, prefix)
		})
	}
}
