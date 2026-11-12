package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCrossLinuxRuntimeMatrixARM64ControlScalarMultiply(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecls, goChecks, cDecls, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for index, form := range arm64ControlMultiplyForms() {
		parts := strings.SplitN(form, " ", 2)
		name := fmt.Sprintf("multiplyCaller%d", index)
		result := "R30"
		if len(strings.Split(parts[1], ",")) == 2 {
			form, result = strings.Replace(form, "R30", "R7", 1), "R7"
		}
		body := "MOVD (R0),R4\nMOVD 8(R0),R5\nMOVD 16(R0),R6\nMOVD R5,R7\nCMP R5,R4\n" + form + "\n" +
			"CSET VS,R8\nCSET CS,R9\nLSL $1,R9\nORR R9,R8\nCSET EQ,R9\nLSL $2,R9\nORR R9,R8\nCSET MI,R9\nLSL $3,R9\nORR R9,R8\n" +
			"MOVD " + result + ",(R1)\nMOVD R8,8(R1)\n"
		source.WriteString(strings.Replace(arm64RawZeroFrameFixture(516, false, body), "rawZero", name, 1))
		sig := arm64RawZeroFrameSig()
		sig.Name = name
		sigs[name] = sig
		fmt.Fprintf(&goDecls, "func %s(*byte,*byte)\n", name)
		fmt.Fprintf(&cDecls, "extern void %s(const unsigned char*,unsigned char*);\n", name)
		fmt.Fprintf(&goChecks, "check(%s,%q)\n", name, parts[0])
		fmt.Fprintf(&cChecks, "if(check(%s,\"%s\"))return 1;\n", name, parts[0])
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const goOracle = `package main

import (
	"encoding/binary"
	"math/bits"
	"strings"
)

func expected(op string, a, b, c uint64) uint64 {
	if strings.Contains(op, "ADD") || strings.Contains(op, "SUB") {
		x, y := a, c
		if strings.HasPrefix(op, "S") {
			x = uint64(int64(int32(x)))
			y = uint64(int64(int32(y)))
		}
		if strings.HasPrefix(op, "U") {
			x = uint64(uint32(x))
			y = uint64(uint32(y))
		}
		r := b + x*y
		if strings.Contains(op, "SUB") {
			r = b - x*y
		}
		if strings.HasSuffix(op, "W") {
			r = uint64(uint32(r))
		}
		return r
	}
	if strings.HasSuffix(op, "H") {
		hi, _ := bits.Mul64(a, b)
		if op == "SMULH" {
			if int64(a) < 0 {
				hi -= b
			}
			if int64(b) < 0 {
				hi -= a
			}
		}
		return hi
	}
	x, y := a, b
	if strings.HasPrefix(op, "S") {
		x = uint64(int64(int32(x)))
		y = uint64(int64(int32(y)))
	}
	if strings.HasPrefix(op, "U") {
		x = uint64(uint32(x))
		y = uint64(uint32(y))
	}
	r := x * y
	if strings.Contains(op, "NEG") {
		r = 0 - r
	}
	if strings.HasSuffix(op, "W") {
		r = uint64(uint32(r))
	}
	return r
}
func check(call func(*byte, *byte), op string) {
	var input, output, want [96]byte
	seed := uint64(0x0123456789abcdef)
	for trial := 0; trial < 128; trial++ {
		for _, off := range []int{0, 1, 3, 7, 17} {
			for i := range input {
				seed = seed*6364136223846793005 + 1
				input[i] = byte(seed >> 56)
				output[i] = 0xa5
				want[i] = 0xa5
			}
			a := binary.LittleEndian.Uint64(input[off:])
			b := binary.LittleEndian.Uint64(input[off+8:])
			c := binary.LittleEndian.Uint64(input[off+16:])
			if trial < 64 {
				a = uint64(1) << trial
			}
			if trial == 64 {
				a = ^uint64(0)
				b = 1
			}
			if trial == 65 {
				a = 1 << 63
				b = 1
			}
			if trial == 66 {
				a = 0
				b = 0
			}
			binary.LittleEndian.PutUint64(input[off:], a)
			binary.LittleEndian.PutUint64(input[off+8:], b)
			d := a - b
			flags := uint64(0)
			if ((a^b)&(a^d))>>63 != 0 {
				flags |= 1
			}
			if a >= b {
				flags |= 2
			}
			if d == 0 {
				flags |= 4
			}
			if d>>63 != 0 {
				flags |= 8
			}
			binary.LittleEndian.PutUint64(want[off:], expected(op, a, b, c))
			binary.LittleEndian.PutUint64(want[off+8:], flags)
			snapshot := input
			call(&input[off], &output[off])
			if input != snapshot || output != want {
				panic("multiply math/NZCV/canary/caller mismatch: " + op)
			}
		}
	}
}
`
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":         "module multiplycalleroracle\n\ngo 1.20\n",
		"main.go":        goOracle + goDecls.String() + "func main(){\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source.String(), "TEXT multiplyCaller", "TEXT ·multiplyCaller"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("original Go scalar-multiply/LR caller oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const cOracle = `#include <stdint.h>
#include <string.h>
static uint64_t expected(const char *op, uint64_t a, uint64_t b, uint64_t c) {
  if (strstr(op, "ADD") || strstr(op, "SUB")) {
    uint64_t x = a, y = c;
    if (op[0] == 'S') {
      x = (uint64_t)(int64_t)(int32_t)x;
      y = (uint64_t)(int64_t)(int32_t)y;
    }
    if (op[0] == 'U') {
      x = (uint32_t)x;
      y = (uint32_t)y;
    }
    uint64_t r = strstr(op, "SUB") ? b - x * y : b + x * y;
    if (op[strlen(op) - 1] == 'W')
      r = (uint32_t)r;
    return r;
  }
  if (op[strlen(op) - 1] == 'H') {
    unsigned __int128 p;
    if (op[0] == 'S')
      p = (unsigned __int128)((__int128)(int64_t)a * (__int128)(int64_t)b);
    else
      p = (unsigned __int128)a * b;
    return (uint64_t)(p >> 64);
  }
  uint64_t x = a, y = b;
  if (op[0] == 'S') {
    x = (uint64_t)(int64_t)(int32_t)x;
    y = (uint64_t)(int64_t)(int32_t)y;
  }
  if (op[0] == 'U') {
    x = (uint32_t)x;
    y = (uint32_t)y;
  }
  uint64_t r = x * y;
  if (strstr(op, "NEG"))
    r = 0 - r;
  if (op[strlen(op) - 1] == 'W')
    r = (uint32_t)r;
  return r;
}
static int check(void (*call)(const unsigned char *, unsigned char *), const char *op) {
  unsigned char input[96], output[96], want[96], snapshot[96];
  const unsigned offsets[] = {0, 1, 3, 7, 17};
  uint64_t seed = UINT64_C(0x0123456789abcdef);
  for (unsigned trial = 0; trial < 128; trial++)
    for (unsigned o = 0; o < 5; o++) {
      unsigned off = offsets[o];
      for (unsigned i = 0; i < 96; i++) {
        seed = seed * UINT64_C(6364136223846793005) + 1;
        input[i] = (unsigned char)(seed >> 56);
        output[i] = 0xa5;
        want[i] = 0xa5;
      }
      uint64_t a, b, c;
      memcpy(&a, input + off, 8);
      memcpy(&b, input + off + 8, 8);
      memcpy(&c, input + off + 16, 8);
      if (trial < 64)
        a = UINT64_C(1) << trial;
      if (trial == 64) {
        a = UINT64_MAX;
        b = 1;
      }
      if (trial == 65) {
        a = UINT64_C(1) << 63;
        b = 1;
      }
      if (trial == 66) {
        a = 0;
        b = 0;
      }
      memcpy(input + off, &a, 8);
      memcpy(input + off + 8, &b, 8);
      uint64_t d = a - b, flags = 0;
      if (((a ^ b) & (a ^ d)) >> 63)
        flags |= 1;
      if (a >= b)
        flags |= 2;
      if (!d)
        flags |= 4;
      if (d >> 63)
        flags |= 8;
      uint64_t result = expected(op, a, b, c);
      memcpy(want + off, &result, 8);
      memcpy(want + off + 8, &flags, 8);
      memcpy(snapshot, input, 96);
      call(input + off, output + off);
      if (memcmp(input, snapshot, 96) || memcmp(output, want, 96))
        return 1;
    }
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "multiply_caller", triple, ir,
		cOracle+cDecls.String()+"int main(void){\n"+cChecks.String()+"return 0;}\n", runner)
	t.Log("original Go + LLVM22/independent Go and C: 28 forms x 128 patterns x 5 unaligned offsets, numerical low/high/signed/accumulate results, all NZCV sentinels, full canaries and restored LR/BP/SP")
}
