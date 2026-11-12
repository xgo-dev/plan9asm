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

func TestCrossLinuxRuntimeMatrixARM64RawZeroFrameFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, sigs, source, cases := arm64RawZeroFrameFamilyFixture(t)
	var goDeclarations, goChecks, cDeclarations, cChecks strings.Builder
	for _, tc := range cases {
		fmt.Fprintf(&goDeclarations, "func %s(*byte,*byte)\n", tc.name)
		fmt.Fprintf(&cDeclarations, "extern void %s(const unsigned char *,unsigned char *);\n", tc.name)
		floating := 0
		if tc.floating {
			floating = 1
		}
		fmt.Fprintf(&goChecks, "check(%s,%d,%d,%d,%d)\n", tc.name, tc.width, tc.count, tc.signBits, floating)
		fmt.Fprintf(&cChecks, "if(check(%s,%d,%d,%d,%d)) return 1;\n", tc.name, tc.width, tc.count, tc.signBits, floating)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":         "module rawzeroframeoracle\n\ngo 1.20\n",
		"main.go":        arm64RawPrivateFrameOracleGo + goDeclarations.String() + "func main(){\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT zero_", "TEXT ·zero_"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "main", "-o", filepath.Join(dir, "oracle.o"), filepath.Join(dir, "oracle_arm64.s"))
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	listing, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil {
		t.Fatalf("actual Go zero/raw leaf object: %v\n%s", err, listing)
	}
	if !strings.Contains(string(listing), "LEAF|NOFRAME, $0-16") || strings.Contains(string(listing), "MOVD.W\tR30,") {
		t.Fatal("actual Go unexpectedly provided a framed LR prologue to a raw local BL")
	}
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	cmd = exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go raw zero-frame LR/SP/BP caller oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	cMain := arm64RawPrivateFrameOracleC + cDeclarations.String() + "int main(void){\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "raw_zero_frame_family", triple, ir, cMain, runner)
	t.Logf("actual Go raw WORD and LLVM22/independent C: %d variants x 256 patterns x 5 unaligned offsets; full input/output canaries and real LR-returning callers", len(cases))
}

func arm64RawZeroRepeatedNumericSource(t *testing.T) string {
	t.Helper()
	// Use ordinary callee-saved temporaries for an executed Go fixture.
	// Temporarily pointing g/OS18 at SP is not safe for asynchronous observers,
	// even when the separate source/object proof verifies their restoration.
	words := assembleARM64LLVMWords(t, []string{
		"add x4,x4,x2", "eor x4,x4,x5", "stp x22,x23,[sp,#-16]!",
		"add x22,sp,#0", "add x23,sp,#0", "ldp x22,x23,[sp],#16",
	}, "")
	return fmt.Sprintf(`TEXT rawZeroNumeric(SB),516,$0-24
MOVD in+0(FP),R0
MOVD out+8(FP),R1
MOVD salt+16(FP),R2
WORD $0xa9bf7bfd
WORD $%#08x
WORD $%#08x
WORD $%#08x
MOVD (R0),R4
MOVD $17,R5
WORD $0x94000007
WORD $0x94000006
MOVD R4,(R1)
MOVD RSP,R9
WORD $%#08x
WORD $0xa8c17bfd
WORD $0xd65f03c0
WORD $%#08x
WORD $%#08x
WORD $0xd65f03c0
`, words[2], words[3], words[4], words[5], words[0], words[1])
}

func TestCrossLinuxRuntimeMatrixARM64RawZeroFrameRepeatedNumericHelper(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := arm64RawZeroRepeatedNumericSource(t)
	if err := arm64RawZeroRuntimeRegisterSafety(source); err != nil {
		t.Fatal(err)
	}
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	sig.Name, sig.Args = "rawZeroNumeric", []LLVMType{Ptr, Ptr, I64}
	sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: 16, Type: I64, Index: 2, Field: -1})
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	const goOracle = `package main

import "encoding/binary"

func rawZeroNumeric(*byte, *byte, uint64)
func readGoG() uintptr
func main() {
	var input, output, want [96]byte
	seed := uint64(0x0123456789abcdef)
	for trial := 0; trial < 256; trial++ {
		for _, off := range []int{0, 1, 3, 7, 17} {
			for i := range input {
				seed = seed*6364136223846793005 + 1
				input[i] = byte(seed >> 56)
				output[i] = 0xa5
				want[i] = 0xa5
			}
			if trial < 64 {
				binary.LittleEndian.PutUint64(input[off:], uint64(1)<<trial)
			}
			if trial == 64 {
				binary.LittleEndian.PutUint64(input[off:], ^uint64(0))
			}
			x := binary.LittleEndian.Uint64(input[off:])
			salt := seed
			x = (x + salt) ^ 17
			x = (x + salt) ^ 17
			binary.LittleEndian.PutUint64(want[off:], x)
			snapshot := input
			beforeG := readGoG()
			rawZeroNumeric(&input[off], &output[off], salt)
			afterG := readGoG()
			if beforeG == 0 || beforeG != afterG || input != snapshot || output != want {
				panic("raw repeated helper math/canary/caller/g mismatch")
			}
		}
	}
}
`
	for name, body := range map[string]string{
		"go.mod":  "module rawzeronumericoracle\n\ngo 1.20\n",
		"main.go": goOracle,
		"oracle_arm64.s": strings.Replace(source, "TEXT rawZeroNumeric", "TEXT ·rawZeroNumeric", 1) +
			"\nTEXT ·readGoG(SB),516,$0-8\nMOVD g,R0\nMOVD R0,ret+0(FP)\nRET\n",
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
		t.Fatalf("actual Go repeated raw BL math/LR oracle: %v\n%s", err, output)
	}
	const cOracle = `#include <stdint.h>
#include <string.h>
extern void rawZeroNumeric(const unsigned char *, unsigned char *, uint64_t);
static uint64_t readG(void) {
  uint64_t v;
  __asm__ volatile("mov %0,x28" : "=r"(v));
  return v;
}
static uint64_t readOS18(void) {
  uint64_t v;
  __asm__ volatile("mov %0,x18" : "=r"(v));
  return v;
}
int main(void) {
  unsigned char input[96], output[96], want[96], snapshot[96];
  const unsigned offsets[] = {0, 1, 3, 7, 17};
  uint64_t seed = UINT64_C(0x0123456789abcdef);
  for (unsigned trial = 0; trial < 256; trial++)
    for (unsigned o = 0; o < 5; o++) {
      unsigned off = offsets[o];
      for (unsigned i = 0; i < 96; i++) {
        seed = seed * UINT64_C(6364136223846793005) + 1;
        input[i] = (unsigned char)(seed >> 56);
        output[i] = 0xa5;
        want[i] = 0xa5;
      }
      if (trial < 64) {
        uint64_t v = UINT64_C(1) << trial;
        memcpy(input + off, &v, 8);
      }
      if (trial == 64) {
        uint64_t v = UINT64_MAX;
        memcpy(input + off, &v, 8);
      }
      uint64_t x;
      memcpy(&x, input + off, 8);
      x = (x + seed) ^ 17;
      x = (x + seed) ^ 17;
      memcpy(want + off, &x, 8);
      memcpy(snapshot, input, 96);
      uint64_t beforeG = readG(), beforeOS18 = readOS18();
      rawZeroNumeric(input + off, output + off, seed);
      if (beforeG != readG() || beforeOS18 != readOS18() ||
          memcmp(input, snapshot, 96) || memcmp(output, want, 96))
        return 1;
    }
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "raw_zero_numeric", triple, ir, cOracle, runner)
	t.Log("actual Go raw BL and LLVM22/C: 1280 independent overflow/bit-pattern cases, two executed arithmetic helper calls, dead private GP at typed void return, ordinary R22/R23 spill restoration, unchanged actual Go g and native caller g/OS18 snapshots, full canaries/caller LR")
}
