package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCrossLinuxRuntimeMatrixARM64RawSelfBLTerminal(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := arm64RawSelfBLFixture()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	sig.Name = "terminal"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module rawselfbloracle\n\ngo 1.20\n",
		"main.go": arm64RawSelfBLOracleGo,
		"oracle_arm64.s": strings.Replace(source, "TEXT terminal", "TEXT ·terminal", 1) +
			"\nTEXT ·readGoG(SB),516,$0-8\nMOVD g,R0\nMOVD R0,ret+0(FP)\nRET\n",
		"oracle.ll": ir,
		"main.c":    arm64RawSelfBLOracleC,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	goPath, llvmPath := filepath.Join(dir, "go-oracle"), filepath.Join(dir, "llvm-oracle")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", goPath, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("build original Go raw self-BL caller: %v\n%s", err, output)
	}
	obj := filepath.Join(dir, "oracle.o")
	command = exec.CommandContext(ctx, llc, "-O0", "-mtriple="+triple, "-filetype=obj", filepath.Join(dir, "oracle.ll"), "-o", obj)
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("LLVM22 self-BL object: %v\n%s", err, output)
	}
	args := append(append([]string(nil), compiler[1:]...), obj, filepath.Join(dir, "main.c"), "-O2", "-o", llvmPath)
	command = exec.CommandContext(ctx, compiler[0], args...)
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("link independent self-BL caller: %v\n%s", err, output)
	}
	goRunner := runner
	if len(runner) != 0 {
		goRunner = []string{runner[0]}
	}
	for _, tc := range []struct {
		name, path string
		runner     []string
	}{
		{name: "original-Go", path: goPath, runner: goRunner},
		{name: "LLVM22-C", path: llvmPath, runner: runner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string(nil), tc.runner...), tc.path)
			command := exec.CommandContext(ctx, args[0], args[1:]...)
			command.Env = append(os.Environ(), "SELF_BL_SINK=0")
			if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
				t.Fatalf("numeric/canary/fixed-register/return oracle: %v\n%s", err, output)
			}
			// Execute the already-built ELF/Mach-O with an owned lifecycle.
			// Cold Go/QEMU startup must not consume any of the full second
			// observed after caller readiness, not an independently observed
			// ASM PC. The original total bound stays.
			output, err := runtimeOracleObserveSink(ctx, func(sinkCtx context.Context) *exec.Cmd {
				command := exec.CommandContext(sinkCtx, args[0], args[1:]...)
				command.Env = append(os.Environ(), "SELF_BL_SINK=1")
				return command
			}, 10*time.Second, time.Second)
			if err != nil {
				t.Fatalf("self-BL returned/trapped or was never entered: %v output=%q", err, output)
			}
		})
	}
	t.Log("original Go/LLVM22: 640 independent nonzero numeric/canary/g/LR cases each; caller-ready zero-input sink remained nonreturning until acknowledged direct-child cancellation")
}

const arm64RawSelfBLOracleGo = `package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func terminal(*byte, *byte)
func readGoG() uintptr

func main() {
	var input, output, want [96]byte
	if os.Getenv("SELF_BL_SINK") == "1" {
		fmt.Println("entered")
		terminal(&input[0], &output[0])
		fmt.Println("returned")
		panic("sink returned")
	}
	seed := uint64(0x0123456789abcdef)
	for trial := 0; trial < 128; trial++ {
		for _, off := range []int{0, 1, 3, 7, 17} {
			for i := range input {
				seed = seed*6364136223846793005 + 1
				input[i] = byte(seed >> 56)
				output[i], want[i] = 0xa5, 0xa5
			}
			value := seed | 1
			binary.LittleEndian.PutUint64(input[off:], value)
			binary.LittleEndian.PutUint64(want[off:], value)
			snapshot := input
			before := readGoG()
			terminal(&input[off], &output[off])
			if before == 0 || before != readGoG() || input != snapshot || output != want {
				panic("normal self-BL sibling numeric/canary/caller mismatch")
			}
		}
	}
}
`

const arm64RawSelfBLOracleC = `#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void terminal(const unsigned char *, unsigned char *);

#ifdef __APPLE__
#define TERMINAL_SYMBOL "_terminal"
#define OS18_CLOBBER
#else
#define TERMINAL_SYMBOL "terminal"
#define OS18_CLOBBER "x18",
#endif

static int checkedTerminal(const unsigned char *input, unsigned char *output) {
  register const unsigned char *arg0 __asm__("x0") = input;
  register unsigned char *arg1 __asm__("x1") = output;
  uint64_t beforeG, beforeOS18, afterG, afterOS18;

  // A single asm boundary prevents the C register allocator from writing
  // x28 between its snapshots (for example to hold the x18 snapshot).
  // The four early-clobber outputs cannot alias the fixed registers or args;
  // ordinary AAPCS64 caller-clobbered GP/FP registers and LR are explicit.
  __asm__ volatile(
      "mov %0,x28\n"
      "mov %1,x18\n"
      "bl " TERMINAL_SYMBOL "\n"
      "mov %2,x28\n"
      "mov %3,x18\n"
      "mov x28,%0\n"
      "mov x18,%1\n"
      : "=&r"(beforeG), "=&r"(beforeOS18), "=&r"(afterG), "=&r"(afterOS18),
        "+r"(arg0), "+r"(arg1)
      :
      : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
        "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
        OS18_CLOBBER "x28", "x30", "v0", "v1", "v2", "v3", "v4", "v5",
        "v6", "v7", "v16", "v17", "v18", "v19", "v20", "v21",
        "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29",
        "v30", "v31", "memory", "cc");

  return beforeG != afterG || beforeOS18 != afterOS18;
}

int main(void) {
  unsigned char input[96] = {0}, output[96], want[96], snapshot[96];
  const char *sink = getenv("SELF_BL_SINK");
  if (sink && strcmp(sink, "1") == 0) {
    puts("entered");
    fflush(stdout);
    terminal(input, output);
    puts("returned");
    fflush(stdout);
    return 99;
  }
  const unsigned offsets[] = {0, 1, 3, 7, 17};
  uint64_t seed = UINT64_C(0x0123456789abcdef);
  for (unsigned trial = 0; trial < 128; trial++) {
    for (unsigned o = 0; o < 5; o++) {
      unsigned off = offsets[o];
      for (unsigned i = 0; i < 96; i++) {
        seed = seed * UINT64_C(6364136223846793005) + 1;
        input[i] = (unsigned char)(seed >> 56);
        output[i] = want[i] = 0xa5;
      }
      uint64_t value = seed | 1;
      memcpy(input + off, &value, 8);
      memcpy(want + off, &value, 8);
      memcpy(snapshot, input, sizeof(input));
      int fixedDiff = checkedTerminal(input + off, output + off);
      int inputDiff = memcmp(input, snapshot, sizeof(input));
      int outputDiff = memcmp(output, want, sizeof(output));
      if (fixedDiff || inputDiff || outputDiff) {
        fprintf(stderr, "trial=%u off=%u fixed=%d input=%d output=%d\n",
                trial, off, fixedDiff, inputDiff, outputDiff);
        return 1;
      }
    }
  }
  return 0;
}
`
