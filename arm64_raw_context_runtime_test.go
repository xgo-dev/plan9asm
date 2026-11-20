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

func arm64RawContextMemoryFixture(t *testing.T) (*File, map[string]FuncSig, string, []arm64RawPrivateMemoryCase) {
	t.Helper()
	cases := arm64RawPrivateMemoryCases()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, tc := range cases {
		name := fmt.Sprintf("contextMemory%d", index)
		prep := []string{"ldr x4,[x3]", "ldr x5,[x3,#8]"}
		outputs := []string{"str x9,[x1,#64]"}
		if tc.count == 2 {
			outputs = append(outputs, "str x10,[x1,#72]")
		}
		if tc.floating {
			prep = []string{"ldr q0,[x3]", "ldr q1,[x3,#16]"}
			bank := map[int]string{4: "s", 8: "d", 16: "q"}[tc.width]
			outputs = []string{fmt.Sprintf("str %s2,[x1,#64]", bank)}
			if tc.count == 2 {
				outputs = append(outputs, fmt.Sprintf("str %s3,[x1,#%d]", bank, 64+tc.width))
			}
		}
		lines := append(append([]string(nil), prep...), outputs...)
		lines = append(lines, strings.ReplaceAll(tc.store, "sp", "x0"), strings.ReplaceAll(tc.load, "sp", "x0"))
		words := assembleARM64LLVMWords(t, lines, "")
		var body strings.Builder
		fmt.Fprintf(&body, "TEXT %s(SB),516,$0-16\nMOVD in+0(FP),R3\nMOVD out+8(FP),R1\nWORD $0xa9bc7bfd\n", name)
		for _, word := range words[:len(prep)] {
			fmt.Fprintf(&body, "WORD $%#08x\n", word)
		}
		body.WriteString("MOVD R1,R0\n")
		privateBase := 16
		if strings.HasSuffix(tc.name, "pre_post") {
			body.WriteString("WORD $0x91008000\n") // ADD 32,X0,X0.
			privateBase = 48
		}
		body.WriteString("WORD $0x94000000\n")
		fmt.Fprintf(&body, "WORD $%#08x\n", uint32(0x910003e0)|uint32(privateBase)<<10)
		body.WriteString("WORD $0x94000000\n")
		for _, word := range words[len(prep) : len(prep)+len(outputs)] {
			fmt.Fprintf(&body, "WORD $%#08x\n", word)
		}
		body.WriteString("WORD $0xa8c47bfd\nWORD $0xd65f03c0\nhelper:\n")
		for _, word := range words[len(words)-2:] {
			fmt.Fprintf(&body, "WORD $%#08x\n", word)
		}
		body.WriteString("WORD $0xd65f03c0\n")
		source.WriteString(arm64RawContextResolveCalls(t, body.String()))
		sig := arm64RawZeroFrameSig()
		sig.Name = name
		sigs[name] = sig
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	return file, sigs, source.String(), cases
}

func TestARM64RawContextMemoryFamilyObjects(t *testing.T) {
	file, sigs, _, cases := arm64RawContextMemoryFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "context-memory.ll", "context-memory.o", ir)
	}
	t.Logf("%d same-source mixed external/private helper memory variants, actual Go and five LLVM22 objects", len(cases))
}

func TestCrossLinuxRuntimeMatrixARM64RawContextMemoryFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, sigs, source, cases := arm64RawContextMemoryFixture(t)
	var goDecls, cDecls, goChecks, cChecks strings.Builder
	for index, tc := range cases {
		name := fmt.Sprintf("contextMemory%d", index)
		fmt.Fprintf(&goDecls, "func %s(*byte, *byte)\n", name)
		fmt.Fprintf(&cDecls, "extern void %s(const unsigned char *, unsigned char *);\n", name)
		storeOffset, floating := 16, 0
		if strings.HasSuffix(tc.name, "pre_post") || strings.HasSuffix(tc.name, "post_pre") {
			storeOffset = 0
		} else if strings.HasSuffix(tc.name, "unscaled") {
			storeOffset = 9
		}
		if tc.floating {
			floating = 1
		}
		fmt.Fprintf(&goChecks, "check(%s, %d, %d, %d, %d, %d)\n", name, tc.width, tc.count, tc.signBits, floating, storeOffset)
		fmt.Fprintf(&cChecks, "if (check(%s, %d, %d, %d, %d, %d)) { return 1; }\n", name, tc.width, tc.count, tc.signBits, floating, storeOffset)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module rawcontextmemoryoracle\n\ngo 1.20\n",
		"main.go": arm64RawContextOracleGo + goDecls.String() + "func main() {\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT contextMemory", "TEXT ·contextMemory") +
			"\nTEXT ·readGoG(SB),516,$0-8\nMOVD g,R0\nMOVD R0,ret+0(FP)\nRET\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "main", "-o", filepath.Join(dir, "oracle.o"), filepath.Join(dir, "oracle_arm64.s"))
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local")
	listing, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || !strings.Contains(string(listing), "LEAF|NOFRAME, $0-16") || strings.Contains(string(listing), "MOVD.W\tR30,") {
		t.Fatalf("actual Go raw helper object/prologue: %v\n%s", err, listing)
	}
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	command = exec.CommandContext(ctx, "go", args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go raw mixed-context helper numeric/canary/caller oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "raw_context_memory", triple, ir,
		arm64RawContextOracleC+cDecls.String()+"int main(void) {\n"+cChecks.String()+"return 0;\n}\n", runner)
	t.Logf("actual Go/LLVM22 independent oracles: %d variants x 128 patterns x 5 unaligned offsets; both external and private helper calls executed, full numeric/canaries and caller g/LR", len(cases))
}

const arm64RawContextOracleGo = `package main

import "encoding/binary"

func readGoG() uintptr

func check(fn func(*byte, *byte), width, count, signBits, floating, storeOffset int) {
	var input, output, want [128]byte
	seed := uint64(0x0123456789abcdef)
	for trial := 0; trial < 128; trial++ {
		for _, off := range []int{0, 1, 3, 7, 17} {
			for i := range input {
				seed = seed*6364136223846793005 + 1
				input[i] = byte(seed >> 56)
				output[i], want[i] = 0xa5, 0xa5
			}
			if trial < 64 {
				binary.LittleEndian.PutUint64(input[off:], uint64(1)<<trial)
			}
			if trial == 64 {
				binary.LittleEndian.PutUint64(input[off:], ^uint64(0))
			}
			for item := 0; item < count; item++ {
				inputStep, outputStep := 8, 8
				if floating != 0 {
					inputStep, outputStep = 16, width
				}
				bytes := input[off+item*inputStep : off+item*inputStep+width]
				copy(want[off+storeOffset+item*width:], bytes)
				if floating != 0 {
					copy(want[off+64+item*outputStep:], bytes)
				} else {
					var value uint64
					for b := width-1; b >= 0; b-- {
						value = value<<8 | uint64(bytes[b])
					}
					if signBits != 0 && value&(uint64(1)<<(width*8-1)) != 0 {
						value |= ^uint64(0) << (width*8)
						if signBits == 32 {
							value = uint64(uint32(value))
						}
					}
					binary.LittleEndian.PutUint64(want[off+64+item*outputStep:], value)
				}
			}
			snapshot := input
			before := readGoG()
			fn(&input[off], &output[off])
			if before == 0 || before != readGoG() || input != snapshot || output != want {
				panic("mixed helper numeric/input/output/caller mismatch")
			}
		}
	}
}
`

const arm64RawContextOracleC = `#include <stdint.h>
#include <string.h>

static uint64_t readG(void) {
  uint64_t value;
  __asm__ volatile("mov %0,x28" : "=r"(value));
  return value;
}

static uint64_t readOS18(void) {
  uint64_t value;
  __asm__ volatile("mov %0,x18" : "=r"(value));
  return value;
}

static int check(void (*fn)(const unsigned char *, unsigned char *),
                 unsigned width, unsigned count, unsigned signBits,
                 unsigned floating, unsigned storeOffset) {
  unsigned char input[128], output[128], want[128], snapshot[128];
  const unsigned offsets[] = {0, 1, 3, 7, 17};
  uint64_t seed = UINT64_C(0x0123456789abcdef);
  for (unsigned trial = 0; trial < 128; trial++) {
    for (unsigned o = 0; o < 5; o++) {
      unsigned off = offsets[o];
      for (unsigned i = 0; i < 128; i++) {
        seed = seed * UINT64_C(6364136223846793005) + 1;
        input[i] = (unsigned char)(seed >> 56);
        output[i] = want[i] = 0xa5;
      }
      if (trial <= 64) {
        uint64_t value = trial < 64 ? UINT64_C(1) << trial : UINT64_MAX;
        memcpy(input + off, &value, 8);
      }
      for (unsigned item = 0; item < count; item++) {
        const unsigned char *bytes = input + off + item * (floating ? 16 : 8);
        memcpy(want + off + storeOffset + item * width, bytes, width);
        if (floating) {
          memcpy(want + off + 64 + item * width, bytes, width);
        } else {
          uint64_t value = 0;
          for (unsigned b = 0; b < width; b++) {
            value |= (uint64_t)bytes[b] << (8*b);
          }
          if (signBits && (value & (UINT64_C(1) << (8*width-1)))) {
            value |= UINT64_MAX << (8*width);
            if (signBits == 32) { value = (uint32_t)value; }
          }
          memcpy(want + off + 64 + item * 8, &value, 8);
        }
      }
      memcpy(snapshot, input, sizeof(input));
      uint64_t beforeG = readG(), beforeOS18 = readOS18();
      fn(input + off, output + off);
      if (beforeG != readG() || beforeOS18 != readOS18() ||
          memcmp(input, snapshot, sizeof(input)) || memcmp(output, want, sizeof(output))) {
        return 1;
      }
    }
  }
  return 0;
}
`
