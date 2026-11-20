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

func TestCrossLinuxRuntimeMatrixARM64RawPrivateFrameFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, sigs, source, cases := arm64RawPrivateFamilyFixture(t)
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
	goSource := strings.ReplaceAll(source, "TEXT rawFrame_", "TEXT ·rawFrame_")
	for name, body := range map[string]string{
		"go.mod": "module rawframeoracle\n\ngo 1.20\n",
		"main.go": arm64RawPrivateFrameOracleGo + goDeclarations.String() +
			"func main(){\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": goSource,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Actual Go obj7 prologue/epilogue is part of the RET proof. This is a
	// framed leaf: Go rewrites R29, restores physical SP, and does not reload
	// R30. Therefore the explicit raw LR spill/reload remains mandatory.
	cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "main", "-o", filepath.Join(dir, "oracle.o"), filepath.Join(dir, "oracle_arm64.s"))
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	listing, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil {
		t.Fatalf("actual Go framed raw source object: %v\n%s", err, listing)
	}
	if err := checkARM64RawPrivateFrameGoListing(filepath.Join(dir, "oracle_arm64.s"), goSource, string(listing)); err != nil {
		t.Fatalf("actual Go framed-leaf source/object contract: %v\n%s", err, listing)
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
		t.Fatalf("actual Go raw private-frame caller oracle: %v\n%s", err, output)
	}
	t.Logf("actual Go original raw frame/leaf epilogue: %d variants x 256 patterns x 5 unaligned offsets, full input/output canaries", len(cases))
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	cMain := arm64RawPrivateFrameOracleC + cDeclarations.String() + "int main(void){\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "raw_private_frame_family", triple, ir, cMain, runner)
	t.Logf("LLVM22 typed caller / independent C: same %d memory variants, %d total cases", len(cases), len(cases)*256*5)
}

const arm64RawPrivateFrameOracleGo = `package main

import "encoding/binary"

func check(fn func(*byte, *byte), width, count, signBits, floating int) {
	var input [96]byte
	var output, want [96]byte
	seed := uint32(0x12345678)
	for trial := 0; trial < 256; trial++ {
		for _, offset := range []int{0, 1, 3, 7, 17} {
			for i := range input {
				seed = seed*1664525 + 1013904223
				input[i] = byte(seed >> 24)
				if trial == 0 {
					input[i] = 0
				}
				if trial == 1 {
					input[i] = 255
				}
				if trial >= 2 && trial < 34 {
					input[i] = 0
					if i == offset+(trial-2)/8 {
						input[i] = 1 << uint((trial-2)%8)
					}
				}
			}
			snapshot := input
			for i := range output {
				output[i] = 0xa5
				want[i] = 0xa5
			}
			for i := 0; i < count; i++ {
				if floating != 0 {
					copy(want[offset+i*width:offset+(i+1)*width], input[offset+i*16:offset+i*16+width])
					continue
				}
				var value uint64
				for j := 0; j < width; j++ {
					value |= uint64(input[offset+i*8+j]) << uint(8*j)
				}
				if signBits != 0 && width < 8 && value>>(uint(width*8)-1) != 0 {
					value |= ^uint64(0) << uint(width*8)
				}
				if signBits == 32 {
					value = uint64(uint32(value))
				}
				binary.LittleEndian.PutUint64(want[offset+i*8:], value)
			}
			fn(&input[offset], &output[offset])
			if input != snapshot || output != want {
				println(width, count, signBits, floating, trial, offset)
				panic("Go raw frame/caller/memory/canary mismatch")
			}
		}
	}
}
`

const arm64RawPrivateFrameOracleC = `
#include <stdint.h>
#include <string.h>
#include <stdio.h>
static int check(void (*fn)(const unsigned char *, unsigned char *), unsigned width,
                 unsigned count, unsigned sign_bits, int floating) {
  unsigned char input[96], snapshot[96], output[96], want[96];
  uint32_t seed = UINT32_C(0x12345678);
  const unsigned offsets[] = {0, 1, 3, 7, 17};
  for (unsigned trial = 0; trial < 256; trial++)
    for (unsigned o = 0; o < 5; o++) {
      unsigned offset = offsets[o];
      for (unsigned i = 0; i < 96; i++) {
        seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
        input[i] = (unsigned char)(seed >> 24);
        if (trial == 0)
          input[i] = 0;
        if (trial == 1)
          input[i] = 255;
        if (trial >= 2 && trial < 34)
          input[i] = i == offset + (trial - 2) / 8
                         ? (unsigned char)(1U << ((trial - 2) % 8))
                         : 0;
      }
      memcpy(snapshot, input, 96);
      memset(output, 0xa5, 96);
      memset(want, 0xa5, 96);
      for (unsigned i = 0; i < count; i++) {
        if (floating) {
          memcpy(want + offset + i * width, input + offset + i * 16, width);
          continue;
        }
        uint64_t value = 0;
        for (unsigned j = 0; j < width; j++)
          value |= (uint64_t)input[offset + i * 8 + j] << (8 * j);
        if (sign_bits && width < 8 && (value >> (width * 8 - 1)))
          value |= UINT64_MAX << (width * 8);
        if (sign_bits == 32)
          value = (uint32_t)value;
        for (unsigned j = 0; j < 8; j++)
          want[offset + i * 8 + j] = (unsigned char)(value >> (8 * j));
      }
      fn(input + offset, output + offset);
      if (memcmp(input, snapshot, 96) || memcmp(output, want, 96)) {
        fprintf(stderr,
                "raw frame width/count/sign/FP/trial/offset %u/%u/%u/%d/%u/%u\n", width,
                count, sign_bits, floating, trial, offset);
        return 1;
      }
    }
  return 0;
}
`
