package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawDoublingMultiplyLongCompleteLLVMMatrix(t *testing.T) {
	var assembly []string
	for _, width := range []struct {
		narrow, wide string
		lanes, bank  int
	}{
		{narrow: "h", wide: "s", lanes: 4, bank: 15},
		{narrow: "s", wide: "d", lanes: 2, bank: 31},
	} {
		for _, op := range []string{"sqdmull", "sqdmlal", "sqdmlsl"} {
			for _, view := range []string{"scalar", "low", "high"} {
				mnemonic := op
				destination, first, second := width.wide+"1", width.narrow+"2", width.narrow+"3"
				if view != "scalar" {
					inputLanes := width.lanes
					if view == "high" {
						mnemonic += "2"
						inputLanes *= 2
					}
					destination = fmt.Sprintf("v1.%d%s", width.lanes, width.wide)
					first = fmt.Sprintf("v2.%d%s", inputLanes, width.narrow)
					second = fmt.Sprintf("v3.%d%s", inputLanes, width.narrow)
				}
				assembly = append(assembly, fmt.Sprintf("%s %s, %s, %s", mnemonic, destination, first, second))
				for lane := 0; lane < 2*width.lanes; lane++ {
					assembly = append(assembly, fmt.Sprintf("%s %s, %s, v%d.%s[%d]",
						mnemonic, destination, first, width.bank, width.narrow, lane))
				}
			}
		}
	}
	words := assembleARM64LLVMWords(t, assembly, "")
	var source strings.Builder
	source.WriteString("TEXT doublingLong(SB),4,$0-0\n")
	for i, word := range words {
		ins := Instr{Op: OpWORD, Raw: fmt.Sprintf("WORD $%#08x", word),
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
			t.Errorf("%s: %v", assembly[i], err)
		}
		fmt.Fprintln(&source, ins.Raw)
	}
	if t.Failed() {
		return
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"doublingLong": {Name: "doublingLong", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"sqdmull", "sqdmlal", "sqdmlsl"} {
				if count := strings.Count(ir, `asm sideeffect "`+op); count != len(words)/3 {
					t.Fatalf("got %d native %s variants, want %d", count, op, len(words)/3)
				}
			}
			compileLLVMToObject(t, llc, triple, "doubling-long.ll", "doubling-long.o", ir)
		})
	}
}

func TestARM64RawDoublingMultiplyLongRejectsNonForms(t *testing.T) {
	for _, word := range []uint32{
		0x1e63d041, // Scalar without Q.
		0x0e23d041, // Byte source.
		0x0ee3d041, // Doubleword source.
		0x2e63d041, // Wrong signedness bit.
		0x0f7fbc41, // Fixed bit in the indexed encoding.
		0x0e63b441, // Adjacent multiply-high instruction.
	} {
		if form, valid := decodeARM64RawDoublingMultiplyLong(word); valid {
			t.Fatalf("accepted non-family word %#08x as %+v", word, form)
		}
	}
	const named = "TEXT named(SB),4,$0-0\nVSQDMULL V3.H4, V2.H4, V1.S4\nRET\n"
	requireARM64GoAssemblerResult(t, named, false)
	file, err := Parse(ArchARM64, named)
	if err != nil {
		return // Source syntax did not acquire a named spelling.
	}
	if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"named": {Name: "named", Ret: Void}}}); err == nil {
		t.Fatal("accepted a mnemonic outside Go's AdvSIMD optab")
	}
}

func TestARM64RawDoublingMultiplyLongNativeQC(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("covered by the required Linux/QEMU runtime counterpart")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64DoublingMultiplyLongRuntime(t, testTargetTriple(runtime.GOOS, runtime.GOARCH), []string{clang}, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawDoublingMultiplyLong(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime owner requires Linux/amd64")
	}
	arm64DoublingMultiplyLongRuntime(t, arm64LinuxGNUTriple,
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64DoublingMultiplyLongRuntime(t *testing.T, triple string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	samples := []string{
		"sqdmull s1, h2, h3",
		"sqdmlsl d1, s2, v31.s[3]",
		"sqdmlal v1.4s, v2.4h, v3.4h",
		"sqdmull2 v1.2d, v2.4s, v3.4s",
		"sqdmlal v1.2d, v2.2s, v31.s[3]",
		"sqdmlsl2 v1.4s, v2.8h, v15.h[7]",
		"sqdmlal v1.4s, v1.4h, v1.4h",
	}
	words := assembleARM64LLVMWords(t, samples, "")
	var source, driver, checks strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	sigs := make(map[string]FuncSig)
	for i, instruction := range samples {
		name := fmt.Sprintf("rawLong%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-16
MOVD input+0(FP), R0
MOVD out+8(FP), R1
MRS FPSR, R10
MSR $0, FPSR
VLD1.P 16(R0), [V1.B16]
VLD1.P 16(R0), [V2.B16]
VLD1 (R0), [V3.B16]
VLD1 (R0), [V15.B16]
VLD1 (R0), [V31.B16]
WORD $%#08x
VST1 [V1.B16], (R1)
MRS FPSR, R11
MSR R10, FPSR
MOVD R11, 16(R1)
RET
`, name, words[i])
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Type: Ptr, Field: -1},
				{Type: Ptr, Offset: 8, Index: 1, Field: -1},
			}}}
		fmt.Fprintf(&driver, "extern void %s(void *, void *);\n", name)
		fmt.Fprintf(&driver, `static int check_%[1]s(unsigned char *in) {
  uint64_t old, status, want[3], got[3];
  __asm__ volatile("mrs %%0, fpsr\nmsr fpsr, xzr\n"
                   "ld1 {v1.16b}, [%%2]\nld1 {v2.16b}, [%%3]\n"
                   "ld1 {v3.16b}, [%%4]\nld1 {v15.16b}, [%%4]\nld1 {v31.16b}, [%%4]\n"
                   "%[2]s\nst1 {v1.16b}, [%%5]\nmrs %%1, fpsr\nmsr fpsr, %%0"
                   : "=&r"(old), "=&r"(status) : "r"(in), "r"(in + 16), "r"(in + 32), "r"(want)
                   : "v1", "v2", "v3", "v15", "v31", "memory");
  want[2] = status;
  %[1]s(in, got);
  if (memcmp(want, got, sizeof(want))) {
    fputs("wrong result or FPSR for %[2]s\n", stderr);
    return 1;
  }
  return 0;
}
`, name, instruction)
		fmt.Fprintf(&checks, "    if (check_%s(input)) return 1;\n", name)
	}
	driver.WriteString(`int main(void) {
  _Alignas(16) unsigned char input[48];
  uint32_t state = 17;
  for (unsigned n = 0; n < 256; ++n) {
    for (unsigned i = 0; i < sizeof(input); ++i) {
      state = state * 1664525 + 1013904223;
      input[i] = state >> 19;
    }
    if (n < 6) {
      unsigned width = n & 1 ? 4 : 2;
      for (unsigned i = 0; i < 16; ++i) {
        if (n < 2) {
          // Saturate the doubled product with two signed minima.
          input[16+i] = input[32+i] = (i % width == width-1 ? 128 : 0);
        } else {
          // A product of 2 fits; adding or subtracting it at the
          // corresponding accumulator limit must still saturate.
          input[16+i] = input[32+i] = (i % width == 0 ? 1 : 0);
          unsigned last = i % (2*width) == 2*width-1;
          input[i] = n < 4 ? (last ? 127 : 255) : (last ? 128 : 0);
        }
      }
    }
`)
	driver.WriteString(checks.String())
	driver.WriteString("  }\n  return 0;\n}\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []int{0, 2} {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_doubling_long_qc", triple, ir, driver.String(), runner, optimization)
	}
}
