package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawSaturatingShiftCompleteLLVMMatrix(t *testing.T) {
	var instructions []string
	for _, form := range []struct {
		scalar      string
		elementBits int
		vectors     []string
	}{
		{"b", 8, []string{"8b", "16b"}},
		{"h", 16, []string{"4h", "8h"}},
		{"s", 32, []string{"2s", "4s"}},
		{"d", 64, []string{"2d"}},
	} {
		for _, view := range append([]string{""}, form.vectors...) {
			registers := [3]string{form.scalar + "1", form.scalar + "2", form.scalar + "3"}
			if view != "" {
				registers = [3]string{"v1." + view, "v2." + view, "v3." + view}
			}
			for _, op := range []string{"sqshl", "uqshl", "sqrshl", "uqrshl"} {
				instructions = append(instructions, fmt.Sprintf("%s %s, %s, %s", op, registers[0], registers[1], registers[2]))
			}
			for _, op := range []string{"sqshl", "uqshl", "sqshlu"} {
				for _, shift := range []int{0, form.elementBits - 1} {
					instructions = append(instructions, fmt.Sprintf("%s %s, %s, #%d", op, registers[0], registers[1], shift))
				}
			}
		}
	}
	words := assembleARM64LLVMWords(t, instructions, "")
	var source strings.Builder
	source.WriteString("TEXT saturatingShiftRaw(SB),4,$0-0\n")
	for index, word := range words {
		ins := Instr{Op: OpWORD, Raw: fmt.Sprintf("WORD $%#08x", word),
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
			t.Errorf("%s (%#08x): %v", instructions[index], word, err)
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
				Sigs: map[string]FuncSig{"saturatingShiftRaw": {Name: "saturatingShiftRaw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"sqshl", "uqshl", "sqshlu", "sqrshl", "uqrshl"} {
				if !strings.Contains(ir, `asm sideeffect "`+op+" ") {
					t.Fatalf("dead %s must still execute and update FPSR.QC", op)
				}
			}
			compileLLVMToObject(t, llc, triple, "saturating-shifts.ll", "saturating-shifts.o", ir)
		})
	}
}

func TestARM64RawSaturatingShiftNativeQC(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("covered by the required Linux/QEMU runtime counterpart")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64SaturatingShiftRuntime(t, testTargetTriple(runtime.GOOS, runtime.GOARCH), []string{clang}, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawSaturatingShiftQC(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime owner requires Linux/amd64")
	}
	arm64SaturatingShiftRuntime(t, arm64LinuxGNUTriple,
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64SaturatingShiftRuntime(t *testing.T, triple string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	samples := []string{
		"sqshl b1, b2, #7",
		"uqshl h1, h2, #15",
		"sqshlu s1, s2, #31",
		"sqshl d1, d2, d3",
		"uqshl v1.8b, v2.8b, v3.8b",
		"sqrshl v1.4h, v2.4h, v3.4h",
		"uqrshl s1, s2, s3",
		"sqshlu v1.2d, v2.2d, #63",
		"sqshl v1.16b, v2.16b, #7",
	}
	words := assembleARM64LLVMWords(t, samples, "")
	var source, driver, checks strings.Builder
	source.WriteString(`TEXT namedStickyQC(SB),4,$0-8
MRS FPSR, R10
MSR $0, FPSR
VMOVI $127, V2.B16
VSQSHL $7, V2.B16, V1.B16
VMOVI $0, V2.B16
VUQSHL $0, V2.B16, V1.B16
MRS FPSR, R11
MSR R10, FPSR
MOVD R11, ret+0(FP)
RET
`)
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\nextern uint64_t namedStickyQC(void);\n")
	sigs := map[string]FuncSig{
		"namedStickyQC": {Name: "namedStickyQC", Ret: I64,
			Frame: FrameLayout{Results: []FrameSlot{{Type: I64, Field: -1}}}},
	}
	for i, instruction := range samples {
		name := fmt.Sprintf("rawSatShift%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVD input+0(FP), R0\nMOVD counts+8(FP), R1\nMOVD out+16(FP), R2\n", name)
		source.WriteString("MRS FPSR, R10\nMSR $0, FPSR\n")
		source.WriteString("VMOVI $255, V1.B16\nVLD1 (R0), [V2.B16]\nVLD1 (R1), [V3.B16]\n")
		fmt.Fprintf(&source, "WORD $%#08x\n", words[i])
		source.WriteString("VST1 [V1.B16], (R2)\nMRS FPSR, R11\nMSR R10, FPSR\nMOVD R11, 16(R2)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Type: Ptr, Field: -1},
				{Type: Ptr, Offset: 8, Index: 1, Field: -1},
				{Type: Ptr, Offset: 16, Index: 2, Field: -1},
			}}}
		fmt.Fprintf(&driver, "extern void %s(void *, void *, void *);\n", name)
		fmt.Fprintf(&driver, `static int check_%[1]s(void *in, void *counts) {
  uint64_t old, status, want[3], got[3];
  __asm__ volatile("mrs %%0, fpsr\nmsr fpsr, xzr\n"
                   "ld1 {v2.16b}, [%%2]\nld1 {v3.16b}, [%%3]\n"
                   "%[2]s\nst1 {v1.16b}, [%%4]\nmrs %%1, fpsr\nmsr fpsr, %%0"
                   : "=&r"(old), "=&r"(status) : "r"(in), "r"(counts), "r"(want)
                   : "v1", "v2", "v3", "memory");
  want[2] = status;
  %[1]s(in, counts, got);
  if (memcmp(want, got, sizeof(want))) {
    fputs("wrong result or FPSR for %[2]s\n", stderr);
    return 1;
  }
  return 0;
}
`, name, instruction)
		fmt.Fprintf(&checks, "    if (check_%s(input, counts)) return 1;\n", name)
	}
	driver.WriteString(`int main(void) {
  if (namedStickyQC() != (1u << 27)) {
    fputs("dead named saturation lost the sticky QC bit\n", stderr);
    return 1;
  }
  unsigned char input[16], counts[16];
  for (unsigned i = 0; i < 256; ++i) {
    for (unsigned j = 0; j < sizeof(input); ++j) {
      input[j] = i * 21 + j * 9;
      counts[j] = i + j * 7;
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
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_saturating_shift_qc", triple, ir, driver.String(), runner, optimization)
	}
}
