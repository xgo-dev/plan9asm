package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func armIntegerMemoryRuntimeFixture() (string, map[string]FuncSig, string) {
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for _, tc := range armIntegerMemoryCases() {
		// Four nonzero shifts all produce a safe four-byte displacement with
		// their matching input; zero and boundary shifts use the host IR model.
		input := 4
		if strings.HasPrefix(tc.offset, "R") && tc.offset != "R0<<0" && tc.offset != "R0<<1" && tc.offset != "R0>>1" && tc.offset != "R0->1" && tc.offset != "R0@>1" {
			continue
		}
		if tc.offset == "R0<<1" {
			input = 2
		}
		if tc.offset == "R0>>1" || tc.offset == "R0->1" || tc.offset == "R0@>1" {
			input = 8
		}
		name := fmt.Sprintf("mem_runtime_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVW p+0(FP), R1\nMOVW R1, R3\nMOVW index+4(FP), R0\nMOVW $0xfedcba98, R2\n%s\nSUB R3, R1, R4\nMOVW R2, ret+8(FP)\nMOVW R4, ret+12(FP)\nRET\n", name, tc.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I32}, Ret: I64, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		}}
		fmt.Fprintf(&declarations, "extern uint64_t %s(uint8_t *, uint32_t);\n", name)
		delta := 4
		if tc.offset == "0" {
			delta = 0
		}
		if tc.offset == "-4" {
			delta = -4
		}
		if strings.Contains(tc.suffix, ".U") && (strings.HasPrefix(tc.offset, "R") || tc.op == "MOVW" || tc.load && tc.op == "MOVBU" || !tc.load && (tc.op == "MOVB" || tc.op == "MOVBS" || tc.op == "MOVBU")) {
			delta = -delta
		}
		address, after := 32+delta, 0
		if strings.Contains(tc.suffix, ".W") || strings.Contains(tc.suffix, ".P") {
			after = delta
		}
		if strings.Contains(tc.suffix, ".P") {
			address = 32
		}
		width := 1
		if tc.op == "MOVW" {
			width = 4
		}
		if strings.HasPrefix(tc.op, "MOVH") {
			width = 2
		}
		value := uint32(0xfedcba98)
		if tc.load {
			value = 0
			for byteIndex := 0; byteIndex < width; byteIndex++ {
				value |= uint32(byte(3*(address+byteIndex)+129)) << uint(8*byteIndex)
			}
			if tc.op == "MOVB" || tc.op == "MOVBS" {
				value = uint32(int8(value))
			}
			if tc.op == "MOVH" || tc.op == "MOVHS" {
				value = uint32(int16(value))
			}
		}
		want := uint64(uint32(after))<<32 | uint64(value)
		fmt.Fprintf(&checks, "for (int j=0;j<64;j++) data[j]=(uint8_t)(3*j+129);\nif (%s(data+32,%d) != UINT64_C(%d)) { puts(\"%s result\"); return 1; }\n", name, input, want, tc.instruction)
		if !tc.load {
			fmt.Fprintf(&checks, "for (int j=0;j<64;j++) { uint8_t expected=(uint8_t)(3*j+129); if (j>=%d && j<%d) expected=(uint8_t)(UINT32_C(0xfedcba98) >> (8*(j-%d))); if (data[j]!=expected) { puts(\"%s memory\"); return 1; } }\n", address, address+width, address, tc.instruction)
		}
	}
	const conditional = "conditional_memory"
	source.WriteString("TEXT " + conditional + "(SB),$0-8\nMOVW p+0(FP), R1\nCMP R0, R0\nMOVW.NE.P 8(R1), R2\nMOVW R1, ret+4(FP)\nRET\n")
	sigs[conditional] = FuncSig{Name: conditional, Args: []LLVMType{Ptr}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}}}
	declarations.WriteString("extern uint32_t conditional_memory(uint8_t *);\n")
	checks.WriteString("if (conditional_memory((uint8_t *)0) != 0) return 2;\n")
	mainC := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + "int main(void) { uint8_t data[64];\n" + checks.String() + "return 0; }\n"
	return source.String(), sigs, mainC
}

func TestARMIntegerMemoryRuntimeObjects(t *testing.T) {
	source, sigs, _ := armIntegerMemoryRuntimeFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "runtime-memory.ll", "runtime-memory.o", ir)
		})
	}
}

func TestARMIntegerMemoryRuntimeCross(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("actual ARM memory execution is required by the Linux cross-runtime job")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatalf("cross-execution driver requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, name := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required tool %s: %v", name, err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, sigs, mainC := armIntegerMemoryRuntimeFixture()
	t.Logf("executing %d ARM memory functions", len(sigs))
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc"}, "arm_integer_memory", triple, ir, mainC, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
