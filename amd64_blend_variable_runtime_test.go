package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86VariableBlendMemoryAndViewsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("execution requires amd64 or Rosetta; native amd64 CI and five-target objects are required")
	}
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			var source, declarations, checks strings.Builder
			sigs := map[string]FuncSig{}
			index := 0
			for _, family := range x86VariableBlendTestFamilies {
				for _, width := range []int{0, 16, 32} {
					for _, memory := range []bool{false, true} {
						for dst := 0; dst < 4; dst++ {
							name := fmt.Sprintf("blend%d", index)
							index++
							reg, move, op, size := "X", "MOVOU", family.legacy, 16
							if width > 0 {
								op, size = family.vector, width
							}
							if width == 32 {
								reg, move = "Y", "VMOVUPS"
							}
							fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
							source.WriteString("MOVQ base+0(FP),AX\nMOVQ source+8(FP),BX\nMOVQ mask+16(FP),CX\nMOVQ out+24(FP),DI\n")
							for r := 0; r < 4; r++ {
								fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", r)
							}
							fmt.Fprintf(&source, "%s (CX),%s0\n%s (BX),%s1\n", move, reg, move, reg)
							operand := reg + "1"
							if memory {
								operand = "(BX)"
							}
							line := fmt.Sprintf("%s %s0,%s,%s%d", op, reg, operand, reg, dst)
							if width > 0 {
								line = fmt.Sprintf("%s %s0,%s,%s2,%s%d", op, reg, operand, reg, reg, dst)
							}
							emitX86GoEncodedTestInstruction(t, &source, line, raw)
							fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\nRET\n", dst, dst, dst)
							sigs[name] = FuncSig{
								Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
								Frame: FrameLayout{Params: []FrameSlot{
									{Offset: 0, Type: Ptr, Index: 0, Field: -1},
									{Offset: 8, Type: Ptr, Index: 1, Field: -1},
									{Offset: 16, Type: Ptr, Index: 2, Field: -1},
									{Offset: 24, Type: Ptr, Index: 3, Field: -1},
								}},
							}
							fmt.Fprintf(&declarations, "extern void %s(const void*, const void*, const void*, void*);\n", name)
							fmt.Fprintf(&checks, "    if (check(%s, %d, %d, %d, %d)) {\n", name, size, family.bits/8, width, dst)
							fmt.Fprintf(&checks, "        fprintf(stderr, \"%s failed\\n\");\n        return 1;\n    }\n", name)
						}
					}
				}
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			body := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
				x86TestGuardPagesC + declarations.String() + x86VariableBlendOracleC +
				"\nint main(void) {\n    if (setup_guard()) return 2;\n" +
				checks.String() + "    return free_guard();\n}\n"
			compileAndRunRuntimeTestForTarget(t, llc, clang, "variable-blend", triple, ir, body, prefix)
		})
	}
}

const x86VariableBlendOracleC = `
static int check(void (*fn)(const void*, const void*, const void*, void*),
                 int size, int lane, int vex, int dst) {
    for (int n = 0; n < 256; n++) {
        uint8_t old[65], storage[33], masks[33], out[112], want[112] = {0};
        uint8_t *input = storage + 1, *mask = masks + 1;
        for (int i = 0; i < 65; i++) old[i] = (uint8_t)(i * 3 + n);
        for (int i = 0; i < size; i++) {
            input[i] = (uint8_t)(i * 7 + n + 83);
            mask[i] = (uint8_t)(n + i * 31);
        }
        const uint8_t *base = old + 1;
        if (!vex && dst == 0) base = mask;
        if (!vex && dst == 1) base = input;
        for (int i = 0; i < size; i += lane) {
            int enabled = mask[i + lane - 1] >> 7;
            memcpy(want + i, (enabled ? input : base) + i, (size_t)lane);
        }
        if (!vex) memcpy(want + 16, old + 1 + 16, 48);
        memcpy(want + 64, want, 32);
        memcpy(want + 96, want, 16);

        for (int edge = 0; edge < 2; edge++) {
            const uint8_t *source = input;
            if (edge) {
                source = guard + page - size;
                memcpy(guard + page - size, input, (size_t)size);
            }
            memset(out, 0xa5, sizeof(out));
            fn(old + 1, source, mask, out);
            if (memcmp(out, want, sizeof(out))) {
                fprintf(stderr, "size=%d lane=%d vex=%d dst=%d n=%d edge=%d\n",
                        size, lane, vex, dst, n, edge);
                return 1;
            }
        }
    }
    return 0;
}
`
