package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86MinimumPositionMemoryAndViewsRuntime(t *testing.T) {
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
			for vex, op := range []string{"PHMINPOSUW", "VPHMINPOSUW"} {
				for _, operand := range []string{"(BX)", "X1", "X0"} {
					name := fmt.Sprintf("minpos%d", index)
					index++
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", name)
					source.WriteString("MOVQ old+0(FP),AX\nMOVQ input+8(FP),BX\nMOVQ out+16(FP),DI\n")
					source.WriteString("VMOVUPS (AX),Z0\nVMOVUPS (AX),Z1\n")
					if operand != "(BX)" {
						fmt.Fprintf(&source, "MOVOU (BX),%s\n", operand)
					}
					emitX86GoEncodedTestInstruction(t, &source, op+" "+operand+",X0", raw)
					source.WriteString("VMOVUPS Z0,(DI)\nVMOVUPS Y0,64(DI)\nVMOVUPS X0,96(DI)\nRET\n")
					sigs[name] = FuncSig{
						Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1},
							{Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1},
						}},
					}
					fmt.Fprintf(&declarations, "extern void %s(const void*, const void*, void*);\n", name)
					fmt.Fprintf(&checks, "    if (check(%s, %d)) {\n", name, vex)
					fmt.Fprintf(&checks, "        fprintf(stderr, \"%s failed\\n\");\n        return 1;\n    }\n", name)
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
				x86TestGuardPagesC + declarations.String() + x86MinimumPositionOracleC +
				"\nint main(void) {\n    if (setup_guard()) return 2;\n" +
				checks.String() + "    return free_guard();\n}\n"
			compileAndRunRuntimeTestForTarget(t, llc, clang, "minpos", triple, ir, body, prefix)
		})
	}
}

const x86MinimumPositionOracleC = `
static int check(void (*fn)(const void*, const void*, void*), int vex) {
    const uint16_t values[] = {0, 1, 0x7fff, 0x8000, 0x8001, 0xfffe, 0xffff};
    for (int n = 0; n < 256; n++) {
        uint8_t old[65], storage[17], out[112], want[112] = {0};
        uint8_t *input = storage + 1;
        for (int i = 0; i < 65; i++) old[i] = (uint8_t)(i * 3 + 31);

        uint16_t minimum = 0xffff, position = 0;
        for (int i = 0; i < 8; i++) {
            uint16_t value = n < 8 ? (i == n ? 0 : 0xffff) :
                             values[(n + i * (n % 5)) % 7];
            memcpy(input + i * 2, &value, 2);
            if (value < minimum) {
                minimum = value;
                position = (uint16_t)i;
            }
        }
        memcpy(want, &minimum, 2);
        memcpy(want + 2, &position, 2);
        if (!vex) memcpy(want + 16, old + 1 + 16, 48);
        memcpy(want + 64, want, 32);
        memcpy(want + 96, want, 16);

        for (int edge = 0; edge < 2; edge++) {
            const uint8_t *source = input;
            if (edge) {
                source = guard + page - 16;
                memcpy(guard + page - 16, input, 16);
            }
            memset(out, 0xa5, sizeof(out));
            fn(old + 1, source, out);
            if (memcmp(out, want, sizeof(out))) {
                fprintf(stderr, "vex=%d n=%d edge=%d\n", vex, n, edge);
                return 1;
            }
        }
    }
    return 0;
}
`
