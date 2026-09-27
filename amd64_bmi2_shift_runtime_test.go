package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86BMI2ShiftRuntime(t *testing.T) {
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
		t.Skip("execution requires amd64 or Rosetta; five-target objects remain required")
	}

	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range x86BMI2ShiftTestOps {
		bits, kind := 32, 0
		if strings.HasSuffix(op, "Q") {
			bits = 64
		}
		if strings.HasPrefix(op, "SHRX") {
			kind = 1
		} else if strings.HasPrefix(op, "SARX") {
			kind = 2
		}

		for _, raw := range []bool{false, true} {
			for _, memory := range []bool{false, true} {
				for _, destination := range []string{"CX", "AX", "DX"} {
					name := fmt.Sprintf("bmi2shift%d", index)
					index++
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", name)
					source.WriteString("MOVQ count+0(FP),AX\nMOVQ source+8(FP),BX\nMOVQ out+16(FP),DI\n")
					source.WriteString("MOVQ (BX),DX\nMOVQ $-1,CX\nCMPQ AX,AX\nSTC\n")
					input := "DX"
					if memory {
						input = "(BX)"
					}
					line := fmt.Sprintf("%s AX,%s,%s", op, input, destination)
					emitX86GoEncodedTestInstruction(t, &source, line, raw)
					fmt.Fprintf(&source, "MOVQ %s,(DI)\n", destination)
					source.WriteString("SETCS 8(DI)\nSETEQ 9(DI)\nSETPS 10(DI)\nSETMI 11(DI)\nSETOS 12(DI)\nRET\n")

					sigs[name] = FuncSig{
						Name: name,
						Args: []LLVMType{I64, Ptr, Ptr},
						Ret:  Void,
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: I64, Index: 0, Field: -1},
							{Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1},
						}},
					}
					fmt.Fprintf(&declarations, "extern void %s(uint64_t, const void*, void*);\n", name)
					fmt.Fprintf(&checks, "    if (check(%s, %d, %d)) return %d;\n", name, bits, kind, index)
				}
			}
		}
	}
	if index != 72 {
		t.Fatalf("generated %d functions, want 72", index)
	}

	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		declarations.String() + x86BMI2ShiftOracleC + `
static int check(void (*fn)(uint64_t, const void*, void*), int bits, int kind) {
    uint64_t values[] = {0, 1, UINT64_MAX, UINT64_C(0x8000000080000000),
                         UINT64_C(0x7fffffff7fffffff), UINT64_C(0xfedcba9876543210)};
    for (unsigned n = 0; n < 256; n++) {
        uint8_t input[9], out[13] = {0};
        uint64_t value = values[n % 6];
        uint64_t count = n < 128 ? n : UINT64_MAX - n;
        memcpy(input + 1, &value, sizeof(value));

        fn(count, input + 1, out);
        uint64_t got;
        memcpy(&got, out, sizeof(got));
        if (got != shift_reference(value, count, bits, kind) ||
            out[8] != 1 || out[9] != 1 || out[10] != 1 || out[11] || out[12]) {
            fprintf(stderr, "bits=%d kind=%d case=%u\n", bits, kind, n);
            return 1;
        }
    }
    return 0;
}

int main(void) {
` + checks.String() + "    return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "bmi2_shift", triple, ir, mainC, prefix)
}

const x86BMI2ShiftOracleC = `
static uint64_t shift_reference(uint64_t value, uint64_t count, int bits, int kind) {
    uint64_t mask = bits == 64 ? UINT64_MAX : UINT32_MAX;
    unsigned shift = (unsigned)count & (bits - 1);
    value &= mask;
    if (kind == 0) {
        return (value << shift) & mask;
    }

    uint64_t result = value >> shift;
    if (kind == 2 && shift && (value & (UINT64_C(1) << (bits - 1)))) {
        result |= mask ^ (mask >> shift);
    }
    return result;
}
`
