package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The byte reference uses the source spelling's mathematical ratio, not a
// production spec or emitted instruction. Wider stores observe every alias.
const x86ZeroExtendByteOracle = `
static int checkExtend(
    void (*fn)(uint8_t *, const uint8_t *, const uint8_t *, uint64_t),
    const char *name, unsigned width, unsigned input, unsigned output,
    int mode, int legacy, int alias, int memory
) {
    const uint64_t masks[] = {0, 1, UINT64_C(0x55aa55aa55aa55aa), UINT64_MAX};
    for (unsigned round = 0; round < 4; round++) {
        for (unsigned m = 0; m < 4; m++) {
            uint8_t aStorage[96], bStorage[96], result[74];
            uint8_t *a = aStorage + 1, *b = bStorage + 3;
            memset(aStorage, 0xa7, sizeof(aStorage));
            memset(bStorage, 0xb9, sizeof(bStorage));
            memset(result, 0xc3, sizeof(result));
            for (unsigned i = 0; i < 64; i++) {
                a[i] = (uint8_t)(i * 19 + round * 83 + 129);
                b[i] = (uint8_t)(i * 31 + round * 59 + 13);
            }
            uint32_t saved, before = 0x1f80 | (round << 13) | round, after;
            __asm__ volatile("stmxcsr %0" : "=m"(saved));
            __asm__ volatile("ldmxcsr %0" : : "m"(before));
            fn(result + 1, a, b, masks[m]);
            __asm__ volatile("stmxcsr %0" : "=m"(after));
            __asm__ volatile("ldmxcsr %0" : : "m"(saved));
            if (after != before || result[0] != 0xc3 || result[73] != 0xc3 ||
                result[65] != 1 || result[66] != 0) {
                fprintf(stderr, "%s CSR/flags/canary failure\n", name);
                return 1;
            }
            const uint8_t *old = alias ? a : b;
            for (unsigned i = 0; i < 64; i++) {
                const unsigned part = i % output;
                const unsigned source = i / output * input + part;
                const int active = mode == 0 || ((masks[m] >> (i / output)) & 1);
                uint8_t want;
                if (i >= width) {
                    want = legacy ? old[i] : 0;
                } else if (!active) {
                    want = mode == 2 ? 0 : old[i];
                } else {
                    want = part < input ? a[source] : 0;
                }
                if (result[i + 1] != want || a[i] != (uint8_t)(i * 19 + round * 83 + 129) ||
                    b[i] != (uint8_t)(i * 31 + round * 59 + 13)) {
                    fprintf(stderr, "%s byte=%u got=%x want=%x\n", name, i, result[i + 1], want);
                    return 1;
                }
            }
            for (unsigned i = 0; i < 96; i++) {
                if ((i < 1 || i >= 65) && aStorage[i] != 0xa7) return 1;
                if ((i < 3 || i >= 67) && bStorage[i] != 0xb9) return 1;
            }
        }
    }
    if (memory) {
        uint8_t b[64], result[74];
        memset(b, 0x59, sizeof(b));
        memset(result, 0xc3, sizeof(result));
        if (mode != 0) {
            // Irrelevant high mask bits cannot access an entirely inactive NULL.
            fn(result + 1, NULL, b, UINT64_C(1) << 63);
            for (unsigned i = 0; i < 64; i++) {
                uint8_t want = i < width && mode == 1 ? 0x59 : 0;
                if (result[i + 1] != want) return 1;
            }
            if (result[0] != 0xc3 || result[73] != 0xc3 || result[65] != 1 || result[66] != 0) return 1;
        }
        if (setup_guard()) return 1;
        // An unmasked source uses its shrinking native tuple width, not a
        // complete X/Y allocation. A masked source needs one active element.
        unsigned sourceBytes = mode == 0 ? width * input / output : input;
        uint8_t *last = guard + page - sourceBytes;
        for (unsigned i = 0; i < sourceBytes; i++) ((volatile uint8_t *)last)[i] = (uint8_t)(0xd0 + i);
        fn(result + 1, last, b, 1);
        int failed = result[0] != 0xc3 || result[73] != 0xc3 || result[65] != 1 || result[66] != 0;
        for (unsigned i = 0; i < 64; i++) {
            unsigned part = i % output;
            int active = mode == 0 || i < output;
            uint8_t want = i >= width ? (legacy ? 0x59 : 0) :
                           active ? (part < input ? (uint8_t)(0xd0 + i / output * input + part) : 0) :
                           mode == 1 ? 0x59 : 0;
            if (result[i + 1] != want || b[i] != 0x59) failed = 1;
        }
        if (free_guard()) return 1;
        if (failed) return 1;
    }
    return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86PackedZeroExtendCompleteBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, vector := range []bool{false, true} {
			for _, width := range []int{16, 32, 64} {
				if !vector && width != 16 {
					continue
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				sourceBank := "X"
				if width*ratio.input/ratio.output > 16 {
					sourceBank = "Y"
				}
				for _, memory := range []bool{false, true} {
					for mode := 0; mode < 3; mode++ {
						if !vector && mode != 0 {
							continue
						}
						for _, destination := range []int{0, 1} {
							if memory && destination == 0 {
								continue // Memory has no register-source alias.
							}
							name := fmt.Sprintf("extend%d", count)
							count++
							opcode := "PMOVZX" + ratio.suffix
							if vector {
								opcode = "V" + opcode
							}
							input, mask := sourceBank+"0", ""
							if memory {
								input = "(BX)"
							}
							if mode != 0 {
								mask = "K1,"
								if mode == 2 {
									opcode += ".Z"
								}
							}
							fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (CX),Z1\n", name)
							if !memory {
								assembly.WriteString("VMOVUPS (BX),Z0\n")
							}
							fmt.Fprintf(&assembly, "KMOVQ DX,K1\nCMPQ AX,AX\nSTC\n%s %s,%s%s%d\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", opcode, input, mask, bank, destination, destination)
							sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
								{Offset: 0, Type: Ptr, Index: 0, Field: -1},
								{Offset: 8, Type: Ptr, Index: 1, Field: -1},
								{Offset: 16, Type: Ptr, Index: 2, Field: -1},
								{Offset: 24, Type: I64, Index: 3, Field: -1},
							}}}
							fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
							fmt.Fprintf(&checks, "    if (checkExtend(%s,\"%s\",%d,%d,%d,%d,%d,%d,%d)) return 1;\n", name, name, width, ratio.input, ratio.output, mode, x86FloatAddSubBoolInt(!vector), x86FloatAddSubBoolInt(destination == 0), x86FloatAddSubBoolInt(memory))
						}
					}
				}
			}
		}
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		declarations.String() + x86TestGuardPagesC + x86ZeroExtendByteOracle +
		"\nint main(void) {\n" + checks.String() + "    return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "zero-extend-bytes", triple, ir, oracle, prefix)
	t.Logf("%d ratio/width/register-memory/mask/self-alias programs, 16 complete-byte flags/MXCSR/canary inputs each; inactive NULL and page-boundary reads", count)
}

func TestCrossLinuxRuntimeMatrixX86PackedZeroExtendOriginalGoBytes(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package oracle\n")
	checks.WriteString(`package oracle
import "testing"
func TestOriginalGoUnsignedBits(t *testing.T) {
    for round := 0; round < 4; round++ {
        var input, old [64]byte
        for i := range input {
            input[i] = byte(i*19 + round*83 + 129)
            old[i] = byte(i*31 + round*59 + 13)
        }
`)
	count := 0
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, memory := range []bool{false, true} {
			for _, alias := range []bool{false, true} {
				if memory && alias {
					continue
				}
				name := fmt.Sprintf("original%d", count)
				count++
				fmt.Fprintf(&declarations, "func %s(a,b,out *byte)\n", name)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),CX\nMOVOU (BX),X1\n", name)
				source, destination := "(AX)", "X1"
				if !memory {
					assembly.WriteString("MOVOU (AX),X0\n")
					source = "X0"
					if alias {
						destination = "X0"
					}
				}
				fmt.Fprintf(&assembly, "CMPQ AX,AX\nSTC\nPMOVZX%s %s,%s\nMOVOU %s,(CX)\nSETCS 16(CX)\nSETNE 17(CX)\nRET\n", ratio.suffix, source, destination, destination)
				fmt.Fprintf(&checks, `
        {
            var result [20]byte
            for i := range result { result[i] = 0xc3 }
            %[1]s(&input[0], &old[0], &result[1])
            if result[0] != 0xc3 || result[19] != 0xc3 || result[17] != 1 || result[18] != 0 {
                t.Fatalf("%[1]s flags/canary failure: %%x", result)
            }
            for i := 0; i < 16; i++ {
                want := byte(0)
                if i%%%[2]d < %[3]d { want = input[i/%[2]d*%[3]d+i%%%[2]d] }
                if result[i+1] != want { t.Fatalf("%[1]s byte %%d got %%x want %%x", i, result[i+1], want) }
            }
        }
`, name, ratio.output, ratio.input)
			}
		}
	}
	checks.WriteString("    }\n}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(),
		"value_amd64.s": assembly.String(), "value_test.go": checks.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=1", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go unsigned byte oracle: %v\n%s", err, output)
	}
	t.Logf("%d original legacy SSE4.1 register/memory/self-alias functions, 4 complete-byte/flags/canary inputs each; not native VEX/EVEX execution", count)
}

func TestCrossLinuxRuntimeMatrixX86PackedZeroExtendIndependentFPBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, width := range []int{16, 32, 64} {
			for _, legacy := range []bool{false, true} {
				if legacy && width != 16 {
					continue
				}
				name := fmt.Sprintf("fpExtend%d", count)
				count++
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				opcode := "VPMOVZX" + ratio.suffix
				if legacy {
					opcode = "PMOVZX" + ratio.suffix
				}
				var cArgs, cInputs []string
				sig := FuncSig{Name: name, Ret: Void}
				for i := 0; i < 32; i++ {
					cArgs = append(cArgs, "uint8_t")
					cInputs = append(cInputs, fmt.Sprintf("input[%d]", i))
					sig.Args = append(sig.Args, I8)
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i), Type: I8, Index: i, Field: -1})
				}
				sig.Args = append(sig.Args, Ptr)
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: 32, Type: Ptr, Index: 32, Field: -1})
				sigs[name] = sig
				fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-40\nMOVQ out+32(FP),AX\nMOVL $89,BX\nMOVD BX,X1\nVPBROADCASTB X1,Z1\n%s a+0(FP),%s1\nVMOVUPS Z1,(AX)\nRET\n", name, opcode, bank)
				fmt.Fprintf(&declarations, "extern void %s(%s, uint8_t *);\n", name, strings.Join(cArgs, ", "))
				fmt.Fprintf(&checks, "    memset(result, 0xc3, sizeof(result));\n    %s(%s, result + 1);\n", name, strings.Join(cInputs, ", "))
				fmt.Fprintf(&checks, `    for (unsigned i = 0; i < 64; i++) {
        unsigned part = i %% %d;
        uint8_t want = i >= %d ? %d : part < %d ? input[i / %d * %d + part] : 0;
        if (result[i + 1] != want) {
            fprintf(stderr, "%s independent FP byte %%u: %%x != %%x\n", i, result[i + 1], want);
            return 1;
        }
    }
    if (result[0] != 0xc3 || result[65] != 0xc3) return 1;
`, ratio.output, width, map[bool]int{false: 0, true: 89}[legacy], ratio.input, ratio.output, ratio.input, name)
			}
		}
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + `
int main(void) {
    for (unsigned round = 0; round < 4; round++) {
        uint8_t input[32], result[66];
        for (unsigned i = 0; i < 32; i++) input[i] = (uint8_t)(round * 83 + i * 19 + 129);
` + checks.String() + "    }\n    return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "zero-extend-fp-bytes", triple, ir, oracle, prefix)
	t.Logf("%d widening programs, 32 independently passed byte fields, 4 full 64-byte alias/canary inputs each", count)
}
