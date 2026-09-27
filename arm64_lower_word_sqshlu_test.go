package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64SQSHLU(scalar, wide bool, elementBits, shift, source, destination int) uint32 {
	base := uint32(0x2f006400)
	if scalar {
		base = 0x7f006400
	} else if wide {
		base |= 1 << 30
	}
	return base | uint32(elementBits+shift)<<16 | uint32(source)<<5 | uint32(destination)
}

func TestARM64RawSQSHLUDecoderCoversEveryImmediate(t *testing.T) {
	for _, scalar := range []bool{false, true} {
		for _, wide := range []bool{false, true} {
			if scalar && wide {
				continue
			}
			for _, elementBits := range []int{8, 16, 32, 64} {
				if !scalar && !wide && elementBits == 64 {
					continue
				}
				for shift := 0; shift < elementBits; shift++ {
					word := encodeARM64SQSHLU(scalar, wide, elementBits, shift, 31, 30)
					form, ok := decodeARM64RawSQSHLU(word)
					if !ok || form.scalar != scalar || form.arrangement.elementBits != elementBits ||
						form.shift != shift || form.source != 31 || form.destination != 30 {
						t.Fatalf("decode %#08x = %+v, %v", word, form, ok)
					}
				}
			}
		}
	}
	for _, word := range []uint32{
		0x2f006400, // immh=0
		0x2f406400, // D1 is not a vector arrangement
		0x2f007400, // opcode neighbor
		0x7f806400, // outside the seven-bit encoded immediate
	} {
		if _, ok := decodeARM64RawSQSHLU(word); ok {
			t.Fatalf("invalid or adjacent SQSHLU word accepted: %#08x", word)
		}
	}
}

func TestARM64SQSHLUNamedSpellingRemainsOutsideGoOptab(t *testing.T) {
	const source = "TEXT named(SB),$0-0\n\tVSQSHLU $1, V0.B16, V1.B16\n\tRET\n"
	requireARM64GoAssemblerResult(t, source, false)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"named": {Name: "named", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted named VSQSHLU, which Go 1.27 rejects")
	}
}

func TestARM64RawSQSHLURuntimeSemantics(t *testing.T) {
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("runtime execution requires an ARM64 host or the Linux cross-runtime job")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler := []string{findLLVM22Tool("clang")}
	var runner []string
	if crossLinux {
		triple = arm64LinuxGNUTriple
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		for _, required := range []string{compiler[0], runner[0]} {
			if _, err := exec.LookPath(required); err != nil {
				t.Fatalf("required cross-runtime tool %s: %v", required, err)
			}
		}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	var source strings.Builder
	source.WriteString("TEXT sqshluRuntime(SB),$0-16\n")
	source.WriteString("\tMOVD input+0(FP), R0\n\tMOVD output+8(FP), R1\n")
	source.WriteString("\tVLD1 (R0), [V0.B16]\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64SQSHLU(false, true, 8, 2, 0, 1))
	source.WriteString("\tVST1.P [V1.B16], 16(R1)\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64SQSHLU(false, false, 8, 2, 0, 1))
	source.WriteString("\tVST1.P [V1.B16], 16(R1)\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64SQSHLU(true, false, 64, 1, 0, 1))
	source.WriteString("\tVST1 [V1.B16], (R1)\n\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"sqshluRuntime": {
			Name: "sqshluRuntime", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void sqshluRuntime(const int8_t *, uint8_t *);
int main(void) {
  const int8_t input[16] = {-128, -64, -1, 0, 1, 31, 63, -128,
                            -127, -2, 2, 32, 64, 100, 126, 127};
  uint8_t got[48] = {0};
  sqshluRuntime(input, got);
  for (int i = 0; i < 16; i++) {
    int value = (int)input[i] * 4;
    const uint8_t want = value < 0 ? 0 : value > 255 ? 255 : (uint8_t)value;
    if (got[i] != want) return i + 1;
    if (got[16+i] != (i < 8 ? want : 0)) return 17 + i;
  }
  for (int i = 32; i < 40; i++) {
    if (got[i] != 0) return i + 1;
  }
  const int8_t positive[16] = {-128, -64, -1, 0, 1, 31, 63, 127};
  uint8_t positiveGot[48] = {0};
  sqshluRuntime(positive, positiveGot);
  uint64_t scalar = 0;
  for (int i = 0; i < 8; i++) {
    scalar |= (uint64_t)(uint8_t)positive[i] << (8 * i);
  }
  scalar <<= 1;
  for (int i = 0; i < 8; i++) {
    if (positiveGot[32+i] != (uint8_t)(scalar >> (8 * i))) return i + 49;
  }
  for (int i = 40; i < 48; i++) {
    if (positiveGot[i] != 0) return i + 17;
  }
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_sqshlu", triple, ir, mainC, runner)
}

func TestARM64RawSQSHLUCompleteScalarAndVectorForms(t *testing.T) {
	type sqshluForm struct {
		word   uint32
		scalar bool
	}
	var source strings.Builder
	var forms []sqshluForm
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, scalar := range []bool{false, true} {
			for _, wide := range []bool{false, true} {
				if scalar && wide || !scalar && !wide && elementBits == 64 {
					continue
				}
				for _, shift := range []int{0, elementBits - 1} {
					word := encodeARM64SQSHLU(scalar, wide, elementBits, shift, 29, 28)
					decoded, err := decodeARM64RawWordInstruction(Instr{
						Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
					})
					if err != nil || decoded.Op != "VSQSHLU" {
						t.Fatalf("decode SQSHLU scalar=%v wide=%v bits=%d shift=%d word=%#08x: %#v, %v",
							scalar, wide, elementBits, shift, word, decoded, err)
					}
					name := fmt.Sprintf("sqshluForm%d", len(forms))
					fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n\tWORD $%#08x\n\tRET\n", name, word)
					forms = append(forms, sqshluForm{word: word, scalar: scalar})
				}
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-unknown-freebsd",
	} {
		for index, form := range forms {
			t.Run(fmt.Sprintf("%s/form-%02d", triple, index), func(t *testing.T) {
				formSource := fmt.Sprintf("TEXT sqshluForm(SB),$0-0\n\tWORD $%#08x\n\tRET\n", form.word)
				file, err := Parse(ArchARM64, formSource)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{
					Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"sqshluForm": {Name: "sqshluForm", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				wantCalls := 1
				if form.scalar {
					wantCalls = 0
					if !strings.Contains(ir, " = icmp slt i") || !strings.Contains(ir, " = shl i") {
						t.Fatal("scalar SQSHLU is missing signed clamp or shift")
					}
				}
				if got := strings.Count(ir, " = call "); got != wantCalls {
					t.Fatalf("got %d SQSHLU calls, want %d", got, wantCalls)
				}
				compileLLVMToObject(t, llc, triple, "arm64-sqshlu.ll", "arm64-sqshlu.o", ir)
			})
		}
	}
}
