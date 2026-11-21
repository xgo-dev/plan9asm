package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawFloatToIntegerRoundingCompleteBaseFormats(t *testing.T) {
	forms, encodings := arm64SIMDFloatToIntCases(t, true)
	if len(forms) != 50 || len(encodings) != 50 {
		t.Fatalf("packed conversion matrix has %d forms and %d encodings", len(forms), len(encodings))
	}
	var source strings.Builder
	source.WriteString("TEXT rawfcvtroundforms(SB),$0-0\n")
	for index, form := range forms {
		lanes := int(form.register[0] - '0')
		for src := 0; src < 32; src++ {
			for dst := 0; dst < 32; dst++ {
				word := encodings[index] | uint32(src)<<5 | uint32(dst)
				decoded, ok := decodeARM64RawSIMDFloatToInt(word)
				if !ok || decoded.arrangement != (arm64VectorArrangement{elementBits: form.bits, lanes: lanes}) ||
					decoded.unsigned != form.unsigned || decoded.source != src || decoded.destination != dst {
					t.Fatalf("%s %s %#08x decoded as %+v, ok=%v", form.name, form.register, word, decoded, ok)
				}
			}
		}
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodings[index]|30<<5|29)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-freebsd", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawfcvtroundforms": {Name: "rawfcvtroundforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, form := range forms {
				want := fmt.Sprintf("asm sideeffect \"%s $0.%s, $1.%s\"", form.name, form.register, form.register)
				if !strings.Contains(ll, want) {
					t.Fatalf("raw FCVT rounding family omitted %q for %s", want, triple)
				}
			}
			if !strings.Contains(ll, `"target-features"="+fullfp16"`) {
				t.Fatal("packed half conversions omitted +fullfp16")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fcvt-round.ll", "arm64-raw-fcvt-round.o", ll)
		})
	}
}

func TestARM64VectorFloatToIntTargetBoundary(t *testing.T) {
	for _, instruction := range []string{"WORD $0x0e79a8d7", "VFCVTZS V6.S2,V23.S2"} {
		source := "TEXT conversion(SB),4,$0-0\n" + instruction + "\nRET\n"
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := arm64ScalarConversionAPI(t, api, source, "aarch64-unknown-linux-gnu")
			if err != nil || !strings.Contains(ir, "asm sideeffect \"fcvt") {
				t.Fatalf("%s lost %s native lowering: %v", api, instruction, err)
			}
			for _, triple := range []string{"", "aarch64_be-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
				if _, err := arm64ScalarConversionAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s on %q: want target context, got %v", api, instruction, triple, err)
				}
			}
		}
	}
}

func TestARM64RawFloatToIntegerRoundingRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfcvtround(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x4e21a801 // FCVTNS V0.4S, V1.4S
	WORD $0x6e21a802 // FCVTNU V0.4S, V2.4S
	WORD $0x4e21b803 // FCVTMS V0.4S, V3.4S
	WORD $0x6e21b804 // FCVTMU V0.4S, V4.4S
	WORD $0x4e21c805 // FCVTAS V0.4S, V5.4S
	WORD $0x6e21c806 // FCVTAU V0.4S, V6.4S
	WORD $0x4ea1a807 // FCVTPS V0.4S, V7.4S
	WORD $0x6ea1a808 // FCVTPU V0.4S, V8.4S
	WORD $0x4ea1b809 // FCVTZS V0.4S, V9.4S
	WORD $0x6ea1b80a // FCVTZU V0.4S, V10.4S
	VST1 [V1.S4, V2.S4, V3.S4, V4.S4], (R1)
	ADD $64, R1
	VST1 [V5.S4, V6.S4, V7.S4, V8.S4], (R1)
	ADD $64, R1
	VST1 [V9.S4, V10.S4], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawfcvtround": {
			Name: "rawfcvtround", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawfcvtround(const float *, uint32_t *);
int main(void) {
  const float input[4] = {1.5f, 2.5f, -1.5f, -2.5f};
  const int32_t want[40] = {
    2,2,-2,-2, 2,2,0,0,
    1,2,-2,-3, 1,2,0,0,
    2,3,-2,-3, 2,3,0,0,
    2,3,-1,-2, 2,3,0,0,
    1,2,-1,-2, 1,2,0,0,
  };
  uint32_t got[40] = {0};
  rawfcvtround(input, got);
  for (int i = 0; i < 40; i++) {
    if ((int32_t)got[i] != want[i]) return i + 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fcvt_round", triple, ll, mainC, nil)
}
