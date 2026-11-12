package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const x86NamedHalfOriginalRoundingSourceSHA = "39f24aa8656393c426524904b1e91470673c5b136cca0219bdedeac28e5818f3"
const x86NamedHalfOriginalRoundingCSHA = "0ad91576f61f4be44cfcbe362e2a49e7a7fc119942c8d513ae9d6e45b1851312"

func x86NamedHalfCheckOriginalRoundingC(t *testing.T, source string) {
	t.Helper()
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != x86NamedHalfOriginalRoundingCSHA {
		t.Fatal("original directed-rounding C oracle or sample inventory changed")
	}
}

// This private companion checks only the four fixed-rounding value functions.
// It does not execute their original F16C instructions, observe MXCSR or
// certify native exceptions. Dynamic imm8 controls 4..7 cannot acquire it.
// The entire original initialized program is authenticated before changing
// exactly its four conversion rows to the existing private FP16 math model.
func x86NamedHalfRoundingMathematicalSource(source string) (string, error) {
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != x86NamedHalfOriginalRoundingSourceSHA {
		return "", fmt.Errorf("different original source cannot acquire the fixed-rounding mathematical companion")
	}
	for rounding := 0; rounding < 4; rounding++ {
		original := fmt.Sprintf("VCVTPS2PH $%d, Z1, Y0\n", rounding)
		if strings.Count(source, original) != 1 {
			return "", fmt.Errorf("original fixed-rounding row is not unique: %d", rounding)
		}
		physical := rawFP16Conversion(true, rounding, 0, 0, 1, false, true, false)
		source = strings.Replace(source, original, x86RawDisplacementDirectives(physical), 1)
	}
	return source, nil
}

func x86NamedHalfRoundingOriginalObjects(t *testing.T, source, llc string) {
	t.Helper()
	const triple = "x86_64-unknown-linux-gnu"
	x86LEAActualTargetGoObject(t, "amd64", triple, source)
	var declarations strings.Builder
	for index := 0; index < 4; index++ {
		fmt.Fprintf(&declarations, "func halfRound%d(input,out *[64]byte)\n", index)
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", triple, api)
		if err != nil {
			t.Fatal("complete original initialized directed-rounding source stopped translating", api, err)
		}
		for index := 0; index < 4; index++ {
			x86NamedHalfRequireOriginalControl(t, ir, fmt.Sprint("halfRound", index), index)
		}
		compileLLVMToObject(t, llc, triple, "original-half-rounding.ll", "original-half-rounding.o", ir)
	}
	// Objects above are the original program; execution below is explicitly
	// the separately authenticated private mathematical companion only.
	t.Log("original directed-rounding Go/three-API native objects retained; runtime is private fixed-rounding mathematics, not original F16C or MXCSR execution")
}

func TestX86NamedHalfPrivateRoundingCompanionRetainsOriginalBoundaries(t *testing.T) {
	var source strings.Builder
	for index := 0; index < 4; index++ {
		fmt.Fprintf(&source, "TEXT halfRound%d(SB),4,$0-16\nMOVQ input+0(FP), AX\nMOVQ out+8(FP), SI\nVMOVDQU64 (AX), Z1\nVCVTPS2PH $%d, Z1, Y0\nVMOVDQU64 Z0, (SI)\nRET\n", index, index)
	}
	original := source.String()
	companion, err := x86NamedHalfRoundingMathematicalSource(original)
	if err != nil || strings.Contains(companion, "VCVTPS2PH $") {
		t.Fatal("original four fixed-rounding rows lost their private companion", err)
	}
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, companion), "amd64")
	if err != nil || len(file.Funcs) != 4 {
		t.Fatal("private mathematical bytes lost their independent FP16 model", err)
	}
	for index, fn := range file.Funcs {
		conversions := 0
		for _, ins := range fn.Instrs {
			if !strings.HasPrefix(string(ins.Op), "VCVTPS2PHX.") {
				continue
			}
			want := "VCVTPS2PHX." + []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[index]
			if string(ins.Op) != want || !ins.x86Encoded || len(ins.Args) != 2 ||
				ins.Args[0].Reg != "Z1" || ins.Args[1].Reg != "Y0" {
				t.Fatal("private companion changed fixed rounding, source, destination or width", ins)
			}
			conversions++
		}
		if conversions != 1 {
			t.Fatal("private mathematical companion lost its sole exact conversion", index, conversions)
		}
	}
	for name, changed := range map[string]string{
		"source":      strings.Replace(original, "(AX), Z1", "(BX), Z1", 1),
		"input":       strings.Replace(original, "MOVQ input+0(FP), AX\n", "", 1),
		"destination": strings.Replace(original, "Z1, Y0", "Z1, Y2", 1),
		"dynamic":     strings.Replace(original, "VCVTPS2PH $0", "VCVTPS2PH $4", 1),
		"header":      strings.Replace(original, "$0-16", "$0-24", 1),
		"store":       strings.Replace(original, "VMOVDQU64 Z0, (SI)", "VMOVDQU64 Z2, (SI)", 1),
		"missing":     "TEXT absent(SB),4,$0-0\nVCVTPS2PH $0,Z1,Y0\nRET\n",
	} {
		t.Run(name, func(t *testing.T) {
			if changed == original {
				t.Fatal("private companion negative did not mutate its original source")
			}
			if result, err := x86NamedHalfRoundingMathematicalSource(changed); err == nil || result != "" {
				t.Fatal("another producer acquired private fixed-rounding mathematics", result, err)
			}
		})
	}
}
