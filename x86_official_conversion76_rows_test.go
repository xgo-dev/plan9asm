package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RemainingConversionPreflightSource(t *testing.T) (string, string) {
	t.Helper()
	instructions := strings.Split(strings.TrimSpace(`
VCVTPD2PS Z16,Y18
VCVTPD2PSX X16,X18
VCVTPD2PSY Y16,X18
VCVTPS2PD Y16,Z18
VCVTPH2PS Y16,Z18
VCVTPS2PH $7,Z16,Y18
VCVTSD2SS X16,X17,X18
VCVTSS2SD X16,X17,X18
VCVTSD2SI X16,CX
VCVTSD2SIQ X16,CX
VCVTSS2SI X16,CX
VCVTSS2SIQ X16,CX
VCVTTSD2SI X16,CX
VCVTTSD2SIQ X16,CX
VCVTTSS2SI X16,CX
VCVTTSS2SIQ X16,CX
VCVTSD2USIL X16,CX
VCVTSD2USIQ X16,CX
VCVTSS2USIL X16,CX
VCVTSS2USIQ X16,CX
VCVTTSD2USIL X16,CX
VCVTTSD2USIQ X16,CX
VCVTTSS2USIL X16,CX
VCVTTSS2USIQ X16,CX
VCVTSI2SDL CX,X17,X18
VCVTSI2SDQ CX,X17,X18
VCVTSI2SSL CX,X17,X18
VCVTSI2SSQ CX,X17,X18
VCVTUSI2SDL CX,X17,X18
VCVTUSI2SDQ CX,X17,X18
VCVTUSI2SSL CX,X17,X18
VCVTUSI2SSQ CX,X17,X18
`), "\n")
	if len(instructions) != 32 {
		t.Fatal("complete initialized conversion namespace changed", len(instructions))
	}
	var source, declarations strings.Builder
	for index, instruction := range instructions {
		name := fmt.Sprint("ConversionProbe", index)
		fields := strings.Fields(instruction)
		if len(fields) != 2 {
			t.Fatal("preflight source is not one complete ordinary instruction", instruction)
		}
		operands := strings.Split(fields[1], ",")
		first := operands[0]
		if strings.HasPrefix(first, "$") {
			first = operands[1]
		}
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b *[64]byte,value uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\n", name)
		if first == "CX" {
			source.WriteString("MOVQ value+24(FP),CX\n")
		} else {
			source.WriteString("MOVQ a+8(FP),AX\nVMOVUPS (AX),Z16\n")
		}
		if len(operands) == 3 && operands[1] == "X17" {
			source.WriteString("MOVQ b+16(FP),BX\nVMOVUPS (BX),Z17\n")
		}
		// Only real source and upper-copy inputs are seeded. An unmasked
		// conversion must not require an invented old GP/vector destination.
		source.WriteString("STC\n" + instruction + "\n")
		if operands[len(operands)-1] == "CX" {
			source.WriteString("MOVQ CX,0(DI)\n")
		} else {
			source.WriteString("VMOVUPS Z18,0(DI)\n")
		}
		source.WriteString("SETCS 64(DI)\nSTMXCSR 68(DI)\nRET\n")
	}
	return source.String(), declarations.String()
}

func TestX86RemainingFPConversionInitializedProducerThreeAPIObjects(t *testing.T) {
	source, declarations := x86RemainingConversionPreflightSource(t)
	const triple = "x86_64-unknown-linux-gnu"
	x86LEAActualTargetGoObject(t, "amd64", triple, source)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized input-kind/result-kind producer did not reach its public API", api, err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, ir, level)
			}
		})
	}
}

func TestX86RemainingFPConversionHalfTerminalKeepsPrefixMemoryObligations(t *testing.T) {
	for _, result := range []bool{false, true} {
		frame, returns := 0, ""
		if result {
			frame, returns = 8, " uint64"
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			instruction := fmt.Sprintf("VCVTPS2PH.Z $7,%s16,K1,(AX)", bank)
			base := fmt.Sprintf("TEXT ·HalfTerminal(SB),4,$0-%d\n%s\nRET\n", frame, instruction)
			declaration := "func HalfTerminal()" + returns + "\n"
			goAssemblerOracleOutput(t, "amd64", base, "", true)
			prefixes := []string{"MOVQ (AX),CX\n", "MOVQ $1,CX\nMOVQ CX,(AX)\n"}
			for _, prefix := range prefixes {
				candidate := strings.Replace(base, instruction, prefix+instruction, 1)
				goAssemblerOracleOutput(t, "amd64", candidate, "", true)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("result=%t/%s/%s", result, bank, api), func(t *testing.T) {
					const triple = "x86_64-unknown-linux-gnu"
					ir, err := x86ScalarFPBitViewAPI(t, base, declaration, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("valid terminal source must pass before its permission controls", err)
					}
					if _, err := x86OfficialMoveFaultBody(ir, "HalfTerminal"); err != nil {
						t.Fatal("terminal half store read an input or continued", err)
					}
					for index, prefix := range prefixes {
						t.Run([]string{"read", "known-data-store"}[index], func(t *testing.T) {
							candidate := strings.Replace(base, instruction, prefix+instruction, 1)
							text, err := x86ScalarFPBitViewAPI(t, candidate, declaration, "amd64", triple, api)
							if text != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("terminal half opcode authorized an earlier unknown address", api, err)
							}
						})
					}
				})
			}
		}
	}
}
