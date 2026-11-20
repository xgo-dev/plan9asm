package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerSignedIntegerFloatCompleteFamily(t *testing.T) {
	for _, row := range x86SignedIntegerFloatRows("amd64") {
		row = strings.ReplaceAll(strings.Replace(row, "8(BX)", "(DI)", 1), "(BX)(SI*4)", "(DI)")
		body := "VMOVUPS (SI),Z0\nVMOVUPS (SI),Z1\n" + row + "\nVMOVSS X1,(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
			t.Fatalf("%s: %v", row, err)
		}
	}
}

func TestX86GoCallerSignedIntegerFloatByteKnowledge(t *testing.T) {
	for _, row := range x86SignedIntegerFloatRows("amd64") {
		if strings.Contains(row, "(BX)") {
			continue
		}
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		f, _, err := x86SignedIntegerFloatProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for known := uint8(0); ; known++ {
			state := x86SourceStackState{known: map[Reg]uint8{AX: known}, callers: map[Reg]x86CallerPointerValue{}, vectors: map[Reg]uint64{"Z0": 0x5500, "Z1": 0xaaff0000}, masks: map[Reg]bool{}}
			accepted := x86CallerSignedIntegerFloatStep(&ins, f, &state, nil)
			mask := uint8((1 << uint(f.sourceBits/8)) - 1)
			if accepted != (known&mask == mask) {
				t.Fatalf("%s GP knowledge %x: %t", row, known, accepted)
			}
			if accepted {
				low := x86CallerVectorByteMask(int64(f.spec.resultBits / 8))
				want := uint64(0xaaff0000) | low
				if !f.spec.legacy {
					want = ^uint64(0xffff) | low | (0x5500 & (uint64(0xffff) &^ low))
				}
				if state.vectors["Z1"] != want {
					t.Fatalf("%s invented upper byte knowledge: %x want %x", row, state.vectors["Z1"], want)
				}
			}
			if known == 255 {
				break
			}
		}
	}
}

func TestX86GoCallerSignedIntegerFloatUnknownPermissionsRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"pointer bits":              "VCVTSI2SSL DI,X0,X1\nVMOVSS X1,(DX)",
		"stack bits":                "CVTSQ2SS SP,X1\nVMOVSS X1,(DX)",
		"g bits":                    "VCVTSI2SSL R14,X0,X1\nVMOVSS X1,(DX)",
		"undefined GP":              "VCVTSI2SSQ R11,X0,X1\nVMOVSS X1,(DX)",
		"partial GP":                "MOVB $7,R11\nCVTSL2SS R11,X1\nVMOVSS X1,(DX)",
		"source SP":                 "VCVTSI2SSL (SP),X0,X1\nVMOVSS X1,(DX)",
		"unknown memory":            "VCVTSI2SSL (R11),X0,X1\nVMOVSS X1,(DX)",
		"pointer FP":                "VCVTSI2SSL a+0(FP),X0,X1\nVMOVSS X1,(DX)",
		"unknown upper passthrough": "VCVTSI2SSL AX,X0,X1\nVEXTRACTPS $3,X1,AX\nMOVL AX,(DX)",
		"CFG undefined GP":          "CMPQ AX,$0\nJE join\nMOVL $7,R11\njoin:\nVCVTSI2SSL R11,X0,X1\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown permission became success: %v", err)
			}
		})
	}
	// A numerical low result is independent of undefined passthrough bytes.
	for _, op := range []string{"CVTSL2SS", "VCVTSI2SSL"} {
		args := "AX,X1"
		if strings.HasPrefix(op, "V") {
			args = "AX,X0,X1"
		}
		body := fmt.Sprintf("%s %s\nVMOVSS X1,(DX)", op, args)
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
			t.Fatal(err)
		}
	}
}
