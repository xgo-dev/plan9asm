package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMScalarCompareNativeEffects(t *testing.T) {
	for _, body := range []string{"CMPF F0", "CMPD F0,F1", "WORD $0xeeb50a40", "WORD $0xeeb50ac0"} {
		source := "TEXT conversion(SB),4,$0-0\nMOVD $1.5,F0\nMOVD $2.5,F1\n" + body + "\nRET\n"
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
			Sigs: map[string]FuncSig{"conversion": {Name: "conversion", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		operation := "vcmpe."
		if body == "WORD $0xeeb50a40" {
			operation = "vcmp."
		}
		if strings.Contains(ir, "fcmp ") || !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, operation) {
			t.Errorf("%s must retain the native signaling/FPSCR effect:\n%s", body, ir)
		}
	}
}

func TestARMScalarCompareNativeTargetBoundary(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, body := range []string{"CMPF F0", "CMPD F0,F1", "WORD $0xeeb50a40", "WORD $0xeeb50bc0"} {
			for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armeb-unknown-linux-gnueabi", "armanything-unknown-linux-gnu"} {
				source := "TEXT conversion(SB),4,$0-0\n" + body + "\nRET\n"
				if err := armWordFloatBoundaryAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s %q needs native FPSCR target: %v", api, body, triple, err)
				}
			}
			for _, invalid := range []string{"CMPF R0", "CMPD.S F0", "WORD $0xffffffff"} {
				for _, dead := range []string{"", "RET\n"} {
					source := "TEXT conversion(SB),4,$0-0\n" + body + "\n" + dead + invalid + "\nRET\n"
					if err := armWordFloatBoundaryAPI(t, api, source, ""); err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s invalid source cannot become target Context: %v", api, err)
					}
				}
			}
		}
	}
}

func TestARMScalarCompareRawDefersAPSRUntilVMRS(t *testing.T) {
	file, err := Parse(ArchARM, "TEXT conversion(SB),4,$0-0\nWORD $0xeeb50ac0\nWORD $0xeef1fa10\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx, output := newARMCtxWithFuncForTest(t, file.Funcs[0], FuncSig{Name: "conversion", Ret: Void}, nil)
	output.Reset()
	compare := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0xeeb50ac0}}}
	if matched, err := ctx.lowerRawWord(compare); !matched || err != nil {
		t.Fatalf("raw compare: matched=%t err=%v", matched, err)
	}
	if ctx.flagsWritten || strings.Contains(output.String(), "store i1") || strings.Contains(output.String(), "vmrs") {
		t.Fatalf("VCMPE changes FPSCR, not APSR: %s", output.String())
	}
	form, ok := decodeARMRawVFPStatusTransfer(0xeef1fa10)
	if !ok {
		t.Fatal("VMRS APSR encoding not decoded")
	}
	if err := ctx.lowerRawVFPStatusTransfer(form); err != nil {
		t.Fatal(err)
	}
	if !ctx.flagsWritten || strings.Count(output.String(), "store i1") != 4 || !strings.Contains(output.String(), "vmrs $0, fpscr") {
		t.Fatalf("VMRS must copy all four native flags: %s", output.String())
	}
}

func TestARMScalarCompareRawPredicateDoesNotInventEntryAPSR(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, body := range []string{"WORD $0x0eb50a40", "WORD $0x1eb50ac0", "WORD $0x0eb50b40", "WORD $0x1eb50bc0"} {
			source := "TEXT conversion(SB),4,$0-0\n" + body + "\nRET\n"
			if err := armWordFloatBoundaryAPI(t, api, source, "armv7-unknown-linux-gnueabihf"); err == nil {
				t.Errorf("%s raw predicate must not use synthetic entry flags: %s", api, body)
			}
		}
	}
}
