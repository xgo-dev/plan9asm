package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

type armConversionStatusCase struct {
	name, body string
	control    uint32
	value      uint64
	status     uint32
	double     bool
}

func armConversionStatusCases() []armConversionStatusCase {
	return []armConversionStatusCase{
		{name: "fraction32", body: "MOVF $1.5,F0\nMOVFW F0,R2", value: 1, status: 0x10},
		{name: "fraction64", body: "MOVD $1.5,F0\nMOVDW F0,R2", value: 1, status: 0x10},
		{name: "overflowSigned", body: "MOVD $2147483648.0,F0\nMOVDW F0,R2", value: 0x7fffffff, status: 1},
		{name: "overflowUnsigned", body: "MOVD $4294967296.0,F0\nMOVDW.U F0,R2", value: 0xffffffff, status: 1},
		{name: "nanSigned", body: "MOVW $0x7fc00000,R2\nMOVW R2,F0\nMOVFW F0,R2", status: 1},
		{name: "negativeUnsigned", body: "MOVF $-1.0,F0\nMOVFW.U F0,R2", status: 1},
		{name: "roundUp", body: "MOVW $16777217,R2\nMOVWF R2,F0\nMOVW F0,R2", control: 1 << 22, value: 0x4b800001, status: 1<<22 | 0x10},
		{name: "roundDown", body: "MOVW $-16777217,R2\nMOVWF R2,F0\nMOVW F0,R2", control: 2 << 22, value: 0xcb800001, status: 2<<22 | 0x10},
		{name: "roundUnsignedDown", body: "MOVW $0xffffffff,R2\nMOVWF.U R2,F0\nMOVW F0,R2", control: 2 << 22, value: 0x4f7fffff, status: 2<<22 | 0x10},
		{name: "wordDoubleSigned", body: "MOVW $2147483647,R2\nMOVWD R2,F0", value: math.Float64bits(2147483647), double: true},
		{name: "wordDoubleUnsigned", body: "MOVW $0xffffffff,R2\nMOVWD.U R2,F0", value: math.Float64bits(4294967295), double: true},
		{name: "deadResult", body: "MOVF $1.5,F0\nMOVFW F0,R2\nMOVW $0,R2", status: 0x10},
	}
}

func armConversionStatusSource() (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, fixture := range armConversionStatusCases() {
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-4
MOVW out+0(FP),R0
MOVD $3.0,F0
MOVD $3.0,F15
WORD $0xeef14a10 // save native FPSCR in R4
MOVW $%d,R3
WORD $0xeee13a10 // install source control and clear cumulative flags
%s
WORD $0xeef13a10 // observe native FPSCR before restoring the caller
WORD $0xeee14a10
`, fixture.name, fixture.control, fixture.body)
		if fixture.double {
			source.WriteString("MOVD F0,0(R0)\n")
		} else {
			source.WriteString("MOVW R2,0(R0)\nMOVW $0,R2\nMOVW R2,4(R0)\n")
		}
		source.WriteString("MOVW R3,8(R0)\nRET\n")
		sigs[fixture.name] = FuncSig{Name: fixture.name, Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}
	}
	return source.String(), sigs
}

func TestARMWordFloatStatusIsNativeAndSurvivesOptimization(t *testing.T) {
	source, sigs := armConversionStatusSource()
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"original", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
		for _, operation := range []string{"s32.f32", "u32.f32", "s32.f64", "u32.f64", "f32.s32", "f32.u32", "f64.s32", "f64.u32"} {
			if !strings.Contains(variant.ir, `asm sideeffect "vcvt.`+operation+` `) {
				t.Errorf("%s omits native side-effecting VCVT %s", variant.name, operation)
			}
		}
		for _, forbidden := range []string{" = fptosi ", " = fptoui ", " = sitofp ", " = uitofp "} {
			if strings.Contains(variant.ir, forbidden) {
				t.Errorf("%s substitutes an ordinary LLVM conversion for native FPSCR: %s", variant.name, forbidden)
			}
		}
		if count := strings.Count(variant.ir, `asm sideeffect "vcvt.`); count != len(armConversionStatusCases()) {
			t.Errorf("%s drops source/dead conversion effects: %d", variant.name, count)
		}
	}
}
