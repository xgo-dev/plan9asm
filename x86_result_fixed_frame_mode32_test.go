package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

const x86Mode32FrameTestSource = `TEXT ·frame(SB),4,$24-12
MOVL p+0(FP),SI
MOVL SI,16(SP)
MOVL n+4(FP),AX
MOVL AX,0(SP)
ADDL 0(SP),AX
MOVL 16(SP),DI
CMPL SI,16(SP)
JNE done
MOVBLZX (DI),CX
ADDL CX,AX
done:
MOVL AX,ret+8(FP)
RET
`

const x86Mode32FrameTestDeclaration = "func frame(p *byte, n uint32) uint32"

var x86Mode32DerivedFrameSource = strings.NewReplacer(
	"MOVL SI,16(SP)", "LEAL 16(SP),BX\nMOVL SI,(BX)",
	"MOVL AX,0(SP)\nADDL 0(SP),AX", "MOVL SP,BP\nMOVL AX,0(BP)\nADDL 0(BP),AX",
	"16(SP)", "(BX)",
).Replace(x86Mode32FrameTestSource)

func TestX86Mode32FixedFrame(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	mixed := strings.NewReplacer("MOVL SI,16(SP)", "MOVL SI,save-8(SP)",
		"ADDL 0(SP),AX", "ADDL savedNumber-24(SP),AX").Replace(x86Mode32FrameTestSource)
	for _, row := range []struct {
		name   string
		source string
	}{
		{"direct", x86Mode32FrameTestSource},
		{"derived", x86Mode32DerivedFrameSource},
		{"named and physical aliases", mixed},
	} {
		t.Run(row.name, func(t *testing.T) {
			goAssemblerOracleOutput(t, "386", row.source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, x86Mode32FrameTestDeclaration, "386", triple, api)
					if err != nil {
						t.Fatal(err)
					}
					x86NumericNativeAddressObject(t, ir, triple)
				})
			}
		})
	}
}

func TestX86Mode32FixedFrameGuards(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	for _, row := range []struct {
		name, old, replacement string
	}{
		{"undefined slot", "MOVL AX,0(SP)", "NOP"},
		{"conditionally defined slot", "MOVL AX,0(SP)", "CMPL AX,$0\nJEQ load\nMOVL AX,0(SP)\nload:"},
		{"negative physical offset", "ADDL 0(SP),AX", "ADDL -4(SP),AX"},
		{"bare name at frame boundary", "ADDL 0(SP),AX", "ADDL savedNumber(SP),AX"},
		{"named zero outside frame", "ADDL 0(SP),AX", "ADDL savedNumber+0(SP),AX"},
		{"named access crossing frame boundary", "ADDL 0(SP),AX", "ADDL savedNumber-2(SP),AX"},
		{"named access below frame", "ADDL 0(SP),AX", "ADDL savedNumber-25(SP),AX"},
		{"partial out of range", "ADDL 0(SP),AX", "ADDL 22(SP),AX"},
		{"partially overwritten pointer", "MOVL 16(SP),DI", "MOVB $0,17(SP)\nMOVL 16(SP),DI"},
		{"numerical use of pointer", "ADDL 0(SP),AX", "ADDL 16(SP),AX"},
		{"stored private address", "MOVL SI,16(SP)", "LEAL 8(SP),BX\nMOVL BX,(SI)\nMOVL SI,16(SP)"},
		{"escaped private address", "MOVL AX,ret+8(FP)", "MOVL SP,ret+8(FP)"},
		{"out of bounds alias", "ADDL 0(SP),AX", "LEAL 20(SP),BX\nADDL 2(BX),AX"},
		{"indexed private address", "ADDL 0(SP),AX", "LEAL 0(SP),BX\nADDL (BX)(AX*4),AX"},
		{"mutated SP", "ADDL 0(SP),AX", "SUBL $4,SP\nADDL 0(SP),AX\nADDL $4,SP"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := strings.Replace(x86Mode32FrameTestSource, row.old, row.replacement, 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, x86Mode32FrameTestDeclaration, "386", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: unbound private-frame effect: %v", api, err)
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, x86Mode32DerivedFrameSource, x86Mode32FrameTestDeclaration, "386", "x86_64-unknown-linux-gnu", api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: fixed 386 pointers reached a 64-bit target: %v", api, err)
		}
	}
}

func TestX86Mode32FixedFrameTypedCalls(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	const declarations = "func callFrame(x uint32) uint32\nfunc callee(x uint32) uint32\n"
	const source = `TEXT ·callFrame(SB),4,$24-8
MOVL x+0(FP),AX
MOVL AX,0(SP)
MOVL $37,16(SP)
CALL ·callee(SB)
MOVL 4(SP),AX
ADDL 16(SP),AX
MOVL AX,ret+4(FP)
RET

TEXT ·callee(SB),4,$0-8
MOVL x+0(FP),AX
ADDL $3,AX
MOVL AX,ret+4(FP)
RET
`
	goAssemblerOracleOutput(t, "386", source, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			x86NumericNativeAddressObject(t, ir, triple)
		})
	}

	for _, row := range []struct {
		name, old, replacement string
	}{
		{"partially initialized argument", "MOVL AX,0(SP)", "MOVW AX,0(SP)"},
		{"result read before call", "CALL ·callee(SB)\nMOVL 4(SP),AX", "MOVL 4(SP),AX\nCALL ·callee(SB)"},
		{"old argument bytes", "MOVL 4(SP),AX", "MOVL 0(SP),AX"},
		{"old register bytes", "MOVL 4(SP),AX", "NOP"},
		{"old stack alias", "CALL ·callee(SB)\nMOVL 4(SP),AX", "LEAL 4(SP),BX\nCALL ·callee(SB)\nMOVL (BX),AX"},
		{"indirect callee", "CALL ·callee(SB)", "CALL AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				bad := strings.Replace(source, row.old, row.replacement, 1)
				ir, err := x86ScalarFPBitViewAPI(t, bad, declarations, "386", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: unbound CALL effect: %v", api, err)
				}
			}
		})
	}
}
