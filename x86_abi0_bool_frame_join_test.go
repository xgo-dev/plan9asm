package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"testing"
)

// Reuse the complete previously supported fixture, including all its inputs,
// direct/aliased stores and same-file caller. No Go assembler/object or runtime
// command runs here; this is the three public APIs' logical translation axis.
func TestX86ABI0Mode32CanonicalBoolExistingWholeFrameThreeAPIs(t *testing.T) {
	const declarations = `func ReadByte(x bool) uint8
func WriteParam(x bool) bool
func WriteResult(x bool) bool
func WriteDirect(x bool) bool
func BoolCallee(x bool) bool
func BoolCaller(x bool) bool
func BoolField(p struct { Pad uint8; Flag bool }) bool
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86BoolFrameSource("386"), declarations, "386", "i386-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("previous complete logical bool frame lost its existing typed input/alias/call role", len(ir), err)
			}
		})
	}
}

func TestX86ABI0Mode32CanonicalBoolTypedInputAndPrivateAlias(t *testing.T) {
	for name, row := range map[string]struct {
		declaration string
		body        string
		args        int
		good        bool
	}{
		"direct-input":              {"func view(x bool) bool", "MOVB x+0(FP),AX\nMOVB AX,ret+4(FP)", 5, true},
		"aggregate-input":           {"func view(p struct{ Pad byte; Flag bool }) bool", "MOVB p_flag+1(FP),AX\nMOVB AX,ret+4(FP)", 5, true},
		"direct-parameter-store":    {"func view(x bool) bool", "MOVB $0,x+0(FP)\nMOVB x+0(FP),AX\nMOVB AX,ret+4(FP)", 5, true},
		"alias-input-store":         {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVB $1,(AX)\nMOVB x+0(FP),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-input-read":          {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVB (AX),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-result-store":        {"func view(x bool) bool", "MOVB x+0(FP),BX\nLEAL ret+4(FP),AX\nMOVB BX,(AX)", 5, true},
		"alias-copy":                {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVL AX,DX\nMOVB (DX),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-affine-copy":         {"func view(x bool) bool", "LEAL x+0(FP),AX\nLEAL 0(AX),DX\nMOVB (DX),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-byte-extension":      {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVBLZX (AX),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-set-input":           {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVL $1,BX\nTESTL BX,BX\nSETNE (AX)\nMOVB x+0(FP),BX\nMOVB BX,ret+4(FP)", 5, true},
		"direct-raw-read-restore":   {"func view(x bool) bool", "MOVB $2,x+0(FP)\nMOVBLZX x+0(FP),AX\nTESTL AX,AX\nSETNE ret+4(FP)", 5, true},
		"alias-raw-read-restore":    {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVB $3,(AX)\nMOVB (AX),BX\nTESTB BX,BX\nSETNE ret+4(FP)", 5, true},
		"numeric-input-is-not-bool": {"func view(x byte) bool", "MOVB x+0(FP),AX\nMOVB AX,ret+4(FP)", 5, false},
		"parameter-raw-overwrite":   {"func view(x bool) bool", "MOVB $2,x+0(FP)\nMOVB x+0(FP),AX\nMOVB AX,ret+4(FP)", 5, false},
		"alias-raw-overwrite":       {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVB $3,(AX)\nMOVB (AX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-partial-copy":        {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVW AX,DX\nMOVB (DX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-outside-slot":        {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVB 1(AX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-affine-escape":       {"func view(x bool) bool", "LEAL x+0(FP),AX\nLEAL 1(AX),DX\nMOVB (DX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-wider-read":          {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVWLZX (AX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-set-unknown-flags":   {"func view(x bool) bool", "LEAL x+0(FP),AX\nSETNE (AX)\nMOVB x+0(FP),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-result-escape":       {"func view() bool", "LEAL ret+0(FP),AX\nMOVL AX,ret+0(FP)", 1, false},
		"alias-all-predecessors":    {"func view(x bool) bool", "MOVL $1,CX\nTESTL CX,CX\nJE other\nLEAL x+0(FP),AX\nJMP joined\nother:\nLEAL x+0(FP),AX\njoined:\nMOVB (AX),BX\nMOVB BX,ret+4(FP)", 5, true},
		"alias-mixed-predecessors":  {"func view(x bool) bool", "MOVL $1,CX\nTESTL CX,CX\nJE other\nLEAL x+0(FP),AX\nJMP joined\nother:\nLEAL ret+4(FP),AX\njoined:\nMOVB (AX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"alias-overwritten":         {"func view(x bool) bool", "LEAL x+0(FP),AX\nMOVL $0,AX\nMOVB (AX),BX\nMOVB BX,ret+4(FP)", 5, false},
		"numeric-input-normalized":  {"func view(x byte) bool", "MOVB x+0(FP),AL\nANDB $1,AL\nMOVB AL,ret+4(FP)", 5, true},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\nRET\n", row.args, row.body), row.declaration+"\n", "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("typed logical bool input/private alias contract differs", row.good, len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolParameterRawBytesRemainPhysical(t *testing.T) {
	logical := regexp.MustCompile(`trunc i8 [^\n]+ to i1\b`)
	for _, raw := range []int{2, 3, 255} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%d/%s", raw, api), func(t *testing.T) {
				body := fmt.Sprintf("TEXT ·view(SB),4,$0-5\nMOVB $%d,x+0(FP)\nMOVB x+0(FP),AL\nTESTB AL,AL\nSETNE ret+4(FP)\nRET\n", raw)
				ir, err := x86ScalarFPBitViewAPI(t, body, "func view(x bool) bool\n", "386", "i386-unknown-linux-gnu", api)
				if err != nil || ir == "" || len(logical.FindAllString(ir, -1)) != 1 {
					t.Fatal("mutable logical bool parameter normalized a physical raw intermediate before RET", err, ir)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolAliasCloneJoinAndBudget(t *testing.T) {
	first := x86ResultState{canonicalFP: []bool{true}, fp: []bool{true}, boolFrameGP: new([16]x86ResultSlotAddress)}
	first.boolFrameGP[0] = x86ResultSlotAddress{start: 0, end: 1, valid: true}
	second := first.clone()
	second.boolFrameGP[0].offset = 1
	if first.boolFrameGP[0].offset != 0 {
		t.Fatal("mutable alias states shared a clone")
	}
	if joined := first.intersect(second); joined.boolFrameGP[0].valid || !joined.fp[0] || !joined.canonicalFP[0] {
		t.Fatal("mixed slot aliases acquired a must-origin or altered independent NUM/canonical facts")
	}
	if joined := first.intersect(x86ResultState{fp: []bool{true}, canonicalFP: []bool{true}}); joined.boolFrameGP[0].valid {
		t.Fatal("an absent alias domain invented a declared-slot address")
	}
	file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\nLEAL ret+0(FP),AX\nMOVB $1,(AX)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	// One FP byte, one independent canonical byte and sixteen slot aliases
	// supplement the complete ordinary state, including native MMX.
	const payload = x86IndependentResultBasePayload + 2 + 16*25
	const limit = (64 << 20) / 8
	for _, room := range []int{3*payload - 1, 3 * payload} {
		fn := file.Funcs[0]
		fn.x86ResultFlowBudget = &x86ResultFlowBudget{bytes: limit - room}
		err := checkX86ScalarFPResultInitialization(fn, x86SDKLiteral386Signature(), "386")
		visits := 0
		if room == 3*payload {
			visits = 3
		}
		if fn.x86ResultFlowBudget.visits != visits || fn.x86ResultFlowBudget.bytes != limit+3*payload-room+8*payload*visits {
			t.Fatal("bool alias source work differs from its exact complete-state charge", fn.x86ResultFlowBudget.bytes)
		}
		if room == 3*payload && err != nil || room != 3*payload && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("logical alias state escaped the shared byte budget", room, err)
		}
	}
}
