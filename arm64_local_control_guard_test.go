package plan9asm

import (
	"errors"
	"testing"
)

func TestARM64LocalControlRejectsEscapedCodeInKnownCell(t *testing.T) {
	const source = `TEXT escapedCell(SB),$48-0
MOVD $0,24(RSP)
ADR target,R1
MOVD R1,(R0)
MOVD 24(RSP),R2
B (R2)
target:
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
		"escapedCell": {Name: "escapedCell", Ret: Void},
	}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("known cell can alias escaped local code; must fail closed: %v", err)
	}
}

func TestARM64LocalControlRejectsUnprovedCallEffects(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		callee FuncSig
	}{
		"native_register_clobber": {body: `ADR target,R20
MOVD fn+0(FP),R9
CALL R9
B (R20)`},
		"native_register_result": {body: `ADR target,R0
MOVD fn+0(FP),R9
BL (R9)
B (R1)`},
		"native_caller_link": {body: `BL R30
B (R30)`},
		"unknown_direct_clobber": {body: `ADR target,R20
BL external(SB)
B (R20)`},
		"unknown_direct_result": {body: `BL external(SB)
B (R0)`},
		"unknown_direct_frame": {body: `ADR target,R1
MOVD R1,24(RSP)
BL external(SB)
MOVD 24(RSP),R2
B (R2)`},
		"typed_direct_clobber": {body: `ADR target,R20
BL external(SB)
B (R20)`, callee: FuncSig{Name: "external", Ret: Void}},
		"typed_direct_result": {body: `BL external(SB)
B (R0)`, callee: FuncSig{Name: "external", Ret: I64}},
		"integer_frame_address": {body: `ADR target,R1
MOVD R1,24(RSP)
ADD $24,RSP,R0
BL external(SB)
MOVD 24(RSP),R2
B (R2)`, callee: FuncSig{Name: "external", Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: Void}},
		"code_argument_escape": {body: `MOVD $0,24(RSP)
ADR target,R0
BL external(SB)
MOVD (R9),R2
B (R2)`, callee: FuncSig{Name: "external", Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: Void}},
	} {
		t.Run(name, func(t *testing.T) {
			source := "TEXT callEffects(SB),$48-8\n" + tc.body + "\ntarget:\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{"callEffects": {
				Name: "callEffects", Args: []LLVMType{I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
			}}
			if tc.callee.Name != "" {
				sigs["external"] = tc.callee
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: sigs})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved native/callee control effects must fail closed: %v", err)
			}
		})
	}
}
