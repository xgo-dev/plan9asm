package asmsig

import (
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestRefineTailForwardersEvidenceAndPurity(t *testing.T) {
	for _, tc := range []struct {
		name, body                            string
		knownCaller, knownTarget, frame, want bool
	}{
		{name: "frame", body: "JMP target(SB)", frame: true, want: true},
		{name: "declaration", body: "JMP target(SB)", knownTarget: true, want: true},
		{name: "zero_offset", body: "JMP target+0(SB)", frame: true, want: true},
		{name: "ret_symbol", body: "RET target(SB)", frame: true, want: true},
		{name: "dead_ret", body: "JMP target(SB)\nRET", frame: true, want: true},
		{name: "unknown", body: "JMP target(SB)"},
		{name: "protected", body: "JMP target(SB)", knownCaller: true, frame: true},
		{name: "writes_register", body: "MOVQ $1, AX\nJMP target(SB)", frame: true},
		{name: "call", body: "CALL target(SB)\nRET", frame: true},
		{name: "offset", body: "JMP target+8(SB)", frame: true},
		{name: "indirect", body: "JMP AX", frame: true},
		{name: "conditional", body: "JEQ target(SB)", frame: true},
		{name: "multiple", body: "JMP target(SB)\nJMP other(SB)", frame: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT caller(SB),$0\n"+tc.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			caller := plan9asm.FuncSig{Name: "caller", Ret: plan9asm.I64}
			target := plan9asm.FuncSig{Name: "target", Ret: plan9asm.Void}
			if tc.frame {
				target.Args = []plan9asm.LLVMType{plan9asm.Ptr}
				target.Frame.Params = []plan9asm.FrameSlot{{Type: plan9asm.Ptr, Field: -1}}
			}
			sigs := map[string]plan9asm.FuncSig{"caller": caller, "target": target}
			RefineTailForwarders(file, sigs, func(s string) string { return s }, map[string]bool{"caller": tc.knownCaller, "target": tc.knownTarget})
			want := caller
			if tc.want {
				want = target
				want.Name = "caller"
			}
			if !reflect.DeepEqual(sigs["caller"], want) {
				t.Fatalf("got %#v, want %#v", sigs["caller"], want)
			}
		})
	}
}

func TestRefineTailForwardersUnprovenCycle(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT a(SB),$0\nJMP b(SB)\nTEXT b(SB),$0\nJMP a(SB)\n")
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]plan9asm.FuncSig{"a": {Name: "a", Ret: plan9asm.I64}, "b": {Name: "b", Ret: plan9asm.I32}}
	RefineTailForwarders(file, sigs, func(s string) string { return s }, nil)
	if sigs["a"].Ret != plan9asm.I64 || sigs["b"].Ret != plan9asm.I32 {
		t.Fatal("unproven cycle changed signatures")
	}
}
