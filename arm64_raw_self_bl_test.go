package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func arm64RawSelfBLFixture() string {
	return `TEXT terminal(SB),516,$0-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xa9bf7bfd
MOVD (R0),R4
CBZ R4,spin
MOVD R4,(R1)
WORD $0xa8c17bfd
WORD $0xd65f03c0
spin:
WORD $0x94000000
WORD $0xd65f03c0
`
}

func TestARM64RawSelfBLTerminalHasNoReturnCertificate(t *testing.T) {
	source := arm64RawSelfBLFixture()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	sig.Name = "terminal"
	c := arm64RawContextLowerer(t, source, sig)
	plan := c.rawZeroContextControlPlan("outer")
	if plan == nil {
		t.Fatal("exact raw self-BL sink lost its independent whole-source proof")
	}
	found := false
	for block, body := range c.blocks {
		if body.name != "spin" {
			continue
		}
		found = true
		if !plan.reachable[block] || len(body.instrs) != 1 {
			t.Fatal("sink does not have the exact single-instruction block")
		}
		point := [2]int{block, 0}
		if plan.before[point] != nil || plan.linkBefore[point] != nil || plan.stackBefore[point] != nil {
			t.Fatal("nonreturning raw loop fabricated a return certificate")
		}
	}
	if !found {
		t.Fatal("sink block not found")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
		if err != nil {
			t.Fatal(err)
		}
		// The source BL must still write its own continuation and branch to
		// itself, not become a return, no-op, native call or unreachable block.
		if !regexp.MustCompile(`(?s)\nbb_spin:[^\n]*\n[^\n]*blockaddress\(@terminal, %bb_anon_5f[^\n]*\n[^\n]*store i64[^\n]*ptr %reg_R30[^\n]*\n\s+br label %bb_spin`).MatchString(ir) {
			t.Fatalf("self-BL LR-write/control semantics lost:\n%s", ir)
		}
		compileLLVMToObject(t, llc, triple, "self-bl.ll", "self-bl.o", ir)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "self.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "self.o"), path)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "00 00 00 94 c0 03 5f d6") {
		t.Fatalf("original Go did not encode the exact unrelocated self BL: %v\n%s", err, output)
	}
	// A last-in-source self BL has only the block splitter's empty PC+4
	// placeholder. It is not an unverified source component or return edge.
	ending := strings.TrimSuffix(source, "WORD $0xd65f03c0\n")
	requireARM64GoAssemblerResult(t, ending, true)
	c = arm64RawContextLowerer(t, ending, sig)
	plan = c.rawZeroContextControlPlan("outer")
	if plan == nil || plan.reachable[len(c.blocks)-1] {
		t.Fatal("synthetic empty fallthrough was fabricated as reachable source")
	}
	endingFile, err := Parse(ArchARM64, ending)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(endingFile, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "self-bl-ending.ll", "self-bl-ending.o", ir)
	}
	// Signed/unsigned expression spellings must encode the same actual BL,
	// rather than being recognized by its spelling or a diagnostic comment.
	for _, word := range []string{"2483027968", "-1811939328", "(0x93ffffff+1)"} {
		changed := strings.Replace(source, "0x94000000", word, 1)
		requireARM64GoAssemblerResult(t, changed, true)
		if arm64RawContextLowerer(t, changed, sig).rawZeroContextControlPlan("outer") == nil {
			t.Fatalf("actual self-BL integer encoding spelling lost proof: %s", word)
		}
	}
}

func arm64RawSelfBLGuardMutations() []struct{ name, old, replacement string } {
	return []struct{ name, old, replacement string }{
		{"ordinary_recursion", "WORD $0x94000000", "BL spin"},
		{"other_target", "WORD $0x94000000", "WORD $0x94000001"},
		{"multiline_helper", "spin:\nWORD $0x94000000", "spin:\nWORD $0xd503201f\nWORD $0x97ffffff"},
		{"changing_sp_loop", "spin:\nWORD $0x94000000", "spin:\nWORD $0xd10043ff\nWORD $0x97ffffff"},
		// SP cannot be a Go MOVD store source. Copy it to a GP first;
		// the independent Go object oracle authenticates the raw BL PC.
		{"escaping_loop", "spin:\nWORD $0x94000000", "spin:\nMOVD RSP,R9\nMOVD R9,(R1)\nWORD $0x97fffffe"},
		{"prefix_escape", "CBZ R4,spin", "MOVD RSP,R9\nMOVD R9,(R1)\nCBZ R4,spin"},
		{"prefix_hidden_escape", "CBZ R4,spin", "MOVD R29,(R1)\nCBZ R4,spin"},
		{"return_lr", "WORD $0xa8c17bfd", "MOVD R1,R30\nWORD $0xa8c117e4"},
		{"return_sp", "WORD $0xa8c17bfd", "WORD $0xa8c27bfd"},
		{"return_g", "MOVD R4,(R1)", "MOVD R4,(R1)\nMOVD $0,g"},
		{"dead_unknown", "spin:\n", "dead:\nWORD $0xffffffff\nWORD $0xd65f03c0\nspin:\n"},
		{"different_sp_join", "CBZ R4,spin", "CBZ R4,left\nSUB $16,RSP\nB spin\nleft:\nB spin"},
	}
}

func TestARM64RawSelfBLSinkCannotBypassWholeSourceGuards(t *testing.T) {
	source := arm64RawSelfBLFixture()
	sig := arm64RawZeroFrameSig()
	sig.Name = "terminal"
	for _, tc := range arm64RawSelfBLGuardMutations() {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(source, tc.old, tc.replacement, 1)
			c := arm64RawContextLowerer(t, changed, sig)
			c.unexposedCallFrame = true
			if c.rawZeroContextControlPlan("outer") != nil {
				t.Fatal("self-BL exemption erased a nonterminal effect or source/return/join failure")
			}
		})
	}
}

func TestARM64ControlGPMoveRejectsFloatingImmediate(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, literal := range []string{"0.0", "1.5", "-1.5"} {
			source := fmt.Sprintf("TEXT floating(SB),516,$0-0\n%s $%s,R30\nRET\n", op, literal)
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !ins.Args[0].ImmIsFloat {
				t.Fatalf("float literal did not exercise typed immediate flag: %+v", ins.Args[0])
			}
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:caller": true})},
				memory: make(map[string]arm64ControlValue),
			}
			if state.transferGPRegisterMove(ins) {
				t.Fatalf("floating operand acquired an integer overwrite witness: %s", ins.Raw)
			}
			state.transfer(ins, ins.Op, false, nil)
			if !arm64ControlHas(arm64ControlRead(state.regs, "R30"), "label:caller") {
				t.Fatalf("fallback washed invalid floating MOV destination provenance: %s", ins.Raw)
			}
		}
	}
}
