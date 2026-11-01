package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64ControlMemoryWidthsPreserveAdjacentCallerCells(t *testing.T) {
	for _, tc := range []struct {
		store string
		width int64
	}{
		{"MOVB R4", 1}, {"MOVBU R4", 1}, {"MOVH R4", 2}, {"MOVHU R4", 2},
		{"MOVW R4", 4}, {"MOVWU R4", 4}, {"MOVD R4", 8},
		{"FMOVS F0", 4}, {"FMOVD F0", 8}, {"FMOVQ F0", 16},
		{"STPW (R4,R5)", 8}, {"STP (R4,R5)", 16},
		{"FSTPS (F0,F1)", 8}, {"FSTPD (F0,F1)", 16}, {"FSTPQ (F0,F1)", 32},
	} {
		t.Run(tc.store, func(t *testing.T) {
			for _, offset := range []int64{-tc.width, 8} {
				source := fmt.Sprintf("TEXT width(SB),$0-0\n%s,%d(RSP)\nRET\n", tc.store, offset)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				state := &arm64ControlState{
					regs: map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
					memory: map[string]arm64ControlValue{
						"sp:0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true}),
					},
				}
				ins := file.Funcs[0].Instrs[1]
				state.transfer(ins, ins.Op, false, nil)
				if !arm64ControlEqual(state.memory["sp:0"], arm64ControlFromMap(map[string]bool{"label:entry_lr": true})) {
					t.Fatalf("adjacent %d-byte store at %d corrupted saved caller: %v", tc.width, offset, state.memory)
				}
			}
		})
	}
}

func TestARM64ControlMemoryLiteralZeroAliasWidths(t *testing.T) {
	for _, tc := range []struct {
		op    string
		width int64
	}{
		{"MOVB", 1}, {"MOVBU", 1}, {"MOVH", 2}, {"MOVHU", 2},
		{"MOVW", 4}, {"MOVWU", 4}, {"MOVD", 8},
	} {
		source := fmt.Sprintf("TEXT zero(SB),$0-0\n%s $0,%d(RSP)\nRET\n", tc.op, -tc.width)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{
			regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
			memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
		}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, ins.Op, false, nil)
		if !arm64ControlEqual(state.memory["sp:0"], arm64ControlFromMap(map[string]bool{"label:entry_lr": true})) {
			t.Errorf("Go literal-zero alias used unknown-width store: %s: %v", tc.op, state.memory)
		}
	}
}

func TestARM64ControlMemoryPartialLoadsAndUnknownStoresStayClosed(t *testing.T) {
	for _, text := range []string{
		"MOVB (RSP),R4", "MOVBU (RSP),R4", "MOVH 1(RSP),R4", "MOVHU (RSP),R4",
		"MOVW (RSP),R4", "MOVWU (RSP),R4", "LDPW (RSP),(R4,R5)", "LDPSW (RSP),(R4,R5)",
		"FMOVS (RSP),F0", "FMOVD (RSP),F0", "FMOVQ (RSP),F0",
		"FLDPS (RSP),(F0,F1)", "FLDPD (RSP),(F0,F1)", "FLDPQ (RSP),(F0,F1)",
	} {
		file, err := Parse(ArchARM64, "TEXT partial(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{
			regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
			memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
		}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, ins.Op, false, nil)
		dst := ins.Args[1].Reg
		if dst == "" {
			dst = ins.Args[1].RegList[0]
		}
		value := arm64ControlRead(state.regs, dst)
		if !arm64ControlHas(value, "code-derived:") || !arm64ControlHas(value, "") {
			t.Fatalf("partial/floating load restored exact pointer identity: %s: %v", text, value)
		}
	}
	for _, text := range []string{"FMOVQ F0,(RSP)(R4)", "FSTPQ (F0,F1),(R9)", "MOVD R4,slot(SB)"} {
		file, err := Parse(ArchARM64, "TEXT unknown(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{
			regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R9": arm64ControlFromMap(map[string]bool{"sp:0": true})},
			memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
		}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, ins.Op, false, nil)
		if !arm64ControlHas(state.memory["sp:0"], "") {
			t.Fatalf("unknown/overlapping store lost caller taint: %s: %v", text, state.memory)
		}
	}
	// Floating code bits must remain tainted across the complete Q-width store,
	// including a later narrow load from the upper eight bytes.
	file, err := Parse(ArchARM64, "TEXT bits(SB),$0-0\nFMOVQ F0,(RSP)\nMOVW 12(RSP),R4\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	state := &arm64ControlState{
		regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "F0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
		memory: make(map[string]arm64ControlValue),
	}
	for _, ins := range file.Funcs[0].Instrs[1:3] {
		state.transfer(ins, ins.Op, false, nil)
	}
	if !arm64ControlHas(arm64ControlRead(state.regs, "R4"), "code-derived:") {
		t.Fatal("upper-half floating store washed away transformed code bits")
	}
}

func TestARM64ControlMemoryTypedGrammarRejectsUnknownAliases(t *testing.T) {
	for _, text := range []string{
		"MOVB $1,(RSP)", "MOVD $unresolved,(RSP)", "FMOVD $0,(RSP)",
		"MOVD.X R4,(RSP)", "MOVD.P 8(R9),R9", "LDP.P 16(R9),(R9,R10)",
		"LDP (RSP),(R9,R9)", "FSTPQ (F0,R4),(RSP)",
	} {
		file, err := Parse(ArchARM64, "TEXT invalid(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			continue
		}
		state := &arm64ControlState{regs: make(map[Reg]arm64ControlValue), memory: make(map[string]arm64ControlValue)}
		if state.transferTypedMemory(file.Funcs[0].Instrs[1]) {
			t.Fatalf("unknown/invalid operand supplied exact-width permission: %s", text)
		}
	}
}

func TestARM64ControlMemoryRangeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		first  string
		width  int64
		second string
		other  int64
		want   bool
	}{
		{"sp:-16", 8, "sp:-8", 8, false}, {"sp:-15", 8, "sp:-8", 8, true},
		{"sp:0", 8, "sp:8", 1, false}, {"sp:0", 8, "sp:7", 1, true},
		{"sp:-9223372036854775808", 8, "sp:9223372036854775807", 8, false},
		{"sp:9223372036854775806", 4, "sp:9223372036854775807", 8, true},
		{"sp:0", 8, "fp:0", 8, false}, {"sp:bad", 8, "sp:0", 8, false},
	} {
		if got := arm64ControlMemoryRangesOverlap(tc.first, tc.width, tc.second, tc.other); got != tc.want {
			t.Fatalf("range (%s,%d)/(%s,%d): got %t want %t", tc.first, tc.width, tc.second, tc.other, got, tc.want)
		}
	}
}

func TestARM64ControlMemoryFixedCallerCellBoundaries(t *testing.T) {
	for _, token := range []string{"label:entry_lr", "entry-bp:", "entry-g:", "entry-os18:"} {
		for _, offset := range []int64{-32, -31} {
			file, err := Parse(ArchARM64, fmt.Sprintf("TEXT fixed(SB),$0-0\nFSTPQ (F0,F1),%d(RSP)\nRET\n", offset))
			if err != nil {
				t.Fatal(err)
			}
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
				memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{token: true})},
			}
			ins := file.Funcs[0].Instrs[1]
			state.transfer(ins, ins.Op, false, nil)
			if arm64ControlHas(state.memory["sp:0"], "") != (offset == -31) {
				t.Fatalf("fixed caller cell %s adjacent/one-byte boundary at %d: %v", token, offset, state.memory)
			}
		}
	}
}

func arm64ControlMemoryAdjacentFixture(t *testing.T) (*File, map[string]FuncSig, string, []arm64RawPrivateMemoryCase) {
	t.Helper()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var cases []arm64RawPrivateMemoryCase
	for _, base := range []arm64RawPrivateMemoryCase{
		{name: "byte", store: "MOVB R4", load: "MOVB", width: 1, count: 1, signBits: 64},
		{name: "ubyte", store: "MOVBU R4", load: "MOVBU", width: 1, count: 1},
		{name: "half", store: "MOVH R4", load: "MOVH", width: 2, count: 1, signBits: 64},
		{name: "uhalf", store: "MOVHU R4", load: "MOVHU", width: 2, count: 1},
		{name: "word", store: "MOVW R4", load: "MOVW", width: 4, count: 1, signBits: 64},
		{name: "uword", store: "MOVWU R4", load: "MOVWU", width: 4, count: 1},
		{name: "double", store: "MOVD R4", load: "MOVD", width: 8, count: 1},
		{name: "float_s", store: "FMOVS F0", load: "FMOVS", width: 4, count: 1, floating: true},
		{name: "float_d", store: "FMOVD F0", load: "FMOVD", width: 8, count: 1, floating: true},
		{name: "float_q", store: "FMOVQ F0", load: "FMOVQ", width: 16, count: 1, floating: true},
		{name: "pair", store: "STP (R4,R5)", load: "LDP", width: 8, count: 2},
		{name: "pair_word", store: "STPW (R4,R5)", load: "LDPW", width: 4, count: 2},
		{name: "pair_signed", store: "STPW (R4,R5)", load: "LDPSW", width: 4, count: 2, signBits: 64},
		{name: "float_pair_s", store: "FSTPS (F0,F1)", load: "FLDPS", width: 4, count: 2, floating: true},
		{name: "float_pair_d", store: "FSTPD (F0,F1)", load: "FLDPD", width: 8, count: 2, floating: true},
		{name: "float_pair_q", store: "FSTPQ (F0,F1)", load: "FLDPQ", width: 16, count: 2, floating: true},
	} {
		for _, mode := range []string{"offset", "pre_post", "post_pre"} {
			for _, call := range []bool{false, true} {
				tc := base
				tc.name = "adjacent_" + base.name + "_" + mode
				if call {
					tc.name += "_local_call"
				}
				storeOp, values, _ := strings.Cut(base.store, " ")
				prep := "MOVD (R0),R4\nMOVD 8(R0),R5\n"
				dst := "R9"
				outputs := "MOVD R9,(R1)\n"
				if tc.count == 2 {
					dst = "(R9,R10)"
					outputs += "MOVD R10,8(R1)\n"
				}
				if tc.floating {
					prep = "FMOVQ (R0),F0\nFMOVQ 16(R0),F1\n"
					dst = "F2"
					move := map[int]string{4: "FMOVS", 8: "FMOVD", 16: "FMOVQ"}[tc.width]
					outputs = move + " F2,(R1)\n"
					if tc.count == 2 {
						dst = "(F2,F3)"
						outputs += fmt.Sprintf("%s F3,%d(R1)\n", move, tc.width)
					}
				}
				width := tc.width * tc.count
				allocation := (width + 15) &^ 15
				body := fmt.Sprintf("SUB $64,RSP\n%s\n%s %s,%d(RSP)\n%s %d(RSP),%s\nADD $64,RSP\n", prep, storeOp, values, 64-width, tc.load, 64-width, dst)
				if mode == "pre_post" {
					body = fmt.Sprintf("%s\n%s.W %s,-%d(RSP)\n%s.P %d(RSP),%s\n", prep, storeOp, values, allocation, tc.load, allocation, dst)
				} else if mode == "post_pre" {
					body = fmt.Sprintf("SUB $%d,RSP\n%s\n%s.P %s,%d(RSP)\n%s.W -%d(RSP),%s\nADD $%d,RSP\n", 2*allocation, prep, storeOp, values, allocation, tc.load, allocation, dst, 2*allocation)
				}
				source.WriteString(strings.Replace(arm64RawZeroFrameFixture(516, call, body+outputs), "rawZero", tc.name, 1))
				sig := arm64RawZeroFrameSig()
				sig.Name = tc.name
				sigs[tc.name] = sig
				cases = append(cases, tc)
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	return file, sigs, source.String(), cases
}

func TestARM64ControlMemoryAdjacentFrameObjects(t *testing.T) {
	file, sigs, _, cases := arm64ControlMemoryAdjacentFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "adjacent-frame.ll", "adjacent-frame.o", ir)
	}
	t.Logf("actual Go and LLVM22 five-target objects: %d exact-width adjacent caller-cell forms", len(cases))
}

func TestARM64ControlMemoryOneByteOverlapRemainsTainted(t *testing.T) {
	for _, source := range []string{
		"MOVB R4,7(RSP)", "MOVH R4,-1(RSP)", "MOVW R4,-3(RSP)",
		"MOVD R4,-7(RSP)", "FMOVS F0,-3(RSP)", "FMOVD F0,-7(RSP)",
		"FMOVQ F0,-15(RSP)", "STPW (R4,R5),-7(RSP)",
		"STP (R4,R5),-15(RSP)", "FSTPS (F0,F1),-7(RSP)",
		"FSTPD (F0,F1),-15(RSP)", "FSTPQ (F0,F1),-31(RSP)",
	} {
		file, err := Parse(ArchARM64, "TEXT overlap(SB),$0-0\n"+source+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{
			regs: map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
			memory: map[string]arm64ControlValue{
				"sp:0": arm64ControlFromMap(map[string]bool{"label:entry_lr": true}),
			},
		}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, ins.Op, false, nil)
		if !arm64ControlHas(state.memory["sp:0"], "") {
			t.Fatalf("one-byte-overlap lost caller-cell taint: %s: %v", source, state.memory)
		}
	}
}
