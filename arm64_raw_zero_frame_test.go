package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64RawZeroFrameFixture(flags int, call bool, body string) string {
	if call {
		body += "WORD $0x94000004\n"
	}
	source := fmt.Sprintf(`TEXT rawZero(SB),%d,$0-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xa9bf7bfd
MOVD $0,R4
%sWORD $0xa8c17bfd
WORD $0xd65f03c0
`, flags, body)
	if call {
		source += "WORD $0xd503201f\nWORD $0xd65f03c0\n"
	}
	return source
}

func TestARM64RawZeroFrameEscapesAndCallerStateFailClosed(t *testing.T) {
	for _, body := range []string{
		"MOVD R29,(R1)",
		"MOVD R29,holder(SB)",
		"MOVD R29,out+8(FP)",
		"MOVD R29,R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD 0(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD RSP,R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD RSP,R0",
		"MOVD RSP,R9",
		"CBZ R0,other\nMOVD RSP,R9\nB joined\nother:\nMOVD R0,R9\njoined:\nMOVD R9,(R1)\nMOVD $0,R9",
		"CBZ R0,other\nMOVD RSP,R9\nB joined\nother:\nADD $8,RSP,R9\njoined:\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD RSP,R9\nEOR R9,R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD (RSP)(R0),R9",
		"MOVD.P (RSP)(R0),R9",
		"MOVD RSP,R9\nMOVD (R0)(R9),R10\nMOVD $0,R9",
		"MOVD.P 8(R29),R29",
		"MOVB R4,1(RSP)",
		"MOVH R4,2(RSP)",
		"MOVW R4,4(RSP)",
		"MOVB R4,9(RSP)",
		"MOVH R4,10(RSP)",
		"MOVW R4,12(RSP)",
		"MOVD R4,8(RSP)",
		"STPW (R4,R5),4(RSP)",
		"FSTPS (F0,F1),4(RSP)",
		"FMOVQ F0,0(RSP)",
		"FMOVD 0(RSP),F0",
		"MOVWU 0(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD R4,-8(RSP)",
		"MOVD R4,16(RSP)",
		"SUB $16,RSP",
		"ADD $16,RSP",
		"CBZ R0,joined\nSUB $16,RSP\njoined:",
		"WORD $0xffffffff",
		"DWORD $0",
		"WORD $0xd63f0000", // Native BLR X0, not a source-local continuation.
		"WORD $0x94010000", // Raw BL outside the exact source envelope.
		"CALL unknown(SB)",
		"SVC $0",
		"B dead_end\ndead:\nMOVD R29,(R1)\ndead_end:",
	} {
		t.Run(body, func(t *testing.T) {
			// The final external store forces actual continuation lowering to
			// need the disjointness proof; otherwise some valid unsafe-to-grant
			// bodies can still translate without ever borrowing that permission.
			file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, body+"\nMOVD R4,(R1)\n"))
			if err != nil {
				t.Fatal(err)
			}
			if arm64RawZeroFrameUnexposed(file.Funcs[0]) {
				t.Fatal("whole-source zero-frame proof erased an escape, overlap or unknown effect")
			}
			sig := arm64RawZeroFrameSig()
			if body == "MOVD RSP,R0" || body == "MOVD RSP,R9" {
				// Unknown/result transport cannot discard these live addresses.
				sig.Ret = I64
			}
			_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: map[string]FuncSig{sig.Name: sig}})
			if err == nil {
				t.Fatal("unsafe source borrowed another translation path")
			}
		})
	}
	for _, replacement := range []string{
		"MOVD $0,R29\nWORD $0xd65f03c0",
		"MOVD $0,R30\nWORD $0xd65f03c0",
		"RET R0",
		"B (R0)",
		"WORD $0xd65f0000", // Physical RET X0.
	} {
		source := strings.Replace(arm64RawZeroFrameFixture(516, false, ""), "WORD $0xd65f03c0", replacement, 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64RawZeroFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("unrestored/unknown caller state inherited a proof: %s", replacement)
		}
	}
}

func TestARM64RawZeroFrameRawCallsStayPhysicalLeaf(t *testing.T) {
	file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(4, true, "MOVD R4,(R1)\n"))
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeARM64RawPCRelative(file.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	if arm64SourceGoFrame(file.Funcs[0]).present || arm64SourceGoFrame(normalized).present {
		t.Fatal("normalizing a raw BL invented a Go LR/FP prologue")
	}
	for _, mutation := range []string{
		"MOVD R29,(R1)\nWORD $0xd65f03c0",
		"SUB $16,RSP\nWORD $0xd65f03c0",
		"MOVD $0,R30\nWORD $0xd65f03c0",
		"WORD $0x97ffffff\nWORD $0xd65f03c0", // Recursive raw call remains bounded/fails.
	} {
		source := strings.Replace(arm64RawZeroFrameFixture(516, true, "MOVD R4,(R1)\n"), "WORD $0xd503201f\nWORD $0xd65f03c0", mutation, 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64RawZeroFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("raw local-call context lost its independent return/effect contract: %s", mutation)
		}
	}
	// A textual local BL does cause Go's prologue selection. It cannot borrow
	// the raw-call witness merely by copying a diagnostic comment.
	manual := normalized
	manual.Instrs = append([]Instr(nil), normalized.Instrs...)
	for index := range manual.Instrs {
		if manual.Instrs[index].arm64RawLocalCall {
			manual.Instrs[index].arm64RawLocalCall = false
		}
	}
	if !arm64SourceGoFrame(manual).present || arm64RawZeroFrameUnexposed(manual) {
		t.Fatal("a comment was accepted as authenticated raw-call origin")
	}
	_, err = Translate(&File{Arch: ArchARM64, Funcs: []Func{manual}}, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"rawZero": arm64RawZeroFrameSig()}})
	if err == nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unproved source call must stay fail-closed: %v", err)
	}
}

func arm64RawZeroFrameSig() FuncSig {
	return FuncSig{
		Name: "rawZero", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}},
	}
}

func TestARM64RawZeroFrameCallerDisjointStore(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int
		call  bool
	}{
		{name: "zero_leaf", flags: 4},
		{name: "noframe_leaf", flags: 516},
		{name: "zero_raw_local_call", flags: 4, call: true},
		{name: "noframe_raw_local_call", flags: 516, call: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64RawZeroFrameFixture(tc.flags, tc.call, "MOVD R4,(R1)\n")
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := arm64RawZeroFrameSig()
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				Sigs: map[string]FuncSig{sig.Name: sig},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "@rawZero(") {
				t.Fatal("typed raw zero-frame root was not emitted")
			}
		})
	}
}

func TestARM64RawZeroFrameTypedVoidDiscardsOnlyDeadVirtualGP(t *testing.T) {
	for _, body := range []string{
		"MOVD RSP,R9",
		"MOVD RSP,R0",
		"MOVD RSP,R9\nMOVD R9,R10",
		"CBZ R0,other\nMOVD RSP,R9\nB joined\nother:\nMOVD R0,R9\njoined:",
	} {
		t.Run(body, func(t *testing.T) {
			source := arm64RawZeroFrameFixture(516, false, body+"\nMOVD R4,(R1)\n")
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if arm64RawZeroFrameUnexposed(file.Funcs[0]) {
				t.Fatal("source-only proof cannot guess the caller's return transport")
			}
			sig := arm64RawZeroFrameSig()
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestARM64RawZeroFrameTypedVoidRequiresCompleteABI0(t *testing.T) {
	file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, "MOVD RSP,R9\nMOVD R4,(R1)\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Func, *FuncSig)
	}{
		{"result", func(_ *Func, sig *FuncSig) { sig.Ret = I64 }},
		{"result_slot", func(_ *Func, sig *FuncSig) { sig.Frame.Results = []FrameSlot{{Type: I64}} }},
		{"custom_regs", func(_ *Func, sig *FuncSig) { sig.ArgRegs = []Reg{"R0", "R1"} }},
		{"register_abi", func(_ *Func, sig *FuncSig) { sig.ARM64GoRegisterABI = &ARM64GoRegisterABI{} }},
		{"closure", func(_ *Func, sig *FuncSig) { sig.ARM64ClosureABI = &ARM64ClosureABI{} }},
		{"machine_entry", func(_ *Func, sig *FuncSig) { sig.ARMEntry = &ARMMachineEntry{} }},
		{"context", func(_ *Func, sig *FuncSig) { sig.WASMContext = Ptr }},
		{"native", func(_ *Func, sig *FuncSig) { sig.WASMNative = true }},
		{"missing_slot", func(_ *Func, sig *FuncSig) { sig.Frame.Params = sig.Frame.Params[:1] }},
		{"aggregate", func(_ *Func, sig *FuncSig) { sig.Args[0] = "{ ptr, i64 }" }},
		{"narrow", func(_ *Func, sig *FuncSig) { sig.Args[0] = I32; sig.Frame.Params[0].Type = I32 }},
		{"slot_type", func(_ *Func, sig *FuncSig) { sig.Frame.Params[0].Type = I64 }},
		{"slot_offset", func(_ *Func, sig *FuncSig) { sig.Frame.Params[0].Offset = 8 }},
		{"slot_index", func(_ *Func, sig *FuncSig) { sig.Frame.Params[0].Index = 1 }},
		{"slot_field", func(_ *Func, sig *FuncSig) { sig.Frame.Params[0].Field = 0 }},
		{"slot_fields", func(_ *Func, sig *FuncSig) { sig.Frame.Params[0].Fields = []int{0} }},
		{"arg_size", func(fn *Func, _ *FuncSig) { fn.ArgSize++ }},
		{"internal", func(fn *Func, _ *FuncSig) { fn.Sym += "<ABIInternal>" }},
		{"helper", func(fn *Func, _ *FuncSig) { fn.arm64PrivateRegisterEntry = true }},
		{"hidden_context", func(fn *Func, _ *FuncSig) { fn.Instrs[0].Raw = "TEXT rawZero(SB),NOSPLIT|NOFRAME|NEEDCTXT,$0-16" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn, sig := file.Funcs[0], arm64RawZeroFrameSig()
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			tc.edit(&fn, &sig)
			transport := &arm64PrivateFrameTransport{entry: sig}
			if arm64RawZeroVoidTransport(fn, transport) || arm64RawZeroFrameUnexposedForTransport(fn, transport) {
				t.Fatal("incomplete/nonordinary caller transport discarded a live frame address")
			}
		})
	}
	if arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], nil) {
		t.Fatal("absent caller contract inherited void transport")
	}
}
