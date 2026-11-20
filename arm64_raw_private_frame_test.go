package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawPrivateFrameOriginalPairedSpill(t *testing.T) {
	// Original krypto encKeySetup: a raw 96-byte private spill frame nested
	// below the Go-generated frame, exact LR spill/reload and balanced SP.
	const source = `TEXT rawPrivateSpill(SB),4,$120-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xa9ba6ffc
WORD $0xa9057bfd
WORD $0x910143fd
MOVD R0,(R1)
WORD $0xa9457bfd
WORD $0xa8c66ffc
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	sig := FuncSig{
		Name: "rawPrivateSpill", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}},
	}
	for _, triple := range arm64TypedNativeTargets {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawPrivateSpill": sig}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "@rawPrivateSpill(") {
				t.Fatal("typed raw spill function was not emitted")
			}
			compileLLVMToObject(t, llc, triple, "raw-private-frame.ll", "raw-private-frame.o", ir)
		})
	}
}

func arm64RawPrivateFrameFixture(name, body string) string {
	return fmt.Sprintf(`TEXT %s(SB),4,$120-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xa9ba6ffc
WORD $0xa9057bfd
WORD $0x910143fd
%s
MOVD R0,(R1)
WORD $0xa9457bfd
WORD $0xa8c66ffc
RET
`, name, body)
}

func arm64RawPrivateFrameSignature(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}},
	}
}

func TestARM64RawPrivateFrameSourceProofFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"external_store", "MOVD R29,(R1)"},
		{"symbol_store", "MOVD R29,holder(SB)"},
		{"incoming_argument_store", "MOVD R29,in+0(FP)"},
		{"alias_store", "MOVD R29,R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"literal_frame_address_store", "MOVD $16(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"frame_result", "MOVD R29,R0"},
		{"frame_temporary_at_ret", "MOVD R29,R9"},
		{"frame_address_spill_restore_escape", "MOVD R29,16(RSP)\nMOVD 16(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"saved_unknown_fp_escape", "MOVD 80(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"partial_scalar_spill_overlap", "MOVB R0,81(RSP)"},
		{"partial_pair_spill_overlap", "STPW (R0,R1),84(RSP)"},
		{"partial_fp_spill_overlap", "FSTPS (F0,F1),84(RSP)"},
		{"fp_read_of_pointer_spill", "FMOVD 80(RSP),F0"},
		{"narrow_pointer_read_then_escape", "MOVWU 80(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"mixed_external_frame_join", "CBZ R0,other\nMOVD R29,R9\nB joined\nother:\nMOVD R0,R9\njoined:\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"mixed_offset_join", "CBZ R0,other\nADD $16,RSP,R9\nB joined\nother:\nADD $24,RSP,R9\njoined:\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"mixed_spill_join", "CBZ R0,other\nMOVD R29,16(RSP)\nB joined\nother:\nMOVD R0,16(RSP)\njoined:\nMOVD 16(RSP),R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"sp_delta_join", "CBZ R0,joined\nSUB $16,RSP\njoined:\nMOVD $0,R9"},
		{"sp_multi_delta_join", "CBZ R0,other\nSUB $16,RSP\nB joined\nother:\nSUB $32,RSP\njoined:\nADD $16,RSP"},
		{"unbalanced_pop", "ADD $16,RSP"},
		{"unbalanced_push", "SUB $16,RSP"},
		{"unknown_index", "MOVD (RSP)(R0),R9"},
		{"unknown_index_writeback", "MOVD.P (RSP)(R0),R9"},
		{"load_writeback_base_overlap", "ADD $16,RSP,R9\nMOVD.P 8(R9),R9\nMOVD $0,R9"},
		{"frame_index", "MOVD RSP,R9\nMOVD (R0)(R9),R10\nMOVD $0,R9"},
		{"unknown_transform_cannot_kill", "MOVD RSP,R9\nEOR R9,R9\nMOVD R9,(R1)\nMOVD $0,R9"},
		{"unknown_word", "WORD $0xffffffff"},
		{"unknown_data", "DWORD $0"},
		{"raw_native_ret", "WORD $0xd65f03c0"},
		{"raw_native_call", "WORD $0xd63f0000"},
		{"source_call", "CALL unknown(SB)"},
		{"local_call", "CALL helper\nhelper:"},
		{"native_exception", "SVC $0"},
		{"dead_escape", "B skip\ndead:\nMOVD R29,(R1)\nskip:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64RawPrivateFrameFixture("rawNegative", tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if arm64CallFrameUnexposed(file.Funcs[0]) {
				t.Fatal("raw private frame proof erased an escape or uncertain effect")
			}
			_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				Sigs: map[string]FuncSig{"rawNegative": arm64RawPrivateFrameSignature("rawNegative")}})
			if err == nil {
				t.Fatal("unsafe raw source passed through an alternate translation path")
			}
		})
	}
	for _, change := range []struct{ from, to string }{
		{"4,$120-16", "516,$120-16"},
		{"4,$120-16", "UnknownFlags,$120-16"},
		{"4,$120-16", "4,$121-16"},
		{"RET\n", "RET R29\n"},
		{"RET\n", ""},
		{"WORD $0x910143fd\n", "MOVD R29,R9\nMOVD R9,(R1)\nMOVD $0,R9\n"},
	} {
		source := strings.Replace(arm64RawPrivateFrameFixture("rawNegative", ""), change.from, change.to, 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("unproven source contract: %s -> %s", change.from, change.to)
		}
	}
}

func TestARM64RawPrivateFrameLocalSpillsCopiesAndExactJoins(t *testing.T) {
	for _, body := range []string{
		"ADD $16,RSP,R9\nMOVD R9,32(RSP)\nMOVD $0,R9\nMOVD 32(RSP),R10\nMOVD (R10),R11\nMOVD $0,R10",
		"CBZ R0,other\nADD $16,RSP,R9\nB joined\nother:\nMOVD $16(RSP),R9\njoined:\nMOVD R9,R10\nMOVD $0,R9\nMOVD (R10),R11\nMOVD $0,R10",
		"MOVD R29,16(RSP)\nMOVD R0,16(RSP)",                                            // A known full overwrite, not an arbitrary raw write mask.
		"CBZ R0,other\nMOVD R29,R9\nB joined\nother:\nMOVD R0,R9\njoined:\nMOVD $0,R9", // Taint is kept at the join then explicitly overwritten.
	} {
		source := arm64RawPrivateFrameFixture("rawLocalRead", body)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if !arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("known private spill/copy/read lost its exact proof: %s", body)
		}
		_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
			Sigs: map[string]FuncSig{"rawLocalRead": arm64RawPrivateFrameSignature("rawLocalRead")}})
		if err != nil {
			t.Fatal(err)
		}
	}
	file, err := Parse(ArchARM64, arm64RawPrivateFrameFixture("rawNoHelpers", "CALL helper<>(SB)")+"TEXT helper<>(SB),4,$0\nADD $1,R9\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coalesceARM64PrivateRegisterHelpers(file); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("raw byte-layout helper root cannot silently borrow coalescing: %v", err)
	}
}

func TestARM64RawPrivateFrameContinuationGuardsRemainIndependent(t *testing.T) {
	for _, body := range []string{
		"MOVD R0,88(RSP)",       // Full LR overwrite, even though no frame address escaped.
		"MOVB R0,89(RSP)",       // Partial LR overwrite.
		"FSTPQ (F0,F1),72(RSP)", // A full FP pair also overlaps the saved LR.
	} {
		file, err := Parse(ArchARM64, arm64RawPrivateFrameFixture("rawLinkClobber", body))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
			Sigs: map[string]FuncSig{"rawLinkClobber": arm64RawPrivateFrameSignature("rawLinkClobber")}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unknown caller LR cannot borrow the address proof: %s: %v", body, err)
		}
	}
	source := strings.Replace(arm64RawPrivateFrameFixture("rawLinkClobber", ""), "RET\n", "MOVD $0,R30\nRET\n", 1)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"rawLinkClobber": arm64RawPrivateFrameSignature("rawLinkClobber")}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("the Go leaf epilogue must not wash an explicitly clobbered R30: %v", err)
	}
}

func TestARM64RawPrivateFrameOverlappingPointerReadsRemainTainted(t *testing.T) {
	for trial := 0; trial < 100; trial++ {
		state := &arm64RawPrivateFrameState{
			regs: make(arm64PrivateFrameAddresses),
			spills: map[int64]arm64PrivateFrameAddress{
				16: {offset: 8, exact: true},
				24: {offset: 32, exact: true},
			},
		}
		form := arm64RawPrivateMemoryForm{
			memory:    Operand{Kind: OpMem, Mem: MemRef{Base: SP, Off: 20}},
			registers: []Reg{"R9"}, elementBytes: 8, gp: true,
		}
		if !state.memory(form, 120) {
			t.Fatal("known bounded pointer read failed")
		}
		value, frame := state.address("R9")
		if !frame || value.exact {
			t.Fatal("map iteration cannot choose one of two overlapping pointer cells")
		}
	}
}
