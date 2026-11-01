package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64PrivateStructureSource(body string) string {
	return `TEXT ·Structure(SB),4,$120-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xd2800024
` + body + `
MOVD $0,R9
MOVD 0(RSP),R30
RET
`
}

func arm64PrivateStructureAPIs(t *testing.T, source string, wantContext bool, objects bool) {
	t.Helper()
	pkg := arm64PrivateCallDeclarations(t, "func Structure(in,out unsafe.Pointer)\n")
	resolve := func(sym string) string {
		return "test." + strings.TrimPrefix(sym, "·")
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if objects && llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		opt := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
		ir, err := Translate(file, opt)
		check := func(api string, err error) {
			t.Helper()
			if wantContext {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s: want Context, got %v", triple, api, err)
				}
			} else if err != nil {
				t.Errorf("%s %s: %v", triple, api, err)
			}
		}
		check("Translate", err)
		if err == nil && objects {
			compileLLVMToObject(t, llc, triple, "private-structure.ll", "private-structure.o", ir)
		}
		ctx := llvm.NewContext()
		module, moduleErr := TranslateModuleInContext(ctx, file, opt)
		var moduleIR, boundIR string
		if moduleErr == nil {
			moduleIR = module.String()
			module.Dispose()
		}
		check("Module", moduleErr)
		bound, boundErr := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
		})
		if boundErr == nil {
			boundIR = bound.Module.String()
			bound.Module.Dispose()
		}
		check("GoModule", boundErr)
		ctx.Dispose()
		if objects && moduleErr == nil {
			compileLLVMToObject(t, llc, triple, "private-module.ll", "private-module.o", moduleIR)
		}
		if objects && boundErr == nil {
			compileLLVMToObject(t, llc, triple, "private-go-module.ll", "private-go-module.o", boundIR)
		}
	}
}

func TestARM64PrivateStructureFrameAndContinuation(t *testing.T) {
	for count := 1; count <= 4; count++ {
		list := arm64TestVectorList(0, count, "S4")
		body := fmt.Sprintf(`VLD1 (R0),%s
ADD $16,RSP,R9
VST%d %s,(R9)
VLD%d (R9),%s
VST1 %s,(R1)
`, list, count, list, count, list, list)
		source := arm64PrivateStructureSource(body)
		requireARM64GoAssemblerResult(t, source, true)
		arm64PrivateStructureAPIs(t, source, false, true)
	}
}

func TestARM64PrivateStructureReservedRegistersRemainSame(t *testing.T) {
	// These are valid raw UMOV instructions. Named R18 is deliberately not a
	// Go scratch register, and R28 is g. Neither may borrow fresh-frame alias
	// permission merely because the result transport does not mention it.
	for _, word := range []uint32{0x0e043c12, 0x0e043c1c} {
		source := arm64PrivateStructureSource(fmt.Sprintf("WORD $%#08x\nMOVD R0,(R1)", word))
		requireARM64GoAssemblerResult(t, source, true)
		arm64PrivateStructureAPIs(t, source, true, false)
	}
}

func TestARM64PrivateStructureCompleteTypedExtents(t *testing.T) {
	cases := arm64RawStructureCases()
	var source strings.Builder
	source.WriteString("TEXT structureFormats(SB),516,$0-0\n")
	for _, tc := range cases {
		fmt.Fprintln(&source, tc.syntax)
	}
	source.WriteString("UNDEF\n") // Compile-form harness, never executed.
	code := assembleARM64StructureTestBytes(t, source.String())
	if len(code) < 4*len(cases) {
		t.Fatal("actual Go object omitted structure formats")
	}
	for index, tc := range cases {
		if word := binary.LittleEndian.Uint32(code[index*4:]); word != tc.word {
			t.Fatalf("actual Go object %s: %#08x != independent %#08x", tc.syntax, word, tc.word)
		}
		file, err := Parse(ArchARM64, "TEXT f(SB),$0-0\n"+tc.syntax+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, ins := range []Instr{file.Funcs[0].Instrs[1], {Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(tc.word)}}}} {
			form, handled, err := parseARM64StructureMemory(ins)
			width := int64(tc.count * tc.bits / 8)
			if !tc.replicate {
				width *= int64(tc.lanes)
			}
			if !handled || err != nil || form.width() != width || form.load != tc.load || form.replicate != tc.replicate ||
				form.post != (tc.post != 0) || len(form.registers) != tc.count {
				t.Fatalf("%s/%#08x: form=%+v handled=%v err=%v, width=%d", tc.syntax, tc.word, form, handled, err, width)
			}
			if tc.post == 1 && form.increment != width || tc.post == 2 && form.index != "R7" {
				t.Fatalf("%s lost encoded writeback: %+v", tc.syntax, form)
			}
		}
	}
	for _, load := range []bool{false, true} {
		for count := 1; count <= 4; count++ {
			for _, bits := range []int{8, 16, 32, 64} {
				for lane := 0; lane < 128/bits; lane++ {
					for post := arm64RawStructureLaneNoPost; post <= arm64RawStructureLaneRegisterPost; post++ {
						word := encodeARM64RawStructureLane(load, count, bits, lane, post, 7, 9, 30)
						form, handled, err := parseARM64StructureMemory(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
						if !handled || err != nil || form.width() != int64(count*bits/8) || form.load != load || form.lane != lane {
							t.Fatalf("raw lane %#08x: %+v/%v/%v", word, form, handled, err)
						}
					}
				}
			}
		}
	}
	t.Logf("shared memory grammar: %d original Go C_LIST formats plus every raw LD/ST1-4 lane, element width and writeback", len(cases))
}

func TestARM64PrivateStructureBoundsSpillsAndJoinsRemainContext(t *testing.T) {
	for _, body := range []string{
		"ADD $16,RSP,R9\nMOVD R9,32(RSP)\nADD $32,RSP,R10\nVLD1 (R10),[V0.B16]\nMOVD $0,R10",
		"ADD $16,RSP,R9\nMOVD R9,32(RSP)\nADD $33,RSP,R10\nVST1 V0.B[0],(R10)\nMOVD $0,R10",
		"ADD $120,RSP,R9\nVLD1 (R9),[V0.B16]",
		"SUB $16,RSP,R9\nVST1 [V0.B16],(R9)",
		"ADD $16,RSP,R9\nVLD1.P (R9)(R4),[V0.B16]",
		"ADD $16,RSP,R9\nVST1.P [V0.B16],(R9)(R4)",
		"MOVD RSP,R9\nVST1 [V0.B16],(R1)(R9)",
		"CBZ R4,other\nADD $16,RSP,R9\nB joined\nother:\nADD $24,RSP,R9\njoined:\nVLD1 (R9),[V0.B16]",
		"CBZ R4,other\nADD $16,RSP,R9\nB joined\nother:\nMOVD R0,R9\njoined:\nVST1 [V0.B16],(R9)",
		"VST1 [V0.B16],(RSP)",
		"MOVD RSP,R9\nVST1 V0.H[0],1(R9)",
		"ADD $16,RSP,R9\nMOVD R9,holder(SB)\nVLD1 (R9),[V0.B16]",
		"ADD $16,RSP,R9\nMOVD R9,out+8(FP)\nVLD1 (R9),[V0.B16]",
		"ADD $16,RSP,R9\nVMOV R9,V0.D[0]\nVST1 [V0.B16],(R1)",
		"ADD $16,RSP,R9\nWORD $0xffffffff",
	} {
		t.Run(strings.ReplaceAll(body, "\n", ";"), func(t *testing.T) {
			source := arm64PrivateStructureSource(body) + "GLOBL holder(SB),NOPTR,$8\n"
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			linkOverlap := body == "VST1 [V0.B16],(RSP)" || body == "MOVD RSP,R9\nVST1 V0.H[0],1(R9)"
			if arm64CallFrameUnexposed(file.Funcs[0]) && !linkOverlap {
				t.Fatal("structure bounds/escape proof accepted uncertain source")
			}
			// Unknown encodings and malformed Go formats can be Unsupported;
			// no public entry point may call them successful translations.
			if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				ResolveSym: testResolveSym("test"), Sigs: map[string]FuncSig{"test.Structure": arm64RawPrivateFrameSignature("test.Structure")}}); err == nil {
				t.Fatal("unsafe original structure source passed translation")
			}
		})
	}
}

func TestARM64PrivateStructureControlWidthsAndVectorAliases(t *testing.T) {
	for _, tc := range []struct {
		syntax string
		width  int64
	}{
		{"VLD1R (R9),[V0.S4]", 4},
		{"VLD4R (R9),[V0.D2,V1.D2,V2.D2,V3.D2]", 32},
		{"VLD1 (R9),[V0.B8]", 8},
		{"VLD4 (R9),[V0.H8,V1.H8,V2.H8,V3.H8]", 64},
		{"VST1 V0.B[15],(R9)", 1},
		{"VST1 [V0.B16],(R9)", 16},
	} {
		file, err := Parse(ArchARM64, "TEXT f(SB),$0-0\n"+tc.syntax+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		form, _, err := parseARM64StructureMemory(file.Funcs[0].Instrs[1])
		if err != nil || form.width() != tc.width {
			t.Fatalf("%s: %+v/%v", tc.syntax, form, err)
		}
		for _, offset := range []int64{-8, -1, 0, tc.width - 1, tc.width} {
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R9": arm64ControlFromMap(map[string]bool{"sp:0": true}), "F0": arm64ControlFromMap(map[string]bool{"label:vectorPC": true})},
				memory: map[string]arm64ControlValue{fmt.Sprintf("sp:%d", offset): arm64ControlFromMap(map[string]bool{"label:caller": true})},
			}
			if !state.transferStructureMemory(file.Funcs[0].Instrs[1]) {
				t.Fatal("validated memory effect was not consumed")
			}
			overlap := offset+8 > 0 && offset < tc.width
			if form.load {
				value := arm64ControlRead(state.regs, form.registers[0])
				if arm64ControlHas(value, "label:caller") != overlap {
					t.Fatalf("%s offset %d: source PC overlap washed/laundered: %v", tc.syntax, offset, value)
				}
			} else {
				value := state.memory[fmt.Sprintf("sp:%d", offset)]
				if arm64ControlHas(value, "") != overlap {
					t.Fatalf("%s offset %d: store extent lost: %v", tc.syntax, offset, value)
				}
				if !arm64ControlHas(state.escaped, "label:vectorPC") && arm64ControlCount(arm64ControlLabels(state.memory["sp:0"])) == 0 {
					t.Fatal("F/V physical alias lost stored code bits")
				}
			}
		}
	}
}

func TestARM64PrivateStructureLargeFrameR20RequiresTypedEntry(t *testing.T) {
	source := strings.Replace(arm64PrivateStructureSource(`ADD $16,RSP,R9
MOVD R4,(R9)
ADD $16,R20,R10
VLD1R (R10),[V0.S4]
VST1 [V0.B16],(R1)
MOVD $0,R10
MOVD $0,R20`), "$120-16", "$232-16", 1)
	requireARM64GoAssemblerResult(t, source, true)
	arm64PrivateStructureAPIs(t, source, false, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the original source-only/unbound negative: a fallback signature
	// does not supply the entry/result transport for its implicit R20 value.
	_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"·Structure": {Name: "·Structure", Ret: I64}},
	})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("uncontracted original R20 source: %v", err)
	}
}

func TestARM64PrivateStructureNamedLaneDisplacementIsNotRewritten(t *testing.T) {
	for _, instruction := range []string{
		"VLD1 1(R0),V0.B[0]",
		"VST1 V0.H[0],2(R1)",
	} {
		// Go cases 96/97 accept C_LOREG here but encode Rm=31 in the
		// no-post form. That field is architecturally reserved, not an
		// address displacement or an implicit fixed post increment.
		code := assembleARM64StructureTestBytes(t, "TEXT laneEncoding(SB),516,$0-0\n"+instruction+"\nUNDEF\n")
		word := binary.LittleEndian.Uint32(code)
		if word&(1<<23) != 0 || word>>16&31 != 31 {
			t.Fatalf("actual Go %s lacks the no-post reserved Rm witness: %#08x", instruction, word)
		}
		if _, valid := decodeARM64RawStructureLane(word); valid {
			t.Fatalf("reserved original Go encoding %#08x accepted as a valid lane", word)
		}
		arm64PrivateStructureAPIs(t, arm64PrivateStructureSource(instruction), true, false)
	}
}

func TestARM64PrivateStructureNamedReservedD1IsNotRewritten(t *testing.T) {
	for count := 2; count <= 4; count++ {
		for _, load := range []bool{false, true} {
			for _, mode := range []string{"plain", "implicit", "immediate", "register"} {
				op, suffix, memory := fmt.Sprintf("VST%d", count), "", "(R1)"
				if load {
					op, memory = fmt.Sprintf("VLD%d", count), "(R0)"
				}
				if mode != "plain" {
					suffix = ".P"
				}
				if mode == "immediate" {
					memory = fmt.Sprintf("%d%s", count*8, memory)
				} else if mode == "register" {
					memory += "(R4)"
				}
				list := arm64TestVectorList(0, count, "D1")
				instruction := op + suffix + " " + list + "," + memory
				if load {
					instruction = op + suffix + " " + memory + "," + list
				}
				code := assembleARM64StructureTestBytes(t, "TEXT reservedD1(SB),516,$0-0\n"+instruction+"\nUNDEF\n")
				word := binary.LittleEndian.Uint32(code)
				if word&(1<<30) != 0 || word>>10&3 != 3 {
					t.Fatalf("actual Go %s lacks Q=0/size=3 witness: %#08x", instruction, word)
				}
				if _, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}); err == nil {
					t.Fatalf("architecturally reserved original Go encoding %#08x decoded", word)
				}
				arm64PrivateStructureAPIs(t, arm64PrivateStructureSource(instruction), true, false)
			}
		}
	}
}
