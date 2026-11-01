package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64LargeFrameMemoryFixture(t *testing.T) (string, GoPackage, []arm64RawPrivateMemoryCase) {
	t.Helper()
	shapes := arm64RawPrivateMemoryCases()
	var instructions []string
	for _, shape := range shapes {
		instructions = append(instructions, strings.ReplaceAll(shape.store, "[sp", "[x20"), strings.ReplaceAll(shape.load, "[sp", "[x20"))
	}
	words := assembleARM64LLVMWords(t, instructions, "")
	var source, declarations strings.Builder
	var cases []arm64RawPrivateMemoryCase
	for index, shape := range shapes {
		store, load := fmt.Sprintf("WORD $%#08x", words[2*index]), fmt.Sprintf("WORD $%#08x", words[2*index+1])
		for _, named := range []bool{false, true} {
			if named {
				decoded := make([]string, 2)
				legal := true
				for part := range decoded {
					ins, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(words[2*index+part])}}})
					if err != nil {
						t.Fatal(err)
					}
					// These two raw sign-extension spellings are not Go frontend
					// mnemonics; the original WORD cases remain fully covered.
					op := arm64ControlOp(ins)
					legal = legal && op != "MOVBW" && op != "MOVHW"
					decoded[part] = strings.Split(ins.Raw, " /*")[0]
				}
				if !legal {
					continue
				}
				store, load = decoded[0], decoded[1]
			}
			shape.name = fmt.Sprintf("r20_%03d_%t", index, named)
			cases = append(cases, shape)
			fmt.Fprintf(&declarations, "func %s(*byte,*byte)\n", shape.name)
			fmt.Fprintf(&source, `TEXT ·%s(SB),4,$496-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
ADD $64,R20,R20
`, shape.name)
			if shape.floating {
				source.WriteString("FMOVQ (R0),F0\nFMOVQ 16(R0),F1\n")
			} else {
				source.WriteString("MOVD (R0),R4\nMOVD 8(R0),R5\n")
			}
			source.WriteString(store + "\n" + load + "\n")
			if shape.floating {
				op := map[int]string{4: "FMOVS", 8: "FMOVD", 16: "FMOVQ"}[shape.width]
				fmt.Fprintf(&source, "%s F2,(R1)\n", op)
				if shape.count == 2 {
					fmt.Fprintf(&source, "%s F3,%d(R1)\n", op, shape.width)
				}
			} else {
				source.WriteString("MOVD R9,(R1)\n")
				if shape.count == 2 {
					source.WriteString("MOVD R10,8(R1)\n")
				}
			}
			source.WriteString("MOVD 0(RSP),R30\nRET\n")
		}
	}
	return source.String(), mustGoPackage(t, "largeframe", "package main\n"+declarations.String()), cases
}

func arm64LargeFrameCheckAPIs(t *testing.T, source string, pkg GoPackage, mutate func(map[string]FuncSig), wantContext, objects bool) []string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := testResolveSym("largeframe")
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(sigs)
	}
	llc := findLLVM22Tool("llc")
	if objects && llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var emitted []string
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
		check := func(api string, err error) {
			t.Helper()
			if wantContext {
				for name, sig := range sigs {
					if sig.Name != name && err != nil && strings.Contains(err.Error(), "signature name mismatch") {
						return // The shared identity validator rejects before lowering.
					}
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s/%s: want Context, got %v", triple, api, err)
				}
			} else if err != nil {
				t.Errorf("%s/%s: %v", triple, api, err)
			}
		}
		ir, err := Translate(file, options)
		check("Translate", err)
		ctx := llvm.NewContext()
		module, moduleErr := TranslateModuleInContext(ctx, file, options)
		moduleIR := ""
		if moduleErr == nil {
			moduleIR = module.String()
			module.Dispose()
		}
		check("Module", moduleErr)
		bound, boundErr := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
			ManualSig: func(name string) (FuncSig, bool) {
				if mutate == nil {
					return FuncSig{}, false
				}
				sig, ok := sigs[name]
				return sig, ok
			},
		})
		boundIR := ""
		if boundErr == nil {
			boundIR = bound.Module.String()
			bound.Module.Dispose()
		}
		check("GoModule", boundErr)
		ctx.Dispose()
		if !wantContext && err == nil && moduleErr == nil && boundErr == nil {
			for api, output := range []string{ir, moduleIR, boundIR} {
				emitted = append(emitted, output)
				if objects {
					compileLLVMToObject(t, llc, triple, fmt.Sprintf("large-frame-%d.ll", api), fmt.Sprintf("large-frame-%d.o", api), output)
				}
			}
		}
	}
	return emitted
}

func TestARM64LargeFrameMemoryFamilyAPIsAndObjects(t *testing.T) {
	source, pkg, cases := arm64LargeFrameMemoryFixture(t)
	requireARM64GoAssemblerResult(t, source, true)
	arm64LargeFrameCheckAPIs(t, source, pkg, nil, false, true)
	t.Logf("%d raw/named scalar, signed-load, GP/FP pair, offset/unscaled/pre/post variants; 3 APIs x 5 objects", len(cases))
}

func TestARM64LargeFrameSourceAndTransportStayFailClosed(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc LargeR20() uint64\n")
	base := arm64LargeFrameScalarSource(496)
	for _, tc := range []struct{ name, body string }{
		{"saved_lr", "MOVD $0,R8\nMOVD R8,(R20)"},
		{"partial_lr", "MOVB R8,1(R20)"},
		{"lr_transform", "ADD $1,R30,R30"},
		{"result_escape", "MOVD R20,R0"},
		{"fp_escape", "MOVD R20,ret+0(FP)"},
		{"global_escape", "MOVD R20,holder(SB)"},
		{"heap_escape", "MOVD R20,(R8)"},
		{"vector_escape", "VMOV R20,V0.D[0]\nVST1 [V0.B16],(R8)"},
		{"address_spill_partial", "MOVD R20,64(RSP)\nMOVB R8,65(RSP)"},
		{"address_spill_fp_load", "MOVD R20,64(RSP)\nFMOVD 64(RSP),F0"},
		{"low_bound", "MOVD -16(R20),R9"},
		{"high_bound", "MOVD 504(R20),R9"},
		{"unknown_index", "MOVD (R20)(R8),R9"},
		{"unknown_transform", "EOR R8,R20\nMOVD (R20),R9"},
		{"mixed_offsets", "CBZ R8,other\nADD $16,R20,R9\nB join\nother:\nADD $24,R20,R9\njoin:\nMOVD (R9),R10"},
		{"mixed_external", "CBZ R8,other\nMOVD R20,R9\nB join\nother:\nMOVD R8,R9\njoin:\nMOVD (R9),R10"},
		{"sp_unbalanced", "SUB $16,RSP"},
		{"source_call", "CALL unknown(SB)"},
		{"raw_call", "WORD $0xd63f0100"},
		{"unknown_word", "WORD $0xffffffff"},
		{"unknown_data", "DWORD $0"},
		{"reserved_r18", "WORD $0x0e043c12"},
		{"reserved_g", "WORD $0x0e043c1c"},
		{"dead_escape", "B live\ndead:\nMOVD R20,holder(SB)\nlive:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(base, "MOVD R0,ret+0(FP)", tc.body+"\nMOVD R0,ret+0(FP)", 1)
			source += "GLOBL holder(SB),16,$8\n"
			requireARM64GoAssemblerResult(t, source, true)
			arm64LargeFrameCheckAPIs(t, source, pkg, nil, true, false)
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*FuncSig)
	}{
		{"fallback", func(sig *FuncSig) { sig.Frame = FrameLayout{} }},
		{"wrong_identity", func(sig *FuncSig) { sig.Name = "different" }},
		{"wrong_slot_width", func(sig *FuncSig) { sig.Frame.Results[0].Type = I32 }},
		{"wrong_slot_offset", func(sig *FuncSig) { sig.Frame.Results[0].Offset = 8 }},
		{"wrong_field", func(sig *FuncSig) { sig.Frame.Results[0].Field = 0 }},
		{"wrong_result", func(sig *FuncSig) { sig.Frame.Results[0].Index = 1 }},
		{"register_contract", func(sig *FuncSig) { sig.ARM64GoRegisterABI = &ARM64GoRegisterABI{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arm64LargeFrameCheckAPIs(t, base, pkg, func(sigs map[string]FuncSig) {
				sig := sigs["largeframe.LargeR20"]
				tc.edit(&sig)
				sigs["largeframe.LargeR20"] = sig
			}, true, false)
		})
	}
}
