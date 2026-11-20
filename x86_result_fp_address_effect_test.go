package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86LEAFPInitializedResultOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			widths, result := []string{"W", "L"}, 4
			if target.arch == "amd64" {
				widths, result = append(widths, "Q"), 8
			}
			var source, declarations strings.Builder
			for _, width := range widths {
				for _, interior := range []int{0, 1} {
					name := fmt.Sprintf("address%s%d", width, interior)
					body := fmt.Sprintf("MOVL $7,ret+RESULT(FP)\nLEA%s ret+%d(FP),AX", width, result+interior)
					original := x86ResultGPSIMDAdmissionSource(t, target.arch, "func view(x uint32) uint32", body)
					source.WriteString(strings.Replace(original, "·view(SB)", "·"+name+"(SB)", 1))
					fmt.Fprintf(&declarations, "func %s(x uint32) uint32\n", name)
				}
			}
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("complete initialized I32 source: TEXTs=%d source=%x object=%x SDK=%s",
				len(widths)*2, receipt.Source, receipt.Object, receipt.GoVersion)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatalf("complete typed source %s: %v", api, err)
				}
				for _, irLevel := range []string{"0", "2"} {
					objectIR := ir
					if irLevel == "2" {
						objectIR = x86DwordProductIROptimize(t, ir)
					}
					for _, backendLevel := range []string{"0", "2"} {
						t.Run(api+"/IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, objectIR, "-O"+backendLevel)
						})
					}
				}
			}
		})
	}
}

func TestX86LEAFPInitializedResultCompleteThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := []string{"W", "L"}
		if target.arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, interior := range []int{0, 1} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s", target.triple, width, interior, api), func(t *testing.T) {
						declaration := "func view(x uint32) uint32"
						result := 8
						if target.arch == "386" {
							result = 4
						}
						body := fmt.Sprintf("MOVL $7,ret+RESULT(FP)\nLEA%s ret+%d(FP),AX", width, result+interior)
						source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil || ir == "" {
							t.Fatalf("known initialized I32 result cannot discard a legal storage-address value: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LEAFPAddressesNeverInitializeDeclaredResult(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := []string{"W", "L"}
		if target.arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, offset := range []int{8, 9} {
				t.Run(fmt.Sprintf("%s/%s/%d", target.triple, width, offset), func(t *testing.T) {
					// Preserve the original CI counterexample and its declared
					// logical storage. Taking an address writes no result byte.
					source := fmt.Sprintf("TEXT Address(SB),4,$0-16\nLEA%s r+%d(FP),AX\nRET\n", width, offset)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"Address": {
							Name: "Address", Args: []LLVMType{I32}, Ret: I32,
							Frame: FrameLayout{
								Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
								Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1, Name: "r"}},
							},
						}},
					}
					if ir, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("unchanged missing result acquired initialization: %v", err)
					}
				})
			}
		}
	}
}

func TestX86NarrowResultFPAddressPreservesUnknownBytesAndRevokesIdentities(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := []string{"W"}
		if arch == "amd64" {
			widths = append(widths, "L")
		}
		for _, width := range widths {
			for _, prior := range []uint8{0, 0x55, 0xff} {
				t.Run(fmt.Sprintf("%s/%s/%x", arch, width, prior), func(t *testing.T) {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.fp = make([]bool, 12)
					owned := make([]bool, 12)
					for offset := 8; offset < 12; offset++ {
						owned[offset] = true
					}
					state.resultAddressSlots = []x86ResultSlotAddress{{start: 8, end: 12, offset: 8, valid: true}}
					state.resultAddressGP[0], state.resultAddressGP[3] = state.resultAddressSlots[0], state.resultAddressSlots[0]
					state.gp[0], state.canonicalGP[0] = prior, 0xff
					state.pointerGP[0], state.callerAddressGP[0], state.callerAddressGP[3] = true, true, true
					state.callerAddressOrigin[0], state.callerAddressOrigin[3] = 1, 2
					state.predicate = x86ResultPredicate{kind: x86ResultNonzeroMaskGP, register: 0, width: 32}
					before := state.clone()
					ins := x86ScalarLaneInstruction(t, "LEA"+width+" ret+9(FP),AX")
					if accepted, known := x86ResultUnusedFPAddressStep(ins, &state, owned, 8, arch); !accepted || !known {
						t.Fatal("bound narrowed address cannot be retained as unknown bytes")
					}
					wantKnown, wantCanonical := prior&^uint8(3), uint8(0xfc)
					if width == "L" {
						wantKnown, wantCanonical = 0xf0, 0xf0 // Architectural upper32 zero, not guessed address bits.
					}
					if state.gp[0] != wantKnown || state.canonicalGP[0] != wantCanonical || state.pointerGP[0] ||
						state.callerAddressGP[0] || state.callerAddressOrigin[0] != 0 || state.resultAddressGP[0].valid ||
						state.predicate != (x86ResultPredicate{}) || state.flags != before.flags || state.direction != before.direction {
						t.Fatal("narrowed address invented bytes or retained aliases/provenance/canonical facts")
					}
					// Exercise the real post-transfer consumer too. Its source view
					// must revoke this destination, not unrelated live identities.
					after := x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch)
					if after[0] || !after[3] || !reflect.DeepEqual(state.resultAddressGP[3], before.resultAddressGP[3]) {
						t.Fatal("validated FP LEA revoked unrelated caller/result storage")
					}
				})
			}
		}
	}
}

func TestX86NarrowFPAddressLiveUsesAndEscapesRemainContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := []string{"W"}
		if target.arch == "amd64" {
			widths = append(widths, "L")
		}
		for _, width := range widths {
			for _, test := range []struct{ name, use string }{
				{"NUM result", "MOVL AX,ret+RESULT(FP)"},
				{"compare", "TESTW AX,AX\nMOVL $0,CX\nSETEQ CL\nMOVL CX,ret+RESULT(FP)"},
				{"native load", "MOVB (AX),CL"},
				{"native store", "MOVB $1,(AX)"},
				{"input escape", "MOVL AX,x+0(FP)"},
				{"vector result", "MOVL AX,X0\nPEXTRD $0,X0,ret+RESULT(FP)"},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+width+"/"+test.name+"/"+api, func(t *testing.T) {
						declaration := "func view(x uint32) uint32"
						body := "MOVL $7,ret+RESULT(FP)\nLEA" + width + " ret+RESULT(FP),AX\n" + test.use
						source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("unused address knowledge escaped into observable data/memory: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestX86UnusedFPAddressPrivateMappedStorageOnly(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := []string{"W", "L"}
		if arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			t.Run(arch+"/"+width, func(t *testing.T) {
				declaration := "func view(x uint8) uint32"
				// A one-byte field has a real address even for a qword LEA:
				// address width is not a read of eight bytes of its pointee.
				body := "MOVL $7,ret+RESULT(FP)\nLEA" + width + " x+0(FP),AX"
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				sigs, err := goSigsForAsmFile(pkg, file, func(string) string { return "view" }, arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				sig := sigs["view"]
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("public declaration query acquired private storage-address role", err)
				}
				ctx, _ := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
				ctx.goarch = arch
				if err := ctx.checkLoweredScalarFPResultInitialization(); err != nil {
					t.Fatal("complete private proof cannot discard an actual one-byte field address", err)
				}
			})
		}
	}
}

func TestX86UnusedFPAddressRejectsUnboundAndNonordinaryRoles(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Instr, *x86ResultState, []bool)
	}{
		{"unmapped", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[0].FPOffset = 4 }},
		{"end", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[0].FPOffset = 12 }},
		{"negative", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[0].FPOffset = -1 }},
		{"missing producer", func(_ *Instr, state *x86ResultState, _ []bool) { state.resultAddressSlots = nil }},
		{"duplicate producer", func(_ *Instr, state *x86ResultState, _ []bool) {
			state.resultAddressSlots = append(state.resultAddressSlots, state.resultAddressSlots[0])
		}},
		{"hole", func(_ *Instr, _ *x86ResultState, owned []bool) { owned[10] = false }},
		{"raw", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.x86Encoded = true }},
		{"address-size", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.x86AddressBits = 32 }},
		{"segment", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.x86SegmentPrefix = 0x64 }},
		{"indexed", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[0].Mem.Index = SI }},
		{"SP", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[1].Reg = SP }},
		{"g", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[1].Reg = "R14" }},
		{"TYPE_ADDR", func(ins *Instr, _ *x86ResultState, _ []bool) { ins.Args[0].Kind = OpImm }},
		{"pointer parameter", func(ins *Instr, state *x86ResultState, owned []bool) {
			ins.Args[0].FPOffset = 1
			state.pointerFP = map[int64]bool{0: true}
			for offset := 0; offset < 8; offset++ {
				owned[offset], state.fp[offset] = true, true
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := x86ResultState{fp: make([]bool, 12), flags: x86ByteFlagsAll}
			state.resultAddressSlots = []x86ResultSlotAddress{{start: 8, end: 12, valid: true}}
			state.gp[0], state.pointerGP[0] = 0xff, true
			owned := make([]bool, 12)
			for offset := 8; offset < 12; offset++ {
				owned[offset] = true
			}
			ins := x86ScalarLaneInstruction(t, "LEAW ret+9(FP),AX")
			test.edit(&ins, &state, owned)
			before := state.clone()
			if accepted, _ := x86ResultUnusedFPAddressStep(ins, &state, owned, 8, "amd64"); accepted || !reflect.DeepEqual(before, state) {
				t.Fatal("failed storage/shape contract published byte or identity facts")
			}
		})
	}
}
