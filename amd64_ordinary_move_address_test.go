package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestGoAMD64LocalAddressIgnoresUncertifiedAccessFields(t *testing.T) {
	for _, source := range []string{"MOVQ $slot-16(SP),BX", "LEAQ slot-16(SP),BX"} {
		// This is an isolated emitter-consumption counterexample, not an
		// initialized native entry. The independent runtime owner captures
		// and executes the complete actual Go source for both address forms.
		emit := func(t *testing.T, stale string) string {
			t.Helper()
			ins := x86ScalarLaneInstruction(t, source)
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			proof := &x86FixedLocalProof{frame: 16, accesses: map[int]map[int]x86FixedLocalAccess{}}
			ctx.fixedLocal = proof
			if stale != "" {
				shape, err := fixedLocalInstructionDigest(ins)
				if err != nil {
					t.Fatal(err)
				}
				access := x86FixedLocalAccess{owner: proof, shape: shape, width: 8, nativeInput: true}
				if stale == "mismatched-record" {
					expected := access
					expected.nativeInput = false
					proof.accesses[0] = map[int]x86FixedLocalAccess{0: expected}
				}
				ins.x86FixedLocalMemory = map[int]x86FixedLocalAccess{0: access}
				if _, certified := ctx.fixedLocalMemoryAccess(ins, 0); certified {
					t.Fatal("stale private fields unexpectedly authenticated themselves")
				}
			}
			ctx.blocks = []amd64Block{{instrs: []Instr{ins}}}
			if terminated, err := ctx.lowerInstr(0, 0, ins, nil, nil); terminated || err != nil {
				t.Fatal("address-only emission borrowed an access contract", terminated, err)
			}
			if ctx.fixedMemRoles != nil {
				t.Fatal("original-instruction address projection escaped its lifetime")
			}
			return output.String()
		}
		want := emit(t, "")
		for _, stale := range []string{"missing-record", "mismatched-record"} {
			t.Run(source+"/"+stale, func(t *testing.T) {
				if got := emit(t, stale); got != want {
					t.Error("unverified nativeInput changed address-only emission")
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalOriginalMoveAddressDomains(t *testing.T) {
	for _, width := range []string{"W", "L", "Q"} {
		for _, old := range []uint8{0, 3, 0x55, 0xff} {
			t.Run(fmt.Sprintf("%s/old%x", width, old), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "MOV"+width+" $slot-16(SP),BX")
				original := fmt.Sprintf("%#v", ins)
				state := x86FixedLocalState{pointers: map[Reg]int64{SP: 0, BX: 8}, known: map[Reg]uint8{BX: old},
					opaque: map[Reg]x86FixedLocalOrigins{}, constants: map[Reg]int64{BX: 7}, booleans: map[Reg]uint8{}, flags: x86ByteFlagsAll}
				proof := &x86FixedLocalProof{frame: 16}
				if known, err := fixedLocalPrivateAddressStep(ins, &state, proof); !known || err != nil {
					t.Fatal("original source address did not reach its existing private LEA consumer", known, err)
				}
				if original != fmt.Sprintf("%#v", ins) {
					t.Fatal("source-address projection changed the original MOV identity")
				}
				value, pointer := state.pointers[BX]
				want := old &^ 3
				if width == "L" {
					want = 0xf0
				} else if width == "Q" {
					want = 0
				}
				if pointer != (width == "Q") || pointer && value != 0 || state.known[BX] != want || state.flags != x86ByteFlagsAll ||
					len(state.constants) != 0 || len(state.opaque) != 0 {
					t.Fatal("partial address became NUM or retained a full pointer identity", state)
				}
			})
		}
		for _, control := range []string{"missing-proof", "changed-raw", "changed-operand", "physical-origin", "address-size", "SP-output", "unnamed-address", "unnamed-computed-address"} {
			t.Run(width+"/"+control, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "MOV"+width+" $slot-16(SP),BX")
				proof := &x86FixedLocalProof{frame: 16}
				switch control {
				case "missing-proof":
					proof = nil
				case "changed-raw":
					ins.Raw = "MOV" + width + " $other-8(SP),BX"
				case "changed-operand":
					ins.Args[0].Sym = "$other-8(SP)"
				case "physical-origin":
					ins.x86Encoded = true
				case "address-size":
					ins.x86AddressBits = 32
				case "SP-output":
					ins = x86ScalarLaneInstruction(t, "MOV"+width+" $slot-16(SP),SP")
				case "unnamed-address":
					ins = x86ScalarLaneInstruction(t, "MOV"+width+" $8(SP),BX")
				case "unnamed-computed-address":
					ins = x86ScalarLaneInstruction(t, "MOV"+width+" $(1<<3)(SP),BX")
				}
				state := x86FixedLocalState{pointers: map[Reg]int64{SP: 0}, known: map[Reg]uint8{},
					opaque: map[Reg]x86FixedLocalOrigins{}, constants: map[Reg]int64{}, booleans: map[Reg]uint8{}}
				before := fmt.Sprintf("%#v", state)
				known, err := fixedLocalPrivateAddressStep(ins, &state, proof)
				if known && !errors.Is(err, ErrProbeNeedsContext) || !reflect.DeepEqual(fmt.Sprintf("%#v", state), before) {
					t.Fatal("missing/changed source or physical role supplied address permission", known, err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalOriginalMoveAddressLiveUses(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, width := range []string{"W", "L", "Q"} {
		for _, use := range []string{"dereference", "numeric", "escape", "out-of-bounds", "uninitialized-local"} {
			t.Run(width+"/"+use, func(t *testing.T) {
				address, initialization := "slot-16", "MOVQ AX,0(SP)\n"
				tail := "MOVQ (BX),AX\nMOVQ AX,ret+8(FP)\n"
				switch use {
				case "numeric":
					tail = "ADDQ BX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\n"
				case "escape":
					tail = "MOVQ BX,ret+8(FP)\n"
				case "out-of-bounds":
					address = "slot+8"
				case "uninitialized-local":
					initialization = ""
				}
				source := "TEXT ·AddressUse(SB),4,$16-16\nMOVQ input+0(FP),AX\nMOVQ $0,BX\n" + initialization +
					"MOV" + width + " $" + address + "(SP),BX\n" + tail + "RET\n"
				declaration := "func AddressUse(input uint64) uint64\n"
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				pkg, request, _, options := x86CMOVFixedLocalFixture(t, source, declaration, "linux/amd64", "x86_64-unknown-linux-gnu")
				if width == "Q" && use == "dereference" {
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
						if err != nil || ir == "" {
							t.Fatal("original full-width MOV lost its independently bounded initialized private pointer", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, level)
						}
					})
					return
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				captured, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := captured.Close(); err != nil {
						t.Error(err)
					}
				}()
				expanded, err := captured.preprocess(request.AssemblyFile, []byte(source))
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, expanded)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := captured.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original named address acquired absent bytes, numeric bits, escaped pointer or out-of-bounds storage", err)
				}
			})
		}
	}
}
