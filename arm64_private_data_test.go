package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"math"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64PrivateDataBoundObjects(t *testing.T, source, declaration, name string) {
	t.Helper()
	arm64PrivateCallGoObject(t, source)
	pkg := mustGoPackage(t, "test/indexed", "package indexed\n"+declaration+"\nfunc Noop()\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	for _, target := range arm64TypedNativeTargets {
		func() {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
			})
			if err != nil {
				t.Fatalf("%s GoModule bounded data: %v", target, err)
			}
			defer bound.Module.Dispose()
			compileLLVMToObject(t, llc, target, name+"-go.ll", name+"-go.o", bound.Module.String())
			opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: bound.Signatures, ResolveSym: resolve}
			ir, err := Translate(file, opt)
			if err != nil {
				t.Fatalf("%s Translate bounded data: %v", target, err)
			}
			compileLLVMToObject(t, llc, target, name+"-text.ll", name+"-text.o", ir)
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Fatalf("%s Module bounded data: %v", target, err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, target, name+"-module.ll", name+"-module.o", module.String())
		}()
	}
}

func arm64PrivateDataContext(t *testing.T, source string) {
	t.Helper()
	arm64PrivateCallGoObject(t, source)
	pkg := mustGoPackage(t, "test/indexed", "package indexed\nfunc Indexed(dst *uint64,n uint64) uint64\nfunc Noop()\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range arm64TypedNativeTargets {
		opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs, ResolveSym: resolve}
		if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s Translate needs a private data/transport contract: %v", target, err)
		}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, file, opt)
		if err == nil {
			module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s Module needs a private data/transport contract: %v", target, err)
		}
		bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
		})
		if err == nil {
			bound.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s GoModule needs a private data/transport contract: %v", target, err)
		}
	}
}

func TestARM64PrivateDataSignedNarrowWordIndexRemainsContext(t *testing.T) {
	for _, tc := range []struct {
		store, native string
		value, frame  int
	}{
		{"MOVB", "ldrsb w11,[x17]", 0x80, 512},
		{"MOVH", "ldrsh w11,[x17]", 0x8000, 65552},
	} {
		t.Run(tc.store, func(t *testing.T) {
			word := assembleARM64LLVMWords(t, []string{tc.native}, "")[0]
			source := arm64PrivateIndexedSource("MOVB", "MOVBU", 0)
			source = strings.Replace(source, "$80-24", fmt.Sprintf("$%d-24", tc.frame), 1)
			source = strings.Replace(source, "MOVD $0x123456789abcde7e,R5", fmt.Sprintf("MOVD $%d,R5", tc.value), 1)
			source = strings.Replace(source, "MOVB R5,0(R17)(R11<<0)", fmt.Sprintf("%s R5,(R17)\nWORD $%#08x\nMOVB R5,0(R17)(R11<<0)", tc.store, word), 1)
			// MOVBW/MOVHW are decoded forms, not Go named instructions.
			// The actual accepted WORD source still needs a raw-frame contract;
			// this new named-data proof must not authorize it implicitly.
			arm64PrivateDataContext(t, source)
			decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			if err != nil {
				t.Fatal(err)
			}
			state := newARM64PrivateDataState()
			state.regs["R17"] = arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{16, 16}}
			form, ok := arm64PrivateDataMemory(decoded)
			if !ok {
				t.Fatalf("decoded signed word load lacks typed memory grammar: %+v", decoded)
			}
			if _, ok := state.memory(arm64ControlOp(decoded), form, int64(tc.frame)); !ok {
				t.Fatal("bounded decoded load was rejected")
			}
			value := state.value("R11").interval
			actual := uint64(uint32(int32(int16(tc.value))))
			if tc.store == "MOVB" {
				actual = uint64(uint32(int32(int8(tc.value))))
			}
			if actual < value.low || actual > value.high {
				t.Fatalf("decoded signed word numeric bound excluded %#x: %v", actual, value)
			}
		})
	}
}

func TestARM64PrivateDataExtentAndEscapeNegatives(t *testing.T) {
	base := arm64PrivateIndexedSource("MOVD", "MOVD", 3)
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"last_element_crosses_extent", "$80-24", "$64-24"},
		{"unbounded_index", "AND $7,R11", "NOP"},
		{"wider_mask", "AND $7,R11", "AND $255,R11"},
		{"hardware_word_count_wrap", "AND $7,R11", "MOVW n+8(FP),R11\nMOVD $32,R12\nLSRW R12,R11"},
		{"unknown_index_transform", "AND $7,R11", "AND $7,R11\nRBIT R11,R11"},
		{"saved_lr_byte_overlap", "MOVD R5,0(R17)(R11<<3)", "MOVB R5,-9(R17)"},
		{"writeback_leaves_allocation", "MOVD R5,0(R17)(R11<<3)", "MOVD.P R5,80(R17)"},
		{"negative_writeback", "MOVD R5,0(R17)(R11<<3)", "MOVD.W R5,-24(R17)"},
		{"private_argument", "MOVD R12,(R7)", "MOVD R17,R0\nCALL ·Consume(SB)\nMOVD R12,(R7)"},
		{"private_fp_result", "MOVD R12,ret+16(FP)", "MOVD R17,ret+16(FP)"},
		{"private_register_result", "MOVD R12,ret+16(FP)", "MOVD R17,R0"},
		{"private_fp_param", "MOVD R12,(R7)", "MOVD R17,dst+0(FP)\nMOVD R12,(R7)"},
		{"private_heap_store", "MOVD R12,(R7)", "MOVD R17,(R7)"},
		{"private_global_store", "MOVD R12,(R7)", "MOVD R17,holder(SB)"},
		{"private_fp_bank", "MOVD R12,(R7)", "FMOVD R17,F0\nMOVD R12,(R7)"},
		{"private_vector_bank", "MOVD R12,(R7)", "VMOV R17,V0.D[0]\nMOVD R12,(R7)"},
		{"different_offsets", "MOVD R5,0(R17)(R11<<3)", "CBZ R11,alternate\nB merged\nalternate:\nADD $24,RSP,R17\nmerged:\nMOVD R5,0(R17)(R11<<3)"},
		{"mixed_external", "MOVD R5,0(R17)(R11<<3)", "CBZ R11,alternate\nB merged\nalternate:\nMOVD R7,R17\nmerged:\nMOVD R5,0(R17)(R11<<3)"},
		{"derived_caller_pc_index", "AND $7,R11", "MOVD R30,R11\nAND $7,R11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(base, tc.old, tc.replacement, 1)
			source += "\nGLOBL holder(SB),NOPTR,$8\n"
			if tc.name == "private_argument" {
				// Use the real zero-arg target's R0 result fallback transport
				// rather than invent a third declaration for the unit fixture.
				source = strings.Replace(source, "MOVD R17,R0\nCALL ·Consume(SB)", "MOVD R17,8(RSP)\nCALL ·Noop(SB)", 1)
			}
			arm64PrivateDataContext(t, source)
		})
	}
}

func TestARM64PrivateDataUnknownStoresPreserveOnlyDisjointCells(t *testing.T) {
	for _, derived := range []bool{false, true} {
		state := &arm64ControlState{
			unexposedSP:  true,
			privateStore: &arm64PrivateDataSpan{8, 24},
			regs:         map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R17": arm64ControlFromMap(map[string]bool{"sp:8": true})},
			memory: map[string]arm64ControlValue{
				"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}), "sp:8": arm64ControlExternal(), "sp:24": arm64ControlFromMap(map[string]bool{"label:untouched": true}), "fp:0": arm64ControlFromMap(map[string]bool{"label:fp": true}),
			},
		}
		if derived {
			state.regs["R11"] = arm64ControlFromMap(map[string]bool{"code-derived:": true})
		}
		state.invalidateUnknownStore(Operand{Kind: OpMem, Mem: MemRef{Base: "R17", Index: "R11"}}, arm64ControlFromMap(map[string]bool{"label:stored": true}))
		if arm64ControlHas(state.memory["sp:0"], "") != derived || arm64ControlHas(state.memory["sp:24"], "") != derived {
			t.Fatal("per-instruction data extent erased the caller/code-derived boundary")
		}
		if !arm64ControlHas(state.memory["sp:8"], "label:stored") || !arm64ControlHas(state.memory["sp:8"], "") || !arm64ControlHas(state.memory["fp:0"], "") {
			t.Fatal("overlap/FP cells retained stale contents or lost stored code provenance")
		}
	}
}

func TestARM64PrivateDataAllMemoryWidthsRejectExtentCrossing(t *testing.T) {
	for _, tc := range arm64PrivateDataCases() {
		if tc.mode != "offset" || tc.zero != "" {
			continue
		}
		t.Run(tc.store+"_"+tc.load, func(t *testing.T) {
			input := "R5"
			if tc.floating {
				input = "F0"
			}
			if tc.count == 2 {
				input = "(R5,R6)"
				if tc.floating {
					input = "(F0,F1)"
				}
			}
			// The first element fits, but the scalar's last bytes or pair's
			// second element do not. Pair offsets retain Go's natural scale.
			offset := 72 - tc.width*tc.count + tc.width
			source := arm64PrivateIndexedSource("MOVD", "MOVD", 3)
			store := fmt.Sprintf("FMOVD R5,F0\nFMOVD R5,F1\n%s %s,%d(R17)", tc.store, input, offset)
			source = strings.Replace(source, "MOVD R5,0(R17)(R11<<3)", store, 1)
			arm64PrivateDataContext(t, source)
		})
	}
}

func TestARM64PrivateDataComparisonCannotEraseMixedOrigins(t *testing.T) {
	source := arm64PrivateIndexedSource("MOVD", "MOVD", 3)
	source = strings.Replace(source, "MOVD R5,0(R17)(R11<<3)", `ADD $64,RSP,R19
CBZ R11,alternate
CMP R17,R19
B merged
alternate:
ADD $24,RSP,R17
CMP R17,R19
merged:
BHI store
B done
store:
MOVD R5,(R17)
done:`, 1)
	source = strings.Replace(source, "MOVD 0(R17)(R11<<3),R12", "MOVD (R17),R12", 1)
	// Both predecessors set real flags, but a disjunctive comparison snapshot
	// must not restore a usable address after the whole-CFG may-frame join
	// marked R17 as mixed. This is an accepted source/object negative only.
	arm64PrivateDataContext(t, source)
	state := newARM64PrivateDataState()
	left := arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{64, 64}, origin: 1}
	right := arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{16, 16}, origin: 2}
	state.regs["R19"] = left
	state.regs["R17"] = arm64PrivateDataValue{frame: true, mixed: true, interval: arm64PoolUnknownInterval}
	state.comparison = arm64PrivateDataCompare{left: left, right: right, leftReg: "R19", rightReg: "R17", valid: true}
	branch, possible := state.branch("BHI", true)
	if !possible || !branch.value("R17").mixed {
		t.Fatal("a cached comparison restored an exact address after a may-frame join")
	}
}

func TestARM64PrivateDataConvergenceBudgetFailsClosed(t *testing.T) {
	source := strings.Replace(arm64PrivateIndexedSource("MOVB", "MOVBU", 0), "$80-24", "$1048576-24", 1)
	source = strings.Replace(source, "MOVB R5,0(R17)(R11<<0)", `MOVD $1048560,R6
ADD R6,R17,R6
clear:
MOVB.P ZR,1(R17)
CMP R17,R6
BHI clear
MOVD $0,R17
ADD $16,RSP,R17
MOVB R5,(R17)`, 1)
	arm64PrivateCallGoObject(t, source)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	transport := &arm64PrivateFrameTransport{
		entry:   FuncSig{Ret: I64},
		resolve: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		sigs:    map[string]FuncSig{"Noop": {Ret: Void}},
	}
	if _, err := arm64PrivateDataProofDetails(file.Funcs[0], transport); err == nil || !strings.Contains(err.Error(), "convergence budget") {
		t.Fatalf("large byte loop must exhaust this bounded proof, not authorize stores: %v", err)
	}
	// The source is assembler-accepted, not executed: a bounded analysis
	// failure remains Context at every final public consumer.
	arm64PrivateDataContext(t, source)
}

func TestARM64PrivateDataNumericIntervalsContainMachineValues(t *testing.T) {
	for _, width := range []uint{32, 64} {
		for low := uint64(0); low < 32; low++ {
			for high := low; high < 32; high++ {
				for count := uint64(0); count < 128; count++ {
					for _, left := range []bool{false, true} {
						interval := arm64PrivateDataShift(arm64PoolInterval{low, high}, arm64PoolInterval{count, count + 3}, left, width)
						for value := low; value <= high; value++ {
							for shift := count; shift <= count+3; shift++ {
								actual := value >> (shift % uint64(width))
								if left {
									actual = value << (shift % uint64(width))
									if width == 32 {
										actual &= math.MaxUint32
									}
								}
								if actual < interval.low || actual > interval.high {
									t.Fatalf("shift width=%d range=[%d,%d] count=%d actual=%d bound=%v", width, low, high, count, actual, interval)
								}
							}
						}
					}
				}
			}
		}
	}
	for _, values := range [][2]uint64{{0, math.MaxUint64}, {17, 24}, {255, 257}, {math.MaxUint32 - 1, math.MaxUint32}, {math.MaxUint64 - 2, math.MaxUint64}} {
		before := arm64PrivateDataNumber(arm64PoolInterval{values[0], values[0]})
		after := arm64PrivateDataNumber(arm64PoolInterval{values[1], values[1]})
		joined := arm64PrivateDataUnion(before, after, true)
		if joined.interval.low > values[0] || joined.interval.high < values[1] {
			t.Fatalf("widening excluded input: %v", joined)
		}
	}
}
