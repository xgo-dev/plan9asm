package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This is the frozen, pre-sharing set operation, not a second source proof.
// Tests compare complete token maps, including unknown and affine identities.
func arm64ControlUnionReference(left, right arm64ControlValue) arm64ControlValue {
	return arm64ControlFromMap(arm64ControlFrozenUnion(arm64ControlMap(left), arm64ControlMap(right)))
}

func arm64ControlSharingState(targets int) *arm64ControlState {
	value := arm64ControlFromMap(make(map[string]bool, targets+1))
	value = arm64ControlSetToken(value, "", true)
	for index := 0; index < targets; index++ {
		value = arm64ControlSetToken(value, fmt.Sprintf("label:continuation_%d", index), true)
	}
	state := &arm64ControlState{
		regs:    make(map[Reg]arm64ControlValue),
		memory:  make(map[string]arm64ControlValue),
		escaped: value,
	}
	for index := 0; index < 31; index++ {
		state.regs[Reg(fmt.Sprintf("R%d", index))] = value
	}
	state.regs[SP] = arm64ControlFromMap(map[string]bool{"sp:0": true})
	state.memory["sp:0"] = value
	return state
}

func TestARM64ControlStableMergeDoesNotCopyTargetSets(t *testing.T) {
	state := arm64ControlSharingState(256)
	other := state.clone()
	before := state.clone()
	allocations := testing.AllocsPerRun(10, func() {
		if state.merge(other) {
			t.Fatal("an equal predecessor changed the control proof")
		}
	})
	if !reflect.DeepEqual(state, before) {
		t.Fatal("stable merge changed complete state")
	}
	if allocations != 0 {
		t.Fatalf("stable merge copied unchanged target sets: %.0f allocations per merge", allocations)
	}
}

func TestARM64ControlSharedUnionMatchesCompleteReference(t *testing.T) {
	tokens := []string{"", "label:caller", "label:local", "code-derived:", "sp:0", "fp:8"}
	values := []arm64ControlValue{nil, {}}
	for mask := 0; mask < 1<<len(tokens); mask++ {
		value := arm64ControlFromMap(make(map[string]bool))
		for index, token := range tokens {
			if mask&(1<<index) != 0 {
				value = arm64ControlSetToken(value, token, true)
			}
		}
		values = append(values, value)
	}
	values = append(values, arm64ControlFromMap(map[string]bool{"label:local": false}), arm64ControlFromMap(map[string]bool{"sp:0": false, "fp:8": true}))
	for leftIndex, left := range values {
		for rightIndex, right := range values {
			beforeLeft := arm64ControlCopyForTest(left)
			beforeRight := arm64ControlCopyForTest(right)
			got := arm64ControlUnion(left, right)
			want := arm64ControlUnionReference(left, right)
			if !reflect.DeepEqual(arm64ControlMap(got), arm64ControlMap(want)) {
				t.Fatalf("complete union %d/%d differs: got %v, want %v", leftIndex, rightIndex, got, want)
			}
			if !reflect.DeepEqual(arm64ControlMap(left), arm64ControlMap(beforeLeft)) || !reflect.DeepEqual(arm64ControlMap(right), arm64ControlMap(beforeRight)) {
				t.Fatalf("union %d/%d changed a predecessor", leftIndex, rightIndex)
			}
			derived := arm64ControlWithToken(got, "new-derived-witness")
			if !arm64ControlHas(derived, "new-derived-witness") || arm64ControlHas(got, "new-derived-witness") ||
				!reflect.DeepEqual(arm64ControlMap(left), arm64ControlMap(beforeLeft)) || !reflect.DeepEqual(arm64ControlMap(right), arm64ControlMap(beforeRight)) {
				t.Fatalf("copy-on-write %d/%d modified a published witness", leftIndex, rightIndex)
			}
		}
	}
}

func arm64ControlCopyForTest(value arm64ControlValue) arm64ControlValue {
	return arm64ControlFromMap(arm64ControlMap(value))
}

func TestARM64ControlSharedValuesDoNotMutatePredecessors(t *testing.T) {
	caller := arm64ControlFromMap(map[string]bool{"label:caller": true})
	original := &arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R10": caller, "F0": caller,
		},
		memory: map[string]arm64ControlValue{"sp:0": caller},
	}
	for _, instruction := range []string{
		"MOVW R10,R11", "MUL R10,R10,R11", "EOR R10,R10,R11",
		"MOVW (RSP),R11", "VLD1 (RSP),[V0.B16]",
		"VST1 [V0.B16],16(RSP)",
	} {
		t.Run(instruction, func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT sharing(SB),4,$32-0\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			before := arm64ControlCopyForTest(caller)
			state := original.clone()
			ins := file.Funcs[0].Instrs[1]
			state.transfer(ins, arm64ControlOp(ins), false, nil)
			if !reflect.DeepEqual(arm64ControlMap(caller), arm64ControlMap(before)) || arm64ControlHas(original.regs["R10"], "code-derived:") || arm64ControlHas(original.regs["F0"], "code-derived:") || arm64ControlHas(original.memory["sp:0"], "code-derived:") {
				t.Fatalf("instruction %q mutated an original reaching definition: %v", instruction, original)
			}
		})
	}
}

func arm64ControlSharingCFG(calls int) (Func, error) {
	var source strings.Builder
	source.WriteString("TEXT controlFanout(SB),516,$0-0\nMOVD R30,R19\n")
	for index := 0; index < calls; index++ {
		fmt.Fprintf(&source, "call_%d:\nCALL helper\n", index)
	}
	source.WriteString("done:\nMOVD R19,R30\nRET\nhelper:\nRET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		return Func{}, err
	}
	return file.Funcs[0], nil
}

func arm64ControlSharingContext(fn Func) *arm64Ctx {
	return &arm64Ctx{
		blocks:           arm64SplitBlocks(fn),
		normalizedSource: fn,
		sig:              FuncSig{Name: "controlFanout", Ret: Void},
		resolve:          func(name string) string { return name },
	}
}

func TestARM64ControlSharingFirstPartyCFGCompleteTargets(t *testing.T) {
	const calls = 32
	fn, err := arm64ControlSharingCFG(calls)
	if err != nil {
		t.Fatal(err)
	}
	ctx := arm64ControlSharingContext(fn)
	if err := ctx.prepareLocalControl(); err != nil {
		t.Fatal(err)
	}
	helper := len(ctx.blocks) - 1
	targets, err := ctx.localControlTargets(helper)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != calls {
		t.Fatalf("helper lost a reaching continuation: got %d, want %d: %v", len(targets), calls, targets)
	}
	for index, reachable := range ctx.localControl.reachable {
		if !reachable {
			t.Fatalf("first-party block %d disappeared from the CFG", index)
		}
	}
}

func TestARM64ControlSharingOriginalGoAndLLVMObjects(t *testing.T) {
	fn, err := arm64ControlSharingCFG(32)
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, instruction := range fn.Instrs {
		source.WriteString(instruction.Raw + "\n")
	}
	// These common scalar/control forms deliberately consume the actual
	// selected SDK on both lanes, not a current-table-only early-return helper.
	goAssemblerOracleOutput(t, "arm64", source.String(), "", true)
	t.Logf("actual Go source-object witness %x", sha256.Sum256([]byte(source.String())))
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(&File{Arch: ArchARM64, Funcs: []Func{fn}}, Options{
				Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"controlFanout": {Name: "controlFanout", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "control-sharing.ll", "control-sharing.o", ir)
		})
	}
}

func TestARM64ControlSharingFrozenReferenceReceipts(t *testing.T) {
	for _, calls := range []int{16, 32, 64} {
		t.Run(fmt.Sprintf("calls_%d", calls), func(t *testing.T) {
			fn, err := arm64ControlSharingCFG(calls)
			if err != nil {
				t.Fatal(err)
			}
			ctx := arm64ControlSharingContext(fn)
			if err := ctx.prepareLocalControl(); err != nil {
				t.Fatal(err)
			}
			// JSON does not support array-valued map keys. Preserve every
			// block/instruction entry in deterministic original CFG order.
			type point struct {
				Block, Instruction  int
				Before, Stack, Link arm64ControlValue
			}
			var points []point
			for block, body := range ctx.blocks {
				for instruction := range body.instrs {
					key := [2]int{block, instruction}
					points = append(points, point{block, instruction,
						ctx.localControl.before[key], ctx.localControl.stackBefore[key], ctx.localControl.linkBefore[key]})
				}
			}
			receipt := struct {
				Original  Func
				Reachable []bool
				Outer     string
				AutoFrame bool
				Points    []point
			}{fn, ctx.localControl.reachable, ctx.localControl.outer, ctx.localControl.autoFrame, points}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("complete-control-receipt %s", encoded)
			ir, err := Translate(&File{Arch: ArchARM64, Funcs: []Func{fn}}, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"controlFanout": {Name: "controlFanout", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("complete-ir-receipt %x", sha256.Sum256([]byte(ir)))
		})
	}
}

func BenchmarkARM64ControlStableMerge(b *testing.B) {
	for _, targets := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("targets_%d", targets), func(b *testing.B) {
			state := arm64ControlSharingState(targets)
			other := state.clone()
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if state.merge(other) {
					b.Fatal("stable predecessor changed state")
				}
			}
		})
	}
}

func BenchmarkARM64ControlFirstPartyCFG(b *testing.B) {
	for _, calls := range []int{16, 32, 64} {
		b.Run(fmt.Sprintf("calls_%d", calls), func(b *testing.B) {
			fn, err := arm64ControlSharingCFG(calls)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if err := arm64ControlSharingContext(fn).prepareLocalControl(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
