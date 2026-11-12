package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86ApproximateMathTestInstruction(member approximateMathTestSpec, source, mode, control string) string {
	bank, operands := "Z", source+","
	if member.scalar {
		bank, operands = "X", operands+"X17,"
	}
	op := member.op + control
	if mode != "plain" {
		operands += "K1,"
		if mode == "zero" {
			op += ".Z"
		}
	}
	return op + " " + operands + bank + "18"
}

func TestX86ApproximateMathCompleteTypedOfficialRows(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	members := make(map[string]approximateMathTestSpec)
	for _, member := range go127ApproximateMathSpecs() {
		members[member.op] = member
	}
	rows, formats, seen := 0, 0, make(map[string]int)
	for _, row := range avx {
		member, selected := members[row.Opcode]
		if !selected {
			continue
		}
		rows++
		seen[member.op]++
		modes := []string{"plain"}
		if row.RowIndex == 1 {
			modes = []string{"merge", "zero"}
		}
		bank := "Z"
		if member.scalar {
			bank = "X"
		}
		for _, mode := range modes {
			for _, input := range []struct{ source, control string }{
				{bank + "16", ""}, {bank + "16", ".SAE"}, {"(AX)", ""}, {"(AX)", ".BCST"},
			} {
				if member.scalar && input.control == ".BCST" {
					continue
				}
				formats++
				instruction := x86ApproximateMathTestInstruction(member, input.source, mode, input.control)
				t.Run(instruction, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, instruction)
					f, known, err := x86FloatingHelperProperties(ins, "amd64")
					width, tuple := 64, 64
					if member.scalar {
						width = 16
					}
					if member.scalar || input.control == ".BCST" {
						tuple = member.laneBits / 8
					}
					if !known || err != nil || f.byteWidth != width || f.spec.bits != member.laneBits ||
						f.memory >= 0 && f.memoryBytes != tuple || f.properties.sae != (input.control == ".SAE") {
						t.Fatal("complete original approximation row has no shared typed carrier/tuple/control", f, known, err)
					}
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
					if !known || err != nil || !effect.requiresResultProof || effect.vector.upperWrite != x86TypedVectorUpperZero ||
						effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 || len(effect.operands) != len(ins.Args) {
						t.Fatal("approximation lacks complete typed inputs/outputs or preserved FLAGS", effect, known, err)
					}
					for _, operand := range effect.operands {
						if operand.index == f.destination && operand.read != (mode == "merge") {
							t.Fatal("zeroing/plain form borrowed an old destination", operand)
						}
						if member.scalar && operand.index == f.second &&
							operand.requiredBytes != 0xffff&^x86CallerVectorByteMask(int64(member.laneBits/8)) {
							t.Fatal("scalar upper-copy acquired an unused low arithmetic input", operand)
						}
					}
				})
			}
		}
	}
	if rows != 20 || formats != 108 || len(seen) != 10 {
		t.Fatal("complete original approximation namespace/row/control closure changed", rows, formats, seen)
	}
	for name, count := range seen {
		if count != 2 {
			t.Fatal("unmasked/masked source row missing", name, count)
		}
	}
}

func TestX86ApproximateMathSparseNumericalInputsAndPreservedState(t *testing.T) {
	for _, member := range go127ApproximateMathSpecs() {
		bank, width, active := "Z", 64, 64
		if member.scalar {
			bank, width, active = "X", 16, member.laneBits/8
		}
		for _, mode := range []string{"plain", "merge", "zero"} {
			ins := x86ScalarLaneInstruction(t, x86ApproximateMathTestInstruction(member, bank+"16", mode, ""))
			for _, mutation := range []string{"complete", "source", "mask", "old-destination", "upper-low", "upper-high"} {
				if mutation == "mask" && mode == "plain" || strings.HasPrefix(mutation, "upper-") && !member.scalar {
					continue
				}
				t.Run(member.op+"/"+mode+"/"+mutation, func(t *testing.T) {
					before := x86FloatingHelperInitializedState()
					switch mutation {
					case "source":
						before.writeVector(16, 64, ^uint64(1), false)
					case "mask":
						before.masks[1] = false
					case "old-destination":
						before.writeVector(18, 64, 0, false)
					case "upper-low":
						before.writeVector(17, 64, ^uint64(1), false)
					case "upper-high":
						before.writeVector(17, 64, ^(uint64(1) << uint(active)), false)
					}
					state := before.clone()
					accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, "amd64", true)
					fail := mutation == "source" || mutation == "mask" || mutation == "old-destination" && mode == "merge"
					if fail {
						if accepted || !known || !reflect.DeepEqual(state, before) {
							t.Fatal("missing active source/mask/merge changed or authorized the state", accepted, known)
						}
						return
					}
					want := before.clone()
					defined := ^uint64(0)
					if mutation == "upper-high" {
						defined &^= uint64(1) << uint(active)
					}
					want.writeVector(18, width, defined, false)
					if !accepted || !known || !reflect.DeepEqual(state, want) {
						t.Fatal("sparse copied bytes, zero upper aliases or unrelated FLAGS/DF/storage changed", accepted, known)
					}
				})
			}
		}
	}
}

func TestX86ApproximateMathInitializedNativeOperandsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	for index, member := range go127ApproximateMathSpecs() {
		instruction := x86ApproximateMathTestInstruction(member, "(AX)", "zero", "")
		if !member.scalar {
			instruction = x86ApproximateMathTestInstruction(member, "(AX)", "zero", ".BCST")
		}
		body, declaration := x86PackedAbsSignInitializedInstruction(index, instruction, "amd64", [3]int{16, 17, 18})
		// Zeroing has no old destination input; the whole output remains observable.
		body = strings.Replace(body, "VMOVDQU64 (CX),Z18\n", "", 1)
		// The memory instruction supplies its own active source. Do not
		// pre-read the same address through an unused register initializer.
		body = strings.Replace(body, "VMOVDQU64 (AX),Z16\n", "", 1)
		source.WriteString(body)
		declarations.WriteString(declaration + "\n")
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
		if err != nil || ir == "" {
			t.Fatal("fully initialized approximation source did not close its typed proof", api, err)
		}
		for _, member := range go127ApproximateMathSpecs() {
			found := false
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, "asm sideeffect") && strings.Contains(line, strings.ToLower(member.op)+" ") {
					found = strings.Contains(line, "*m") && strings.Contains(line, "~{memory}") && strings.Contains(line, "~{fpsr}") &&
						strings.Contains(line, fmt.Sprintf("elementtype([%d x i8])", member.laneBits/8))
				}
			}
			if !found {
				t.Fatal("native instruction lost its actual scalar/broadcast memory operand or FX-state clobber", member.op)
			}
		}
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, level)
		}
	}
}

func TestX86ApproximateMathVoidCannotInventActiveInputs(t *testing.T) {
	for _, member := range go127ApproximateMathSpecs() {
		bank := "Z"
		if member.scalar {
			bank = "X"
		}
		instruction := x86ApproximateMathTestInstruction(member, bank+"16", "zero", "")
		source := "TEXT Missing(SB),4,$0-0\n" + instruction + "\nRET\n"
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, source, "func Missing()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Void supplied unavailable source/upper/mask numerical inputs", member.op, api, err)
			}
		}
	}
}
