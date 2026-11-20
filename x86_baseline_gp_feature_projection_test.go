package plan9asm

import (
	"reflect"
	"sort"
	"testing"
)

func x86CheckBaselineGPFeatureProjection(t *testing.T, arch string, instructions []Instr, want string) {
	t.Helper()
	before := cloneX86ReplayInstrs(instructions)
	if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: instructions}); got != want {
		t.Fatalf("feature projection = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(instructions, before) {
		t.Fatal("feature inference changed source operands or private metadata")
	}
}

func TestX86BaselineGPFeatureFamiliesRetainEmptyProjection(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		// These independent inventories already own complete Go grammar tests.
		// This projection does not establish initialized values or source roles.
		var rows []string
		for _, form := range x86LockScalarOracleForms(arch) {
			rows = append(rows, form.text)
		}
		for alias := range x86ConditionalBranchAliasOracle() {
			rows = append(rows, alias+" feature_done")
		}
		rows = append(rows, "LEAW 8(AX)(BX*2),CX", "LEAL 8(AX)(BX*2),CX",
			"JMP feature_done", "CALL helper(SB)", "RET")
		if arch == "amd64" {
			rows = append(rows, "LEAQ 8(AX)(BX*2),CX")
		}
		sort.Strings(rows)
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row)
				wantFast := instruction.Op != OpCALL // The external SB target keeps its original route.
				if got := x86BaselineGPFeatureInstruction(instruction.Op, &instruction, arch); got != wantFast {
					t.Fatal("existing baseline family lost its conservative feature route", got, wantFast)
				}
				x86CheckBaselineGPFeatureProjection(t, arch, []Instr{instruction}, "")
				x86CheckBaselineGPFeatureProjection(t, arch, []Instr{
					instruction, x86ScalarLaneInstruction(t, "PSHUFB X0,X1"),
				}, "+ssse3")
			})
		}
	}
}

func TestX86BaselineGPFeatureProjectionKeepsISAAndVectorRequirements(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ source, want string }{
			{"MOVBEL (AX),BX", "+movbe"},
			// POPCNT remains with its existing portable/native family owner;
			// an empty feature string does not make it a baseline GP candidate.
			{"POPCNTL AX,BX", ""},
			{"LZCNTL AX,BX", "+lzcnt"},
			{"ANDNL AX,BX,CX", "+bmi"},
			{"BLSIL AX,BX", "+bmi"},
			{"BEXTRL AX,BX,CX", "+bmi"},
			{"MULXL AX,BX,CX", "+bmi2"},
			{"SHLXL AX,BX,CX", "+bmi2"},
			{"ADCXL AX,BX", "+adx"},
			{"ADOXL AX,BX", "+adx"},
			{"XBEGIN 1(PC)", "+rtm"},
			{"PSHUFB X0,X1", "+ssse3"},
			{"VCVTSD2SS X0,X1,X2", "+avx"},
			{"MOVQ X0,X1", ""},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row.source)
				if x86BaselineGPFeatureInstruction(instruction.Op, &instruction, arch) {
					t.Fatal("ISA-dependent, vector or MOV input entered the baseline route")
				}
				instructions := []Instr{
					x86ScalarLaneInstruction(t, "ADDL AX,BX"),
					x86ScalarLaneInstruction(t, "LEAL 8(AX)(BX*2),CX"),
					x86ScalarLaneInstruction(t, "JEQ feature_done"),
					instruction,
					x86ScalarLaneInstruction(t, "RET"),
				}
				x86CheckBaselineGPFeatureProjection(t, arch, instructions, row.want)
			})
		}
	}
}

func TestX86BaselineGPFeatureProjectionRetainsSourceMetadata(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{"ADDL AX,BX", "LEAL 8(AX)(BX*2),CX", "JEQ feature_done"} {
			for _, change := range []struct {
				name     string
				apply    func(*Instr)
				physical bool
			}{
				{"encoded", func(i *Instr) { i.x86Encoded = true }, true},
				{"raw-origin", func(i *Instr) {
					i.x86SourceRaw = &x86SourceRawInstruction{op: i.Op, args: append([]Operand(nil), i.Args...)}
				}, true},
				{"raw-return", func(i *Instr) { i.x86RawNearReturn = &x86RawNearReturnForm{} }, true},
				{"address-size", func(i *Instr) { i.x86AddressBits = 16 }, true},
				{"unbound-address", func(i *Instr) { i.x86UnboundAddressOverride = true }, true},
				{"segment", func(i *Instr) { i.x86SegmentPrefix = 0x64 }, true},
				{"numerical-read", func(i *Instr) { i.x86NumericalRead = &x86NumericalReadCertificate{} }, false},
				{"SDK-literal", func(i *Instr) { i.x86SDKLiteral = &x86SDKLiteralCertificate{} }, false},
				{"source-stack", func(i *Instr) { i.x86SourceStackFP = map[int]int64{0: 0} }, false},
				{"caller-memory", func(i *Instr) { i.x86CallerMemory = map[int]x86CallerMemoryAccess{0: {}} }, false},
				{"private-memory", func(i *Instr) { i.x86FixedLocalMemory = map[int]x86FixedLocalAccess{0: {}} }, false},
				{"native-memory", func(i *Instr) { i.x86FixedLocalMemory = map[int]x86FixedLocalAccess{0: {nativeInput: true}} }, false},
			} {
				t.Run(arch+"/"+row+"/"+change.name, func(t *testing.T) {
					instruction := x86ScalarLaneInstruction(t, row)
					change.apply(&instruction)
					if got := x86BaselineGPFeatureInstruction(instruction.Op, &instruction, arch); got == change.physical {
						t.Fatal("feature routing confused physical encoding with independent source metadata", got)
					}
					// Deliberately empty certificates cannot supply source facts.
					// Inference must leave them intact for their actual consumers.
					x86CheckBaselineGPFeatureProjection(t, arch, []Instr{
						instruction, x86ScalarLaneInstruction(t, "PSHUFB X0,X1"),
					}, "+ssse3")
				})
			}
		}
	}
}

func TestX86BaselineGPFeatureProjectionDoesNotAcceptMalformedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			lea    bool
		}{
			{"ADDL AX", false},
			{"ADDL.Z AX,BX", false},
			{"ADDL X0,BX", false},
			{"ADDL (AX),(BX)", false},
			{"LEAL AX,BX", true},
			{"LEAL (AX),X0", true},
			{"LEAL.Z (AX),BX", true},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row.source)
				if x86BaselineGPFeatureInstruction(instruction.Op, &instruction, arch) {
					t.Fatal("malformed syntax entered the baseline route")
				}
				grammarError := func() error {
					if row.lea {
						_, err := x86LEAOperandWidth(instruction, arch)
						return err
					}
					_, known, err := x86LockScalarRMWProperties(instruction.Op, instruction, arch)
					if !known {
						t.Fatal("malformed control lost its family registration")
					}
					return err
				}
				before := grammarError()
				if before == nil {
					t.Fatal("malformed control is accepted by its existing family grammar")
				}
				x86CheckBaselineGPFeatureProjection(t, arch, []Instr{
					instruction, x86ScalarLaneInstruction(t, "PSHUFB X0,X1"),
				}, "+ssse3")
				if after := grammarError(); after == nil || before.Error() != after.Error() {
					t.Fatal("feature inference changed the original grammar rejection", before, after)
				}
			})
		}
		for _, source := range []string{"RET AX", "JMP X0", "JEQ $2,feature_done", "JEQ 1(PC)", "JCXZQ feature_done"} {
			t.Run(arch+"/original-route/"+source, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, source)
				if source == "JEQ 1(PC)" {
					// The text parser already rejects this address. Also retain
					// the boundary for callers constructing an Instr directly.
					instruction.Args[0].Mem.Index, instruction.Args[0].Mem.Scale = AX, 1
				}
				if x86BaselineGPFeatureInstruction(instruction.Op, &instruction, arch) {
					t.Fatal("invalid or separately owned branch role entered the baseline route")
				}
				x86CheckBaselineGPFeatureProjection(t, arch, []Instr{instruction}, "")
			})
		}
	}
}
