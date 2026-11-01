package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const x86FixupOriginalSourceSHA = "42757d53a686c410e0c26dd1a0b3fc046098d5b96a431553e3604bcdbf52703c"

const x86FixupRuntimeDeclaration = `func fixupimmsemantics(out *[289]byte,
	src32 *[16]uint32, table32 *[16]uint32, old32 *[16]uint32,
	src64 *[8]uint64, table64 *[8]uint64, old64 *[8]uint64, mask uint64)`

func x86FixupOriginalRuntimeSource(t *testing.T) string {
	t.Helper()
	source := x86X87FunctionLiteral(t, "amd64_lower_fixupimm_test.go", "TestAMD64FixupImmediateRuntimeSemantics", "source")
	if actual := fmt.Sprintf("%x", sha256.Sum256([]byte(source))); actual != x86FixupOriginalSourceSHA {
		t.Fatal("complete original FIXUPIMM source changed", actual)
	}
	return source
}

// Table response 0000 retains the active old DEST even with zero masking.
// Supply the old32 input expected by the unchanged independent C reference;
// the complete historical source remains an independent Context negative.
func x86FixupRuntimeSource(t *testing.T, original string) string {
	t.Helper()
	if actual := fmt.Sprintf("%x", sha256.Sum256([]byte(original))); actual != x86FixupOriginalSourceSHA {
		t.Fatal("foreign source acquired FIXUPIMM runtime fixture transport", actual)
	}
	const instruction = "\tVFIXUPIMMPS.Z $0, Z0, Z1, K1, Z3\n"
	if strings.Count(original, instruction) != 1 {
		t.Fatal("complete FIXUPIMM runtime lost its unique old32 destination consumer")
	}
	return strings.Replace(original, instruction, "\tVMOVDQU32 0(DX), Z3\n"+instruction, 1)
}

func TestX86FixupRuntimeOriginalSourceRequiresOldDestination(t *testing.T) {
	source := x86FixupOriginalRuntimeSource(t)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, x86FixupRuntimeDeclaration,
				"amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("uninitialized active old DEST acquired a numerical result", err)
			}
		})
	}
}

func TestX86FixupRuntimeInputMatchesIndependentOldDestinationReference(t *testing.T) {
	original := x86FixupOriginalRuntimeSource(t)
	source := x86FixupRuntimeSource(t, original)
	// Check the complete actual program before invoking any translator API.
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, x86FixupRuntimeDeclaration,
				"amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("actual runtime input does not provide the old32 required by its independent C reference", err)
			}
		})
	}
}

func TestX86FixupCorrectedRuntimeCompleteThreeAPITargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	original := x86FixupOriginalRuntimeSource(t)
	source := x86FixupRuntimeSource(t, original)
	const load = "\tVMOVDQU32 0(DX), Z3\n"
	if strings.Count(source, load) != 1 || strings.Replace(source, load, "", 1) != original {
		t.Fatal("runtime repair changed more than the unique old32 input load")
	}
	// These are complete public-program objects, not executed native semantics.
	for _, triple := range []string{
		"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, x86FixupRuntimeDeclaration,
						"amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("corrected complete FIXUPIMM program did not translate", err)
					}
					for _, optimize := range []bool{false, true} {
						t.Run(fmt.Sprintf("IR_O2=%t", optimize), func(t *testing.T) {
							input := ir
							if optimize {
								input = x86DwordProductIROptimize(t, ir)
							}
							x86PackedStringCompileObject(t, llc, triple, input, "-O0")
						})
					}
				})
			}
		})
	}
}

func TestX86FixupImmediateZeroingStillReadsOldActiveDestination(t *testing.T) {
	var directory strings.Builder
	directory.WriteString("TEXT fixupoldinputs(SB),$0-0\n")
	var rows []struct {
		name, instruction string
		active            int
	}
	for _, member := range go127FixupImmediateSpecs() {
		banks := []string{"X", "Y", "Z"}
		if member.scalar {
			banks = banks[:1]
		}
		for _, bank := range banks {
			width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
			active := width
			if member.scalar {
				active = member.laneBits / 8
			}
			for _, mode := range []string{"plain", "merge", "zero"} {
				op, mask := member.op, ""
				if mode != "plain" {
					mask = ", K1"
				}
				if mode == "zero" {
					op += ".Z"
				}
				instruction := fmt.Sprintf("%s $0, %s0, %s1%s, %s2", op, bank, bank, mask, bank)
				fmt.Fprintf(&directory, "\t%s\n", instruction)
				rows = append(rows, struct {
					name, instruction string
					active            int
				}{member.op + "/" + bank + "/" + mode, instruction, active})
			}
		}
	}
	directory.WriteString("\tRET\n")
	// Go's full four-name, eight-width register directory is independent of the
	// result model. Zeroing applies to inactive lanes, not table response 0000.
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", directory.String())
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction)
			state := x86FloatingHelperInitializedState()
			before := state.clone()
			if accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, "amd64", true); !accepted || !known {
				t.Fatal("complete old destination lost its initialized transfer")
			}
			if !reflect.DeepEqual(state, before) {
				t.Fatal("FIXUPIMM changed independent inputs, FLAGS, DF, pointers or upper-byte knowledge")
			}
			for missing := 0; missing < row.active; missing++ {
				state = before.clone()
				state.writeVector(2, 64, state.vectorBytes(2)&^(uint64(1)<<uint(missing)), false)
				initial := state.clone()
				if accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, "amd64", true); accepted || !known ||
					!reflect.DeepEqual(state, initial) {
					t.Fatal("missing active DEST byte was invented or failure partly changed state", missing)
				}
			}
		})
	}
}
