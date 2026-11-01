package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialBitCountConflictRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86PackedBitCountConflictRows, 48, 198, 0, x86OfficialAbsAssembly)
}

func TestX86OfficialBitCountConflictOldDestinationIsOnlyMergeInput(t *testing.T) {
	for _, opcode := range []string{"VPOPCNTD", "VPCONFLICTQ"} {
		for _, zeroing := range []bool{false, true} {
			op := opcode
			if zeroing {
				op += ".Z"
			}
			instruction := op + " X16,K1,X18"
			ins := x86ScalarLaneInstruction(t, instruction)
			form, numericalOld, known, err := x86FixedVectorValueProperties(ins, "amd64")
			if !known || err != nil || numericalOld || form.second != -1 || form.destination != 2 ||
				form.mask != 1 || form.zeroing != zeroing {
				t.Fatal("unary source acquired a numerical old-destination input", instruction, numericalOld, known, err)
			}
			fixtures := []x86OfficialPackedCase{{witness: goasmrules.X86PackedBinaryWitness{
				Instruction: instruction, Generation: "evex", Width: 128,
				First: "X16", Destination: "X18", Masked: true, Zeroing: zeroing,
			}}}
			source, declaration := x86OfficialAbsAssembly(fixtures)
			missing := strings.Replace(source, "VMOVDQU64 (CX),Z18\n", "", 1)
			if source == missing {
				t.Fatal("old-destination mutation did not remove its actual initialization")
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(instruction+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("existing initialized unary transport rejected", err)
					}
					ir, err = x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if zeroing {
						if err != nil || ir == "" {
							t.Fatal("zeroing unary operation borrowed an unnecessary old destination", err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("merging unary operation borrowed its absent old bytes", err)
					}
				})
			}
		}
	}
}
