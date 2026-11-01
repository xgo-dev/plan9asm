package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86OfficialEVEXBinaryAlwaysOld(opcode string) bool {
	switch opcode {
	case "VPERMB", "VPERMW", "VPMULTISHIFTQB", "VPROLVD", "VPROLVQ", "VPRORVD", "VPRORVQ":
		return false
	}
	return true // The independent official scope binds exactly 31 members.
}

func TestX86OfficialEVEXBinaryRemainderInitializedThreeAPIsObjects(t *testing.T) {
	for _, role := range []struct {
		name          string
		alwaysOld     bool
		rows, formats int
		assembly      func([]x86OfficialPackedCase) (string, string)
	}{
		{"two-source", false, 42, 171, x86OfficialPackedAssembly},
		{"always-old-destination", true, 144, 594, x86OfficialFMA3Assembly},
	} {
		t.Run(role.name, func(t *testing.T) {
			build := func(legacy goasmrules.X86LegacyCatalog, avx []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
				rows, err := goasmrules.X86PackedEVEXBinaryRemainderRows(legacy, avx)
				var selected []goasmrules.X86PackedBinaryRow
				for _, row := range rows {
					if x86OfficialEVEXBinaryAlwaysOld(row.Opcode) == role.alwaysOld {
						selected = append(selected, row)
					}
				}
				return selected, err
			}
			// Reuse the existing initialized transports and complete original
			// Go-byte/three-API/object driver. Native semantics stay separate.
			x86OfficialPackedRowsObjectsUsing(t, build, role.rows, role.formats, 0, role.assembly)
		})
	}
}

func TestX86OfficialEVEXBinaryInitializerMatchesExistingTypedRoles(t *testing.T) {
	const members = `VPDPBUSD VPDPBUSDS VPDPWSSD VPDPWSSDS VPMADD52HUQ VPMADD52LUQ
		VPERMB VPERMW VPERMI2B VPERMI2W VPERMI2D VPERMI2Q VPERMI2PS VPERMI2PD
		VPERMT2B VPERMT2W VPERMT2D VPERMT2Q VPERMT2PS VPERMT2PD VPMULTISHIFTQB
		VPROLVD VPROLVQ VPRORVD VPRORVQ VPSHLDVW VPSHLDVD VPSHLDVQ VPSHRDVW VPSHRDVD VPSHRDVQ`
	ordinary, numericalOld := 0, 0
	for _, opcode := range strings.Fields(members) {
		alwaysOld := x86OfficialEVEXBinaryAlwaysOld(opcode)
		if alwaysOld {
			numericalOld++
		} else {
			ordinary++
		}
		for _, mode := range []string{"plain", "merge", "zero"} {
			op, mask := opcode, ""
			if mode != "plain" {
				mask = "K1,"
			}
			if mode == "zero" {
				op += ".Z"
			}
			instruction := op + " X16,X17," + mask + "X18"
			ins := x86ScalarLaneInstruction(t, instruction)
			needsOld := alwaysOld || mode == "merge"
			if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64"); known {
				if err != nil {
					t.Fatal(instruction, err)
				}
				writes := 0
				for _, operand := range effect.operands {
					if operand.write {
						writes++
						if operand.index != len(ins.Args)-1 || operand.read != needsOld || operand.width != 16 {
							t.Fatal("initializer role differs from existing typed effect", instruction, operand)
						}
					}
				}
				if writes != 1 {
					t.Fatal("typed effect lost the actual destination", instruction, writes)
				}
			} else if form, old, known, err := x86FixedVectorValueProperties(ins, "amd64"); !known || err != nil ||
				old != alwaysOld || form.destination != len(ins.Args)-1 || form.byteWidth != 16 {
				t.Fatal("initializer role differs from existing indexed-permute form", instruction, old, known, err)
			}
			fixture := []x86OfficialPackedCase{{witness: goasmrules.X86PackedBinaryWitness{
				Instruction: instruction, Generation: "evex", Width: 128,
				First: "X16", Second: "X17", Destination: "X18", Masked: mode != "plain", Zeroing: mode == "zero",
			}}}
			assembly, oldLoad := x86OfficialPackedAssembly, "VMOVUPS (BX),X18\n"
			if alwaysOld {
				assembly, oldLoad = x86OfficialFMA3Assembly, "VMOVUPS (AX),X18\n"
			}
			source, _ := assembly(fixture)
			if strings.Contains(source, oldLoad) != needsOld || !strings.Contains(source, instruction+"\n") {
				t.Fatal("initializer fabricated or omitted a numerical old-destination input", instruction, source)
			}
		}
	}
	if ordinary != 7 || numericalOld != 24 {
		t.Fatal("independent input-role partition changed", ordinary, numericalOld)
	}
}

func TestX86OfficialEVEXBinaryZeroingCannotSupplyNumericalOldDestination(t *testing.T) {
	// One original named witness per semantic role: integer dot, IFMA, I2
	// indices, T2 table and both variable funnel directions. Existing families
	// continue to own their complete input-byte and native-semantic matrices.
	for _, opcode := range []string{"VPDPBUSD", "VPMADD52LUQ", "VPERMI2D", "VPERMT2D", "VPSHLDVD", "VPSHRDVQ"} {
		t.Run(opcode, func(t *testing.T) {
			instruction := opcode + ".Z X16,X17,K1,X18"
			source, declaration := x86FMA3InitializedAxisSource("amd64", "OldEVEX", instruction)
			missing := strings.Replace(source, "VMOVUPS (AX),X18\n", "", 1)
			if source == missing {
				t.Fatal("negative did not remove the actual old-destination initialization")
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("initialized numerical old-destination control rejected", err)
					}
					ir, err = x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("zeroing borrowed the absent numerical old destination", err)
					}
				})
			}
		})
	}
}
