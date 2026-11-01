package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func amd64RegisterLaneFixture(op string, lane int) string {
	destination := "X0"
	insert := fmt.Sprintf("%s $%d,AX,X0", op, lane)
	if strings.HasPrefix(op, "V") {
		destination = "X1"
		insert += ",X1"
	}
	return fmt.Sprintf("TEXT ·view<ABIInternal>(SB),4,$0-24\nMOVQ BX,X0\n%s\nPEXTRQ $1,%s,CX\nMOVQ %s,AX\nXORQ CX,AX\nRET\n",
		insert, destination, destination)
}

// The explicit register entry has no initialized ABI0 FP fields. This is the
// same seed/insert pattern as the SDK hash routines, without AES or globals.
func TestAMD64RegisterResultScalarLaneThreeAPIs(t *testing.T) {
	for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ"} {
		t.Run(op, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, amd64RegisterLaneFixture(op, 255),
					"func view(value,seed uint64) uint64\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Errorf("%s: register result incorrectly requires ABI0 result storage: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterResultKeepsUnknownInputsAndSourceRoles(t *testing.T) {
	const declaration = "func view(value,seed uint64) uint64\n"
	source := amd64RegisterLaneFixture("PINSRQ", 1)
	for name, bad := range map[string]string{
		"ABI0":             strings.ReplaceAll(source, "<ABIInternal>", ""),
		"unknown input":    strings.ReplaceAll(source, "$1,AX,X0", "$1,R12,X0"),
		"unknown return":   strings.ReplaceAll(source, "RET", "MOVQ R12,AX\nRET"),
		"ABI0 input":       strings.ReplaceAll(source, "MOVQ BX,X0", "MOVQ seed+8(FP),X0"),
		"ABI0 result":      strings.ReplaceAll(source, "RET", "MOVQ AX,ret+16(FP)\nRET"),
		"hidden g":         strings.ReplaceAll(source, "$1,AX,X0", "$1,R14,X0"),
		"hidden closure":   strings.ReplaceAll(source, "$1,AX,X0", "$1,DX,X0"),
		"physical stack":   strings.ReplaceAll(source, "MOVQ BX,X0", "MOVQ (SP),X0"),
		"unbound call":     strings.ReplaceAll(source, "RET", "CALL ·Unknown(SB)\nRET"),
		"path loses value": strings.ReplaceAll(source, "RET", "CMPQ BX,$0\nJE done\nMOVQ R12,AX\ndone:\nRET"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, bad, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: unbound entry/input/result was accepted: %v", api, err)
				}
			}
		})
	}
	t.Run("modeled timestamp", func(t *testing.T) {
		// Its actual AX/DX output is numerical, not an unknown source effect.
		known := strings.ReplaceAll(source, "RET", "RDTSC\nRET")
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, known, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
				t.Errorf("%s: modeled timestamp return rejected: %v", api, err)
			}
		}
	})
}

func TestAMD64RegisterResultIntegerWidthsAndEveryArgumentRegister(t *testing.T) {
	registers := []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}
	for _, width := range []struct{ typ, insert, extract string }{
		{"uint8", "PINSRB", "PEXTRB"}, {"uint16", "PINSRW", "PEXTRW"},
		{"uint32", "PINSRD", "PEXTRD"}, {"uint64", "PINSRQ", "PEXTRQ"},
	} {
		for index, reg := range registers {
			t.Run(fmt.Sprintf("%s/%s", width.typ, reg), func(t *testing.T) {
				parameters := strings.TrimSuffix(strings.Repeat(width.typ+",", index+1), ",")
				declaration := fmt.Sprintf("func view(%s) %s\n", parameters, width.typ)
				source := fmt.Sprintf("TEXT ·view<ABIInternal>(SB),4,$0-80\n%s $0,%s,X0\n%s $0,X0,AX\nRET\n",
					width.insert, reg, width.extract)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Errorf("%s: initialized selected scalar bytes rejected: %v", api, err)
					}
				}
			})
		}
	}
}

func TestAMD64RegisterResultRejectsUnmodeledTransport(t *testing.T) {
	source := amd64RegisterLaneFixture("PINSRQ", 1)
	for _, declaration := range []string{
		"func view(value uint8,seed uint64) uint64", // Unknown upper argument bytes.
		"func view(value uint16,seed uint64) uint64",
		"func view(value uint32,seed uint64) uint64",
		"func view(value *uint64,seed uint64) uint64", // Pointer is not numeric.
		"func view(value [2]uint64,seed uint64) uint64",
		"func view(value float64,seed uint64) uint64",
		"func view(value bool,seed uint64) uint64",
		"func view(value,seed uint64) (uint64,uint64)",
		"func view(value,seed uint64) *uint64",
		"func view(value,seed uint64) bool",
		"func view(" + strings.TrimSuffix(strings.Repeat("uint64,", 10), ",") + ") uint64",
	} {
		t.Run(declaration, func(t *testing.T) {
			pkg := mustGoPackage(t, "registerresult", "package registerresult\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: sig, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unmodeled transport gained register initialization:", err)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("register role escaped into the standalone ABI0 observer:", err)
			}
		})
	}
}
