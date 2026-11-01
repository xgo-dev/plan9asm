package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialFMA3RowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86FMA3Rows, 360, 2028, 0, x86OfficialFMA3Assembly)
}

func x86OfficialFMA3Assembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprintf("FMARow%d", index)
		body, declaration := x86FMA3InitializedAxisSource("amd64", fixture.symbol, fixture.witness.Instruction)
		for offset, instruction := range strings.Split(body, "\n") {
			if instruction == fixture.witness.Instruction {
				fixture.line = line + offset
			}
		}
		source.WriteString(body)
		declarations.WriteString(declaration)
		line += strings.Count(body, "\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialFMA3ScalarTupleAndRoundingGoBytes(t *testing.T) {
	var source strings.Builder
	var cases []x86OfficialPackedCase
	line := 1
	for index, anchor := range []struct {
		instruction string
		encoding    []byte
	}{
		{"VFMADD132SD.RD_SAE X16,X17,X18", []byte{0x62, 0xa2, 0xf5, 0x30, 0x99, 0xd0}},
		{"VFMADD132SS.RU_SAE.Z X16,X17,K1,X18", []byte{0x62, 0xa2, 0x75, 0xd1, 0x99, 0xd0}},
		{"VFNMADD231PS.RN_SAE Z16,Z17,Z18", []byte{0x62, 0xa2, 0x75, 0x10, 0xbc, 0xd0}},
		{"VFNMSUB132PD.RZ_SAE.Z Z16,Z17,K1,Z18", []byte{0x62, 0xa2, 0xf5, 0xf1, 0x9e, 0xd0}},
		{"VFMADD132SD 64(AX),X17,X18", []byte{0x62, 0xe2, 0xf5, 0x00, 0x99, 0x50, 0x08}},
		{"VFMADD132SS 64(AX),X17,X18", []byte{0x62, 0xe2, 0x75, 0x00, 0x99, 0x50, 0x10}},
	} {
		name := fmt.Sprintf("FMAByte%d", index)
		body, _ := x86FMA3InitializedAxisSource("amd64", name, anchor.instruction)
		fixture := x86OfficialPackedCase{
			row: "independent/FMA3/" + anchor.instruction, symbol: name,
			witness: goasmrules.X86PackedBinaryWitness{Instruction: anchor.instruction, Encoding: anchor.encoding},
		}
		for offset, instruction := range strings.Split(body, "\n") {
			if instruction == anchor.instruction {
				fixture.line = line + offset
			}
		}
		cases = append(cases, fixture)
		source.WriteString(body)
		line += strings.Count(body, "\n")
	}
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("actual original Go bytes lost scalar N4/N8 tuple compression or RC fields", err)
	}
}

func TestX86FMA3InitializedAxisSourceOwnsOfficialHighBankOperands(t *testing.T) {
	for _, instruction := range []string{
		"VFMADD132PS X16,X17,X18",
		"VFMADD132PS Y16,Y17,Y18",
		"VFMADD132PS Z16,Z17,Z18",
		"VFMADD132SD.RD_SAE X16,X17,X18",
		"VFMADD132PS.BCST.Z (AX),Z17,K1,Z18",
	} {
		t.Run(instruction, func(t *testing.T) {
			source, _ := x86FMA3InitializedAxisSource("amd64", "OfficialFMA", instruction)
			bank := strings.Split(strings.Fields(instruction)[1], ",")[1][:1]
			for _, register := range []int{16, 17, 18} {
				if !strings.Contains(source, fmt.Sprintf("VMOVUPS (AX),%s%d\n", bank, register)) {
					t.Fatal("official high-bank FMA3 lacks an initialized arithmetic source or old destination", source)
				}
			}
			if !strings.Contains(source, instruction+"\n") || !strings.Contains(source, "VMOVD X18,AX\n") {
				t.Fatal("FMA3 fixture changed the original instruction or its public result continuation", source)
			}
			if !strings.Contains(instruction, "K1") && strings.Contains(source, "KMOVW") {
				t.Fatal("plain FMA3 fixture borrowed an unrelated AVX512 mask", source)
			}
		})
	}
}

func TestX86OfficialFMA3ZeroingStillRequiresOldDestination(t *testing.T) {
	for _, instruction := range []string{
		"VFMADD132PS.Z X0,X1,K1,X2",
		"VFNMADD231SD.Z X0,X1,K1,X2",
	} {
		t.Run(instruction, func(t *testing.T) {
			source, declaration := x86FMA3InitializedAxisSource("amd64", "OldFMA", instruction)
			missing := strings.Replace(source, "MOVUPS (AX),X2\n", "", 1)
			if missing == source {
				t.Fatal("old-destination negative did not remove its independent initialization")
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("independently initialized zeroing FMA3 lost its positive continuation", err)
					}
					ir, err = x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("zeroing supplied the missing FMA3 arithmetic destination", err)
					}
				})
			}
		})
	}
}
