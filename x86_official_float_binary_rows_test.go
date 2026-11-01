package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialAVXFloatBinaryRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86AVXFloatBinaryRows, 132, 684, 0)
}

func TestX86OfficialFloatBinaryOriginalScalarPPAndSAEBytes(t *testing.T) {
	var cases []x86OfficialPackedCase
	for index, anchor := range []struct {
		instruction, generation, bank string
		encoding                      []byte
	}{
		{"VADDSD X0,X1,X2", "vex", "X", []byte{0xc5, 0xf3, 0x58, 0xd0}},
		{"VADDSS X0,X1,X2", "vex", "X", []byte{0xc5, 0xf2, 0x58, 0xd0}},
		{"VDIVSD.RD_SAE X16,X17,X18", "evex", "X", []byte{0x62, 0xa1, 0xf7, 0x30, 0x5e, 0xd0}},
		{"VMINPD.SAE Z16,Z17,Z18", "evex", "Z", []byte{0x62, 0xa1, 0xf5, 0x50, 0x5d, 0xd0}},
		{"VMINSD.SAE X16,X17,X18", "evex", "X", []byte{0x62, 0xa1, 0xf7, 0x10, 0x5d, 0xd0}},
		{"VMAXSS.SAE.Z X16,X17,K1,X18", "evex", "X", []byte{0x62, 0xa1, 0x76, 0x91, 0x5f, 0xd0}},
	} {
		first, second, destination := anchor.bank+"0", anchor.bank+"1", anchor.bank+"2"
		if anchor.generation == "evex" {
			first, second, destination = anchor.bank+"16", anchor.bank+"17", anchor.bank+"18"
		}
		width := 128
		if anchor.bank == "Z" {
			width = 512
		}
		cases = append(cases, x86OfficialPackedCase{row: fmt.Sprint("independent/float-binary/", index),
			witness: goasmrules.X86PackedBinaryWitness{
				Instruction: anchor.instruction, Generation: anchor.generation, Width: width,
				First: first, Second: second, Destination: destination, Encoding: anchor.encoding,
				Masked: strings.Contains(anchor.instruction, "K1"), Zeroing: strings.Contains(anchor.instruction, ".Z"),
			}})
	}
	source, _ := x86OfficialPackedAssembly(cases)
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("actual original scalar pp or SAE vector length changed", err)
	}
}

func TestX86OfficialFloatBinaryMergeAndZeroingInputs(t *testing.T) {
	for _, opcode := range []string{"VADDPS", "VMULSD", "VMINPS", "VMAXSD"} {
		for _, mode := range []string{"plain", "merge", "zero"} {
			t.Run(opcode+"/"+mode, func(t *testing.T) {
				op, mask := opcode, ""
				if mode != "plain" {
					mask = "K1,"
				}
				if mode == "zero" {
					op += ".Z"
				}
				cases := []x86OfficialPackedCase{{row: "dependency/" + opcode,
					witness: goasmrules.X86PackedBinaryWitness{
						Instruction: op + " X16,X17," + mask + "X18", Generation: "evex", Width: 128,
						First: "X16", Second: "X17", Destination: "X18", Masked: mode != "plain", Zeroing: mode == "zero",
					}}}
				source, declaration := x86OfficialPackedAssembly(cases)
				old := "VMOVUPS (BX),X18\n"
				if strings.Contains(source, old) != (mode == "merge") {
					t.Fatal("ordinary floating fixture acquired FMA's unconditional old-destination input", source)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatal("complete ordinary floating inputs lost their positive continuation", err)
						}
						missing := []string{"VMOVUPS (AX),X16\n", "VMOVUPS (BX),X17\n"}
						if mode == "merge" {
							missing = append(missing, old)
						}
						for _, load := range missing {
							negative := strings.Replace(source, load, "", 1)
							if negative == source {
								t.Fatal("missing-input control did not remove its initialization", load)
							}
							ir, err := x86ScalarFPBitViewAPI(t, negative, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("ordinary floating arithmetic borrowed an absent input or merge destination", load, err)
							}
						}
					})
				}
			})
		}
	}
}
