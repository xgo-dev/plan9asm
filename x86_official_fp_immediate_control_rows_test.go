package plan9asm

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialFloatingImmediateControlRowsInitializedThreeAPIsObjects(t *testing.T) {
	// The existing FMA producer initializes active old DEST even for plain or
	// zero-masked FIXUP, plus scalar upper/data sources. No new producer is needed.
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86FloatingImmediateControlRows, 80, 390, 0, x86OfficialFMA3Assembly)
}

func TestX86OfficialFloatingImmediateControlScalarAndBroadcastTupleGoBytes(t *testing.T) {
	var cases []x86OfficialPackedCase
	for _, anchor := range []struct {
		instruction string
		encoding    []byte
	}{
		{"VGETMANTSS $7,64(AX),X17,X18", []byte{0x62, 0xe3, 0x75, 0x00, 0x27, 0x50, 0x10, 0x07}},
		{"VGETMANTSD $7,64(AX),X17,X18", []byte{0x62, 0xe3, 0xf5, 0x00, 0x27, 0x50, 0x08, 0x07}},
		{"VGETMANTPS $7,64(AX),Z18", []byte{0x62, 0xe3, 0x7d, 0x48, 0x26, 0x50, 0x01, 0x07}},
		{"VGETMANTPD.BCST $7,64(AX),Y18", []byte{0x62, 0xe3, 0xfd, 0x38, 0x26, 0x50, 0x08, 0x07}},
		{"VFIXUPIMMPS.BCST.Z $7,64(AX),Z17,K1,Z18", []byte{0x62, 0xe3, 0x75, 0xd1, 0x54, 0x50, 0x10, 0x07}},
		{"VRNDSCALESD.SAE.Z $7,X16,X17,K1,X18", []byte{0x62, 0xa3, 0xf5, 0x91, 0x0b, 0xd0, 0x07}},
	} {
		cases = append(cases, x86OfficialPackedCase{
			row:     "independent/FP-control/" + anchor.instruction,
			witness: goasmrules.X86PackedBinaryWitness{Instruction: anchor.instruction, Encoding: anchor.encoding},
		})
	}
	source, _ := x86OfficialFMA3Assembly(cases)
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("original Go scalar/full/broadcast tuple or SAE byte identity", err)
	}
}
