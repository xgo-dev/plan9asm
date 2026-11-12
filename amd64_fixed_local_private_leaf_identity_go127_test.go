//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64FixedLocalPrivateLeafOriginalCallIdentity(t *testing.T) {
	assembly := fixedLocalPrivateLeafSource("CALL leaf<>(SB)\n CALL other<>(SB)", "MOVQ (BP),AX") +
		"TEXT other<>(SB),4,$0\n ADDQ $2,AX\n RET\n"
	x86InsertExtractGoListing(t, "amd64", assembly)
	pkg, request, _ := fixedLocalPrivateLeafFixture(t, assembly)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	expanded, err := owner.preprocess(request.AssemblyFile, []byte(assembly))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	data, err := owner.fixedLocalDataObservation(request.AssemblyFile, expanded)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := owner.read(filepath.Join(owner.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(data *gostaticstorage.AMD64AssemblyData, listing []byte, file *File) error {
		functions, err := goAMD64FrameListingWithDataObject(listing, file, pkg, owner.origins, data, nil,
			request.Target, request.Directory, "")
		if err != nil {
			return err
		}
		return goAMD64FrameDataTextJoin(functions, data, request.Directory, owner.origins, "")
	}
	if err := check(data, listing, file); err != nil {
		t.Fatal("complete actual original source/object/listing control", err)
	}
	root := data.TextOrder[0].ObjectOrdinal
	if root == 0 || len(data.Member.Texts[root].Relocations) != 2 {
		t.Fatal("fixture did not exercise separate static/nonstatic banks and both CALLs")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"valid_other_leaf", "wrong_bank", "wrong_relative", "unknown_ABI", "call_addend", "call_width",
		"call_field_inside_opcode", "missing_CALL", "missing_source_association", "reordered_source_association", "missing_parsed_TEXT",
	} {
		t.Run(name, func(t *testing.T) {
			var changed gostaticstorage.AMD64AssemblyData
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			input := bytes.Clone(listing)
			parsed := *file
			relocation := &changed.Member.Texts[root].Relocations[0]
			switch name {
			case "valid_other_leaf":
				before := goAMD64FrameDataRelocationLine(*relocation, &changed)
				relocation.Target = changed.Member.Texts[root].Relocations[1].Target
				after := goAMD64FrameDataRelocationLine(*relocation, &changed)
				if before == "" || after == "" || before == after {
					t.Fatal("mutation did not retain another valid actual local object target")
				}
				input = bytes.Replace(input, []byte(before), []byte(after), 1)
			case "wrong_bank":
				relocation.Target.PackageIndex++
			case "wrong_relative":
				relocation.Target.SymbolIndex++
			case "unknown_ABI":
				relocation.Target.ABIKnown = false
			case "call_addend":
				relocation.Add++
			case "call_width":
				relocation.Size++
			case "call_field_inside_opcode":
				relocation.Offset--
			case "missing_CALL":
				changed.Member.Texts[root].Relocations = changed.Member.Texts[root].Relocations[1:]
			case "missing_source_association":
				changed.TextOrder = changed.TextOrder[:len(changed.TextOrder)-1]
			case "reordered_source_association":
				changed.TextOrder[1], changed.TextOrder[2] = changed.TextOrder[2], changed.TextOrder[1]
			case "missing_parsed_TEXT":
				parsed.Funcs = parsed.Funcs[:len(parsed.Funcs)-1]
			}
			if err := check(&changed, input, &parsed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed complete source/native CALL identity was accepted", err)
			}
		})
	}
}
