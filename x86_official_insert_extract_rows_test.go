package plan9asm

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// This preflight proves observable initialized producers, not per-row encoding
// ownership. The independent official-row driver must later bind each actual
// selected source row, including the alternate VPEXTRW shadow observations.
func TestX86OfficialInsertExtractExistingObservableProducer(t *testing.T) {
	var instructions []string
	for _, kind := range []string{"F", "I"} {
		instructions = append(instructions,
			"VEXTRACT"+kind+"128 $255,Y0,X2",
			"VINSERT"+kind+"128 $7,X0,Y1,Y2")
		for _, chunk := range []struct{ name, register string }{
			{"32X4", "X"}, {"64X2", "X"}, {"32X8", "Y"}, {"64X4", "Y"},
		} {
			instructions = append(instructions,
				"VEXTRACT"+kind+chunk.name+" $255,Z16,"+chunk.register+"18",
				"VINSERT"+kind+chunk.name+" $7,"+chunk.register+"16,Z17,Z18")
		}
	}
	instructions = append(instructions, "VEXTRACTPS $255,X16,CX", "VINSERTPS $7,X16,X17,X18")
	for _, suffix := range []string{"B", "W", "D", "Q"} {
		instructions = append(instructions, "VPEXTR"+suffix+" $255,X16,CX", "VPINSR"+suffix+" $7,CX,X17,X18")
	}
	if len(instructions) != 30 {
		t.Fatal("complete observable mnemonic producer changed", len(instructions))
	}
	var source, declarations strings.Builder
	for index, instruction := range instructions {
		name := fmt.Sprint("InsertExtract", index)
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b *[64]byte,value uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ value+24(FP),CX\n", name)
		low := strings.Contains(instruction, "128 ")
		if low {
			source.WriteString("VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\n")
		} else {
			source.WriteString("VMOVUPS (AX),Z16\nVMOVUPS (BX),Z17\n")
		}
		fmt.Fprintf(&source, "STC\n%s\n", instruction)
		if strings.HasSuffix(instruction, ",CX") {
			source.WriteString("MOVQ CX,0(DX)\n")
		} else if low {
			source.WriteString("VMOVUPS Z2,0(DX)\n")
		} else {
			source.WriteString("VMOVUPS Z18,0(DX)\n")
		}
		source.WriteString("SETCS 72(DX)\nRET\n")
	}
	const triple = "x86_64-unknown-linux-gnu"
	x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("real data inputs and observable vector/GP results", api, err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, ir, level)
			}
		})
	}
}

func x86OfficialInsertExtractShadowTarget(row goasmrules.X86PackedBinaryRow) string {
	if row.Opcode != "VPEXTRW" {
		return ""
	}
	for _, pair := range [][2]string{{"/2", "/0"}, {"/3", "/1"}, {"/5", "/4"}} {
		if strings.HasSuffix(row.ID, pair[0]) {
			// The source row's global ordinal also differs, so locate the
			// complete earlier row by opcode/table/local ordinal below.
			return "/VPEXTRW/_yvpextrw" + pair[1]
		}
	}
	return ""
}

// The canonical bytes name AX for either direction. All pointer-dependent
// inputs are initialized before an extract redirects AX to the output array.
func x86OfficialInsertExtractAssembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declarations strings.Builder
	vectorSeed := func(register string) string {
		return "Z" + register[1:]
	}
	for index := range cases {
		fixture := &cases[index]
		w := fixture.witness
		fixture.symbol = fmt.Sprint("TransferRow", index)
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b *[64]byte,mask uint64)\n", fixture.symbol)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\n", fixture.symbol)
		if w.First != "(AX)" && w.First != "CX" {
			fmt.Fprintf(&source, "VMOVUPS (AX),%s\n", vectorSeed(w.First))
		}
		if w.Second != "" {
			fmt.Fprintf(&source, "VMOVUPS (BX),%s\n", vectorSeed(w.Second))
		}
		if w.Masked {
			source.WriteString("MOVQ mask+24(FP),R9\nKMOVQ R9,K1\n")
			if !w.Zeroing && w.Destination != "(AX)" {
				fmt.Fprintf(&source, "VMOVUPS (BX),%s\n", vectorSeed(w.Destination))
			}
		}
		if w.First == "CX" {
			source.WriteString("MOVQ (AX),CX\n")
		}
		if w.Destination == "(AX)" {
			source.WriteString("MOVQ DX,AX\n")
		}
		source.WriteString("STC\n")
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, w.Instruction)
		if w.Destination == "CX" {
			source.WriteString("MOVQ CX,0(DX)\n")
		} else if w.Destination != "(AX)" {
			fmt.Fprintf(&source, "VMOVUPS %s,0(DX)\n", vectorSeed(w.Destination))
		}
		source.WriteString("SETCS 72(DX)\nRET\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialInsertExtractSelectedRowsThreeAPIObjects(t *testing.T) {
	selected := func(legacy goasmrules.X86LegacyCatalog, avx []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
		rows, err := goasmrules.X86InsertExtractRows(legacy, avx)
		if err != nil {
			return nil, err
		}
		if len(rows) != 82 {
			return nil, fmt.Errorf("complete physical source rows changed: %d", len(rows))
		}
		var ordinary []goasmrules.X86PackedBinaryRow
		for _, row := range rows {
			if x86OfficialInsertExtractShadowTarget(row) == "" {
				ordinary = append(ordinary, row)
			}
		}
		return ordinary, nil
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86OfficialPackedRowsObjectsInspect(t, selected, 79, 194, 0, x86OfficialInsertExtractAssembly,
		func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86OfficialInsertExtractNamedShadowsRetainOriginalBytes(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86InsertExtractRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		target := x86OfficialInsertExtractShadowTarget(row)
		if target == "" {
			continue
		}
		if len(row.Witnesses) != 1 {
			t.Fatal("alternate GP-only physical row changed", row)
		}
		shadow := row.Witnesses[0]
		var earlier *goasmrules.X86PackedBinaryWitness
		for _, candidate := range rows {
			if !strings.HasSuffix(candidate.ID, target) {
				continue
			}
			for index := range candidate.Witnesses {
				if candidate.Witnesses[index].Instruction == shadow.Instruction {
					earlier = &candidate.Witnesses[index]
				}
			}
		}
		if earlier == nil || bytes.Equal(earlier.Encoding, shadow.Encoding) {
			t.Fatal("shadow lacks its distinct original earlier-row bytes", row.ID)
		}
		fixture := []x86OfficialPackedCase{{row: row.ID, witness: shadow}}
		source, _ := x86OfficialInsertExtractAssembly(fixture)
		listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
		if err != nil {
			t.Fatal(err)
		}
		observed := fixture[0]
		observed.witness = *earlier
		if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{observed}); err != nil {
			t.Fatal("actual Go no longer selects the original earlier row", row.ID, err)
		}
		if err := x86OfficialPackedVerifyListing(listing, fixture); err == nil {
			t.Fatal("shadowed alternate encoding was falsely counted as named Go bytes", row.ID)
		}
		count++
	}
	if count != 3 {
		t.Fatal("complete alternate-encoding shadow observations changed", count)
	}
}
