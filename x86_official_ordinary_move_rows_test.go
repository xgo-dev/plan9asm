package plan9asm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86OrdinaryMoveOriginalCase struct {
	x86OfficialPackedCase
	original string
	mode64   bool
	rewrite  string
}

// Literal original-Go encodings are independent of the production formatter.
// In particular the MMX/XMM carriers are not GP numeric permissions, and an
// address rewrite is explicitly observed as LEA rather than a selected MOV row.
func x86OrdinaryMoveOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OrdinaryMoveOriginalCase {
	t.Helper()
	type sample struct {
		row      int
		operands string
		code     string
	}
	fixtures := map[string][]sample{
		"MOVB": {{0, "CL,BL", "88cb"}, {0, "CL,0(SI)", "880e"}, {1, "0(SI),BL", "8a1e"}, {2, "$128,BL", "b380"}, {3, "$128,0(SI)", "c60680"}},
		"MOVW": {{0, "CX,BX", "6689cb"}, {0, "CX,0(SI)", "66890e"}, {1, "0(SI),BX", "668b1e"}, {2, "$128,BX", "66bb8000"}, {3, "$128,0(SI)", "66c7068000"}, {4, "$slot+0(SP),BX", "668d1c24"}},
		"MOVL": {{0, "CX,BX", "89cb"}, {0, "CX,0(SI)", "890e"}, {1, "0(SI),BX", "8b1e"}, {2, "$128,BX", "bb80000000"}, {3, "$128,0(SI)", "c70680000000"},
			{4, "CX,M1", "0f6ec9"}, {4, "0(SI),M1", "0f6e0e"}, {5, "M1,CX", "0f7ec9"}, {5, "M1,0(SI)", "0f7e0e"},
			{6, "CX,X1", "660f6ec9"}, {6, "0(SI),X1", "660f6e0e"}, {7, "X1,CX", "660f7ec9"}, {7, "X1,0(SI)", "660f7e0e"}, {8, "$slot+0(SP),BX", "8d1c24"}},
		"MOVQ": {{0, "0(SI),M1", "0f6f0e"}, {1, "M1,0(SI)", "0f7f0e"}, {2, "X0,M1", "f20fd6c8"},
			{3, "X0,X1", "f30f7ec8"}, {3, "0(SI),X1", "f30f7e0e"}, {4, "X1,0(SI)", "660fd60e"},
			{5, "CX,BX", "4889cb"}, {5, "CX,0(SI)", "48890e"}, {6, "0(SI),BX", "488b1e"},
			{7, "$0x1122334455667788,BX", "48bb8877665544332211"}, {8, "$128,0(SI)", "48c70680000000"},
			{9, "CX,M1", "480f6ec9"}, {10, "M1,CX", "480f7ec9"}, {11, "CX,X1", "66480f6ec9"}, {12, "X1,CX", "66480f7ec9"}, {13, "$slot+0(SP),BX", "488d1c24"}},
	}
	var result []x86OrdinaryMoveOriginalCase
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		samples, found := fixtures[entry.Opcode]
		if !found {
			continue
		}
		if seen[entry.Opcode] {
			t.Fatal("duplicate original MOV table", entry.Opcode)
		}
		seen[entry.Opcode] = true
		for _, fixture := range samples {
			index := fixture.row
			if entry.Opcode == "MOVQ" && len(entry.Rows) == 15 && index >= 7 {
				index++
			}
			code, err := hex.DecodeString(fixture.code)
			if err != nil || index >= len(entry.Rows) {
				t.Fatal("independent MOV fixture changed", err)
			}
			original := entry.Opcode + " " + fixture.operands
			selected, rewrite := original, ""
			if entry.Rows[index].ZCase == "Zaut_r" && entry.Opcode != "MOVW" {
				selected = "LEA" + entry.Opcode[3:] + " " + strings.TrimPrefix(fixture.operands, "$")
				rewrite = "original Go progedit rewrites TYPE_ADDR before ymov matching"
			}
			result = append(result, x86OrdinaryMoveOriginalCase{
				x86OfficialPackedCase: x86OfficialPackedCase{row: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, index),
					witness: goasmrules.X86PackedBinaryWitness{Instruction: selected, Destination: strings.Split(fixture.operands, ",")[1], Encoding: code}},
				original: original, mode64: entry.Prefix == "Pw8" && entry.Rows[index].UnmatchedOffset >= 8, rewrite: rewrite,
			})
		}
		if entry.Opcode == "MOVQ" && len(entry.Rows) == 15 {
			result = append(result, x86OrdinaryMoveOriginalCase{x86OfficialPackedCase: x86OfficialPackedCase{
				row: fmt.Sprintf("optab/%d/MOVQ/ymovq/7", entry.TableIndex), witness: goasmrules.X86PackedBinaryWitness{
					Instruction: "MOVQ $-1,BX", Destination: "BX", Encoding: []byte{0x48, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff}}},
				original: "MOVQ $-1,BX", mode64: true})
		}
	}
	if len(seen) != 4 {
		t.Fatal("missing complete ordinary MOV source table", seen)
	}
	return result
}

func TestX86OrdinaryMoveAddressOriginalAndCanonicalLEASourceOwnership(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// These literal bytes and the actual Go assembler are independent of the
	// MOV source formatter. A LEA object does not select a shadowed MOV row.
	for _, arch := range []string{"amd64", "386"} {
		for _, sample := range []struct{ width, code, prefix string }{
			{"W", "668d1c24", "Pe"}, {"L", "8d1c24", "Px"}, {"Q", "488d1c24", "Pw"},
		} {
			if arch == "386" && sample.width == "Q" {
				continue // Original mode32 refusal is independently executed above.
			}
			t.Run(arch+"/"+sample.width, func(t *testing.T) {
				originalID, canonicalID := "", ""
				for _, entry := range catalog.Optab {
					if entry.Opcode == "MOV"+sample.width {
						for _, row := range entry.Rows {
							if row.ZCase == "Zaut_r" {
								if originalID != "" || len(row.Classes) != 2 || row.Classes[0] != "Yiauto" || row.Classes[1] != "Yrl" {
									t.Fatal("original address-MOV row identity changed")
								}
								originalID = fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
							}
						}
					}
					if entry.Opcode == "LEA"+sample.width {
						if canonicalID != "" || entry.Ytab != "ym_rl" || entry.Prefix != sample.prefix || len(entry.Rows) != 1 {
							t.Fatal("canonical LEA source identity changed")
						}
						row := entry.Rows[0]
						if row.ZCase != "Zm_r" || row.ZOffset != 1 || row.UnmatchedOffset != 0 ||
							len(row.Classes) != 2 || row.Classes[0] != "Ym" || row.Classes[1] != "Yrl" {
							t.Fatal("canonical LEA complete row schema changed")
						}
						canonicalID = fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab)
					}
				}
				if originalID == "" || canonicalID == "" {
					t.Fatal("original MOV or independent canonical LEA owner missing")
				}
				code, err := hex.DecodeString(sample.code)
				if err != nil {
					t.Fatal(err)
				}
				original := "MOV" + sample.width + " $slot+0(SP),BX"
				canonical := "LEA" + sample.width + " slot+0(SP),BX"
				observed := original
				if sample.width != "W" {
					observed = canonical
				}
				x86OrdinaryMoveCheckOriginalGo(t, arch, []x86OrdinaryMoveOriginalCase{
					{x86OfficialPackedCase: x86OfficialPackedCase{row: originalID, witness: goasmrules.X86PackedBinaryWitness{
						Instruction: observed, Destination: "BX", Encoding: code}}, original: original},
					{x86OfficialPackedCase: x86OfficialPackedCase{row: canonicalID, witness: goasmrules.X86PackedBinaryWitness{
						Instruction: canonical, Destination: "BX", Encoding: code}}, original: canonical},
				})
				if sample.width == "W" {
					t.Log("actual original MOVW retains Zaut_r owner", originalID, "; independent LEAW owner", canonicalID)
				} else {
					t.Log("actual original MOV front-end rewrite before MOV table selection", originalID, "->", canonicalID, canonical)
				}
			})
		}
	}
}

func x86OrdinaryMoveCheckOriginalGo(t *testing.T, arch string, cases []x86OrdinaryMoveOriginalCase) {
	t.Helper()
	for start := 0; start < len(cases); start += 32 {
		end := start + 32
		if end > len(cases) {
			end = len(cases)
		}
		t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
			var source strings.Builder
			var originals []x86OfficialPackedCase
			for index, fixture := range cases[start:end] {
				fixture.symbol = fmt.Sprintf("OrdinaryMove%d", start+index)
				fixture.line = strings.Count(source.String(), "\n") + 2
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", fixture.symbol, fixture.original)
				originals = append(originals, fixture.x86OfficialPackedCase)
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal("original ordinary MOV source fixture failed", err)
			}
			if err := x86OfficialPackedVerifyListing(listing, originals); err != nil {
				t.Fatal("original MOV row/direction/first-match bytes differ", err)
			}
		})
	}
}

func TestX86OfficialOrdinaryMoveCompleteOriginalGo(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	all := x86OrdinaryMoveOriginalCases(t, catalog)
	for _, arch := range []string{"amd64", "386"} {
		var accepted []x86OrdinaryMoveOriginalCase
		seen := map[string]bool{}
		for _, fixture := range all {
			if arch == "386" && fixture.mode64 {
				if !seen[fixture.row] {
					t.Run("386/refusal/"+fixture.row, func(t *testing.T) {
						goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+fixture.original+"\nRET\n", "", false)
					})
				}
				seen[fixture.row] = true
				continue
			}
			accepted = append(accepted, fixture)
		}
		x86OrdinaryMoveCheckOriginalGo(t, arch, accepted)
	}
}

func TestX86OfficialOrdinaryMoveCompleteSourceJoin(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	all := x86OrdinaryMoveOriginalCases(t, catalog)
	modes := map[string][]goasmrules.X86OrdinaryMoveRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86OrdinaryMoveRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		expected := map[string]x86OrdinaryMoveOriginalCase{}
		for _, fixture := range all {
			if arch != "386" || !fixture.mode64 {
				expected[fixture.row+"/"+fixture.original] = fixture
			}
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				original, found := expected[key]
				if !found || !bytes.Equal(witness.Encoding, original.witness.Encoding) || witness.Destination != original.witness.Destination {
					t.Fatal("complete MOV row/instruction/bytes/destination join differs", arch, key, witness, original.witness)
				}
				if (row.Rewrite != "") != (original.rewrite != "") || row.Rewrite != "" && !strings.HasPrefix(original.witness.Instruction, row.Rewrite+" ") {
					t.Fatal("original MOV-to-LEA observation lost its rewrite identity", key, row.Rewrite, original.rewrite)
				}
				delete(expected, key)
			}
		}
		if len(expected) != 0 {
			t.Fatal("independent original MOV observations omitted", arch, expected)
		}
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_ORDINARY_MOVE_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86OrdinaryMoveRow
	}{catalog, modes})
}

// All preserved GP/XMM bytes and typed pointer extents are independently
// initialized. An MMX operand opens a real MMX region and is closed by EMMS.
// The source-row descriptor supplies none of those facts.
func x86OrdinaryMoveInitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if word == 4 {
		move = "MOVL"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DX\n%s p+%d(FP),SI\n"+
		"%s old+%d(FP),BX\n%s input+%d(FP),CX\nMOVOU (SI),X0\nMOVOU (SI),X1\nCMPL CX,CX\n",
		name, 2*word+16, move, move, word, move, 2*word, move, 2*word+8)
	mmx := strings.Contains(operation, "M1")
	if mmx {
		source += "MOVQ (SI),M1\n"
	}
	source += operation + "\n"
	if mmx {
		source += "MOVQ M1,32(DX)\nEMMS\n"
	}
	source += fmt.Sprintf("MOVOU X1,0(DX)\nMOVOU (SI),X2\nMOVOU X2,16(DX)\n"+
		"%s BX,48(DX)\n%s CX,56(DX)\nSETCS 62(DX)\nSETEQ 63(DX)\nRET\n", move, move)
	return source, fmt.Sprintf("func %s(out *[64]byte,p *[16]byte,old,input uint64)\n", name)
}

func TestX86OfficialOrdinaryMoveInitializedThreeAPIFiveObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	all := x86OrdinaryMoveOriginalCases(t, catalog)
	for _, arch := range []string{"amd64", "386"} {
		var cases []x86OfficialPackedCase
		for _, fixture := range all {
			if arch == "386" && fixture.mode64 || strings.Contains(fixture.original, "$slot+") {
				continue
			}
			cases = append(cases, fixture.x86OfficialPackedCase)
		}
		x86Legacy127Objects(t, arch, cases, x86OrdinaryMoveInitializedFunction)
	}
}

func TestX86OfficialOrdinaryMoveSourceRowsDoNotSupplyInputAuthority(t *testing.T) {
	for _, row := range []struct{ operation, initialization, observation string }{
		{"MOVB CL,BL", "MOVQ old+0(FP),BX\n", ""},
		{"MOVW CX,BX", "MOVQ input+8(FP),CX\n", ""},
		{"MOVL M1,CX", "", "MOVQ CX,ret+16(FP)\n"},
		{"MOVQ X0,M1", "", "MOVQ M1,ret+16(FP)\nEMMS\n"},
		{"MOVB 0(SI),BL", "MOVQ old+0(FP),BX\n", ""},
		{"MOVQ CX,0(SI)", "MOVQ old+0(FP),BX\nMOVQ input+8(FP),CX\n", ""},
		{"MOVW $slot+0(SP),BX", "MOVQ old+0(FP),BX\n", ""},
		{"MOVL $slot+0(SP),BX", "", ""},
		{"MOVQ $slot+0(SP),BX", "", ""},
	} {
		t.Run(row.operation, func(t *testing.T) {
			observation := row.observation
			if observation == "" {
				observation = "MOVQ BX,ret+16(FP)\n"
			}
			source := "TEXT ·MissingMovInput(SB),4,$0-24\n" + row.initialization + row.operation + "\n" + observation + "RET\n"
			declaration := "func MissingMovInput(old,input uint64) uint64\n"
			// The source spelling remains Go-valid even when a numerical input,
			// bank/state input, pointer or independently owned frame is absent.
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original MOV syntax supplied absent input/source authority", api, ir, err)
				}
			}
		})
	}
}

func TestX86OfficialOrdinaryMoveOriginalAddressCapturedFrameObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, width := range []string{"W", "L", "Q"} {
		t.Run(width, func(t *testing.T) {
			// The bounded local is initialized independently. The address-only
			// scratch is overwritten before any numerical/result observation;
			// a partial W/L address must not become a dereferenceable pointer.
			source := "TEXT ·OrdinaryAddress(SB),4,$16-16\nMOVQ input+0(FP),AX\nMOVQ AX,0(SP)\n" +
				"MOV" + width + " $slot-16(SP),BX\nMOVQ $0,BX\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
			declaration := "func OrdinaryAddress(input uint64) uint64\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, goos := range []string{"linux", "darwin", "windows"} {
				t.Run(goos, func(t *testing.T) {
					triple := testTargetTriple(goos, "amd64")
					pkg, request, _, options := x86CMOVFixedLocalFixture(t, source, declaration, goos+"/amd64", triple)
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
						if err != nil || ir == "" {
							t.Fatal("original address MOV with independently captured initialized frame rejected", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, ir, level)
						}
					})
				})
			}
		})
	}
}

func TestX86OfficialOrdinaryMoveImmediateFirstMatch(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	historicalSignedRow := false
	for _, entry := range catalog.Optab {
		if entry.Opcode == "MOVQ" {
			historicalSignedRow = len(entry.Rows) == 15
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		var cases []x86OrdinaryMoveOriginalCase
		for _, row := range []struct{ instruction, code string }{
			{"MOVB $-1,BL", "b3ff"}, {"MOVW $65535,BX", "66bbffff"}, {"MOVL $-1,BX", "bbffffffff"},
		} {
			code, _ := hex.DecodeString(row.code)
			cases = append(cases, x86OrdinaryMoveOriginalCase{x86OfficialPackedCase: x86OfficialPackedCase{row: "independent immediate selector", witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: code}}, original: row.instruction})
		}
		if arch == "amd64" {
			for _, row := range []struct{ instruction, current, historical string }{
				{"MOVQ $0,BX", "bb00000000", "48c7c300000000"},
				{"MOVQ $1,BX", "bb01000000", "48c7c301000000"},
				{"MOVQ $2147483647,BX", "bbffffff7f", "48c7c3ffffff7f"},
				{"MOVQ $2147483648,BX", "bb00000080", "bb00000080"},
				{"MOVQ $4294967295,BX", "bbffffffff", "bbffffffff"},
				{"MOVQ $4294967296,BX", "48bb0000000001000000", "48bb0000000001000000"},
				{"MOVQ $-1,BX", "48c7c3ffffffff", "48c7c3ffffffff"},
				{"MOVQ $-2147483648,BX", "48c7c300000080", "48c7c300000080"},
				{"MOVQ $-2147483649,BX", "48bbffffff7fffffffff", "48bbffffff7fffffffff"},
			} {
				encoding := row.current
				if historicalSignedRow {
					encoding = row.historical
				}
				code, _ := hex.DecodeString(encoding)
				cases = append(cases, x86OrdinaryMoveOriginalCase{x86OfficialPackedCase: x86OfficialPackedCase{row: "independent MOVQ shortening", witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: code}}, original: row.instruction})
			}
		}
		x86OrdinaryMoveCheckOriginalGo(t, arch, cases)
	}
}
