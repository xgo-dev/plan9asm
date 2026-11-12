package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// These cases follow the original prefix switch and zero-terminated literal
// span. They are independent of the production witness formatter.
func x86LegacyLiteralSIMDSourceCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, boundary bool) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	seenPrefixes := map[string]bool{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yxshuf" && entry.Ytab != "yaes" {
			continue
		}
		if boundary && (entry.Ytab != "yxshuf" || seenPrefixes[entry.Prefix]) {
			continue
		}
		seenPrefixes[entry.Prefix] = true
		prefixes := map[string][]byte{"Pq": {0x66, 0x0f}, "Pf2": {0xf2, 0x0f}, "Pf3": {0xf3, 0x0f}, "Pm": {0x0f}, "Px": {}}
		prefix, found := prefixes[entry.Prefix]
		if !found {
			t.Fatal("independent literal SIMD source prefix changed", entry)
		}
		payload := append([]byte(nil), prefix...)
		for index, atom := range entry.OpBytes {
			value, err := strconv.ParseUint(atom, 0, 8)
			if err != nil || value == 0 && index != len(entry.OpBytes)-1 {
				t.Fatal("independent literal SIMD source atom changed", entry, index, err)
			}
			if value != 0 {
				payload = append(payload, byte(value))
			}
		}
		immediates := []int{7}
		if boundary {
			immediates = []int{0, 127, 128, 255}
		}
		for _, immediate := range immediates {
			for _, source := range []string{"X0", "(AX)"} {
				modrm := byte(0xc8)
				if source == "(AX)" {
					modrm = 0x08
				}
				instruction := entry.Opcode + " " + source + ",X1"
				code := append(append([]byte(nil), payload...), modrm)
				if entry.Ytab == "yxshuf" {
					instruction = fmt.Sprintf("%s $%d,%s,X1", entry.Opcode, immediate, source)
					code = append(code, byte(immediate))
				}
				cases = append(cases, x86OfficialPackedCase{
					row:     fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab),
					witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Destination: "X1", Encoding: code},
				})
			}
		}
	}
	want := 66
	if boundary {
		want = 32 // Four observed prefix classes times two carriers times four Yu8 boundaries.
	}
	if len(cases) != want {
		t.Fatal("complete literal SIMD source/class-boundary inventory changed", len(cases), want)
	}
	return cases
}

func x86LegacyLiteralSIMDCheckGoBatches(t *testing.T, arch string, cases []x86OfficialPackedCase) {
	t.Helper()
	for start := 0; start < len(cases); start += 32 {
		end := start + 32
		if end > len(cases) {
			end = len(cases)
		}
		t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
			batch := cases[start:end]
			var source strings.Builder
			line := 1
			for index := range batch {
				fixture := &batch[index]
				fixture.symbol = fmt.Sprintf("LiteralSIMD%d", start+index)
				fixture.line = line + 1
				body := fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", fixture.symbol, fixture.witness.Instruction)
				source.WriteString(body)
				line += strings.Count(body, "\n")
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal("actual Go refused complete original literal SIMD source", err)
			}
			if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
				t.Fatal("actual Go literal SIMD prefix/terminator/immediate bytes differ", err)
			}
		})
	}
}

func TestX86OfficialLegacyLiteralSIMDOriginalGoBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := make(map[string][]goasmrules.X86PackedBinaryRow)
	for _, arch := range []string{"amd64", "386"} {
		cases := x86LegacyLiteralSIMDSourceCases(t, catalog, false)
		rows, err := goasmrules.X86LegacyLiteralSIMDRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		expected := map[string]goasmrules.X86PackedBinaryWitness{}
		for _, fixture := range cases {
			expected[fixture.row+"/"+fixture.witness.Instruction] = fixture.witness
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				original, found := expected[key]
				if !found || !bytes.Equal(original.Encoding, witness.Encoding) || original.Destination != witness.Destination {
					t.Fatal("literal SIMD transport differs from independent actual-Go source", key, witness, original)
				}
				delete(expected, key)
			}
		}
		if len(rows) != 33 || len(expected) != 0 {
			t.Fatal("literal SIMD row/witness join omitted or repeated source cases", arch, len(rows), expected)
		}
		x86LegacyLiteralSIMDCheckGoBatches(t, arch, cases)
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_LEGACY_LITERAL_SIMD_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86PackedBinaryRow
		}{catalog, modes})
	}
}

func TestX86OfficialLegacyLiteralSIMDGoImmediateAndModeBoundaries(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run("unsigned/"+arch, func(t *testing.T) {
			x86LegacyLiteralSIMDCheckGoBatches(t, arch, x86LegacyLiteralSIMDSourceCases(t, catalog, true))
		})
		seen := map[string]bool{}
		for _, entry := range catalog.Optab {
			if entry.Ytab != "yxshuf" || seen[entry.Prefix] {
				continue
			}
			seen[entry.Prefix] = true
			for _, immediate := range []int{-129, -128, -1, 256} {
				t.Run(fmt.Sprintf("%s/%s/imm%d", arch, entry.Prefix, immediate), func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Bad(SB),4,$0-0\n%s $%d,X0,X1\nRET\n", entry.Opcode, immediate)
					goAssemblerOracleOutput(t, arch, source, "", false)
				})
			}
		}
		modes := map[string]bool{}
		for _, entry := range catalog.Optab {
			if entry.Ytab != "yxshuf" && entry.Ytab != "yaes" {
				continue
			}
			key := entry.Ytab + "/" + entry.Prefix
			if modes[key] {
				continue
			}
			modes[key] = true
			t.Run("high-register/"+arch+"/"+key, func(t *testing.T) {
				instruction := entry.Opcode + " X8,X1"
				if entry.Ytab == "yxshuf" {
					instruction = entry.Opcode + " $7,X8,X1"
				}
				source := "TEXT ·Mode(SB),4,$0-0\n" + instruction + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", arch == "amd64")
			})
		}
	}
}

// Exact original source-format units compile independently of initialized
// public programs. They do not establish NUM, memory bounds, FP control or
// numerical/native execution. Those stay with the typed family owners.
func TestX86OfficialLegacyLiteralSIMDOriginalFormatObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	objects := 0
	for _, arch := range []string{"amd64", "386"} {
		cases := x86LegacyLiteralSIMDSourceCases(t, catalog, false)
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				var source strings.Builder
				signatures := map[string]FuncSig{}
				for index, fixture := range cases[start:end] {
					name := fmt.Sprintf("LiteralSIMDFormat%d", start+index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, fixture.witness.Instruction)
					signatures[name] = FuncSig{Name: name, Ret: Void}
				}
				file, err := Parse(ArchAMD64, source.String())
				if err != nil || len(file.Funcs) != end-start {
					t.Fatal("original literal SIMD format functions changed", err)
				}
				for _, triple := range x86Legacy127Targets(arch) {
					ir := x86SingleInstructionFormatObjectUnits(t, file, signatures, arch, triple,
						func(consumer *amd64Ctx, instruction Instr) (bool, bool, error) {
							// Reuse the real typed family emitters. This is neither
							// a raw-byte/inline-assembly substitute nor a public proof.
							for _, lower := range []func(Op, Instr) (bool, bool, error){
								consumer.lowerPackedFloatShuffle, consumer.lowerImmediatePackedBlend, consumer.lowerPackedFloatingDot,
								consumer.lowerPackedSumAbsoluteDifferences, consumer.lowerRound,
								consumer.lowerVec,
							} {
								if known, terminal, err := lower(instruction.Op, instruction); known {
									return known, terminal, err
								}
							}
							return false, false, nil
						})
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
						objects++
					}
				}
			})
		}
	}
	if objects != 30 {
		t.Fatal("complete literal SIMD five-target O0/O2 format matrix changed", objects)
	}
}

func x86Legacy127Targets(arch string) []string {
	if arch == "386" {
		return []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
	}
	return []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
}

// Inputs are explicit pointer/scalar parameters. Seeding both X inputs is
// deliberate initialized context, not a fact inferred from source syntax.
// MMX has a separate real region, output observation and mandatory EMMS.
func x86LegacyMediaInitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "Q"
	if word == 4 {
		move = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DX\nMOV%s a+%d(FP),AX\nMOV%s b+%d(FP),BX\nMOV%s mask+%d(FP),CX\n"+
		"MOVOU (AX),X0\nMOVOU (BX),X1\nCMPL CX,CX\n", name, 3*word+8, move, move, word, move, 2*word, move, 3*word)
	mmx := strings.Contains(operation, "M1")
	if mmx {
		source += "MOVQ (AX),M0\nMOVQ (BX),M1\n"
	}
	source += operation + "\n"
	if mmx {
		source += "MOVQ M1,32(DX)\nEMMS\n"
	}
	// Observe the whole X carrier and memory, including scalar/half merge
	// bytes. COMI observes its defined status rather than a fictitious X write.
	source += "MOVOU X1,0(DX)\nMOVOU (AX),X2\nMOVOU X2,16(DX)\n" +
		"SETCS CL\nMOVB CL,40(DX)\nSETEQ CL\nMOVB CL,41(DX)\nSETPS CL\nMOVB CL,42(DX)\nRET\n"
	return source, fmt.Sprintf("func %s(out *[48]byte,a,b *[16]byte,mask uint64)\n", name)
}

// This batches complete functions, not a compiler process per source row.
// Whole-source Go byte identity precedes each three-API O0/O2 object batch.
func x86Legacy127Objects(t *testing.T, arch string, cases []x86OfficialPackedCase,
	function func(string, string, string) (string, string)) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for start := 0; start < len(cases); start += 32 {
		end := start + 32
		if end > len(cases) {
			end = len(cases)
		}
		t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
			batch := cases[start:end]
			var source, declarations strings.Builder
			for index := range batch {
				fixture := &batch[index]
				fixture.symbol = fmt.Sprint("Legacy127Row", index)
				body, declaration := function(fixture.symbol, fixture.witness.Instruction, arch)
				position := strings.Index(body, "\n"+fixture.witness.Instruction+"\n")
				if position < 0 || strings.Count(body, "\n"+fixture.witness.Instruction+"\n") != 1 {
					t.Fatal("initialized producer lost the exact original instruction", fixture.row)
				}
				fixture.line = strings.Count(source.String(), "\n") + strings.Count(body[:position+1], "\n") + 1
				source.WriteString(body)
				declarations.WriteString(declaration)
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
				t.Fatal("actual original source row/prefix/direction/byte identity", err)
			}
			for _, target := range x86Legacy127Targets(arch) {
				t.Run(target, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, target, api)
							if err != nil || ir == "" {
								t.Fatal("initialized whole-function translation", err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target, ir, level)
							}
						})
					}
				})
			}
		})
	}
}

func x86Legacy127SaveIdentity(t *testing.T, variable string, value interface{}) {
	t.Helper()
	if path := os.Getenv(variable); path != "" {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func x86LegacyMediaInitializedCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) []x86OfficialPackedCase {
	t.Helper()
	rows, err := goasmrules.X86LegacyMediaRemainderRows(catalog, arch)
	if err != nil {
		t.Fatal(err)
	}
	var cases []x86OfficialPackedCase
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: witness})
		}
	}
	literal, err := goasmrules.X86LegacyLiteralSIMDRows(catalog, arch)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]goasmrules.X86PackedBinaryRow)
	for _, row := range literal {
		byID[row.ID] = row
	}
	for _, original := range x86LegacyLiteralSIMDSourceCases(t, catalog, false) {
		matched := false
		for _, witness := range byID[original.row].Witnesses {
			if witness.Instruction == original.witness.Instruction {
				matched = bytes.Equal(witness.Encoding, original.witness.Encoding)
			}
		}
		if !matched {
			t.Fatal("initialized literal SIMD row differs from independent original bytes", original.row, original.witness.Instruction)
		}
		cases = append(cases, x86LegacyLiteralSIMDInitializedCarrier(t, original, arch))
	}
	return cases
}

// All object owners consume the same complete stream, but execute disjoint
// original-row partitions. Count every witness before either owner compiles it.
func x86LegacyMediaObjectPartitions(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) (media, crypto, immediate []x86OfficialPackedCase) {
	t.Helper()
	rows, err := goasmrules.X86LegacyMediaRemainderRows(catalog, arch)
	if err != nil {
		t.Fatal(err)
	}
	mediaIDs := map[string]bool{}
	expected := map[string]int{}
	for _, row := range rows {
		mediaIDs[row.ID] = true
		expected[row.ID] = len(row.Witnesses)
	}
	cryptoIDs := map[string]bool{}
	immediateRows := 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yaes" && entry.Ytab != "yxshuf" {
			continue
		}
		for _, row := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if _, found := expected[id]; found {
				t.Fatal("initialized original-row partitions overlap", id)
			}
			expected[id] = 2 // Complete register and memory carriers.
			if entry.Ytab == "yaes" {
				cryptoIDs[id] = true
			} else {
				immediateRows++
			}
		}
	}
	if len(mediaIDs) != 96 || len(cryptoIDs) != 10 || immediateRows != 23 {
		t.Fatal("complete original initialized row partitions changed", len(mediaIDs), len(cryptoIDs), immediateRows)
	}
	seen := map[string]bool{}
	actual := map[string]int{}
	for _, fixture := range x86LegacyMediaInitializedCases(t, catalog, arch) {
		if _, found := expected[fixture.row]; !found {
			t.Fatal("initialized stream has an unowned original row", fixture.row)
		}
		key := fixture.row + "/" + fixture.witness.Instruction
		if seen[key] {
			t.Fatal("initialized row partition repeats an original witness", key)
		}
		seen[key] = true
		actual[fixture.row]++
		if mediaIDs[fixture.row] {
			media = append(media, fixture)
		} else if cryptoIDs[fixture.row] {
			crypto = append(crypto, fixture)
		} else {
			immediate = append(immediate, fixture)
		}
	}
	for id, want := range expected {
		if actual[id] != want {
			t.Fatal("initialized row partition lost original witnesses", id, actual[id], want)
		}
	}
	return media, crypto, immediate
}

func x86LegacyLiteralSIMDInitializedCarrier(t *testing.T, original x86OfficialPackedCase, arch string) x86OfficialPackedCase {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, original.witness.Instruction)
	spec, known, err := amd64PackedStringCompareProperties(ins.Op, ins, arch)
	if err != nil {
		t.Fatal(err)
	}
	if !known || !spec.explicitLength || ins.Args[1].Kind != OpMem {
		return original
	}
	// EAX is an independent numerical length. Keep the canonical AX byte
	// witness above; use SI for this initialized pointer, with its own exact
	// stock-Go byte check in x86Legacy127Objects. No pointer bits become NUM.
	code := original.witness.Encoding
	if strings.Count(original.witness.Instruction, "(AX)") != 1 || len(code) < 2 || code[len(code)-2] != 0x08 {
		t.Fatal("explicit-length canonical source carrier changed", original)
	}
	original.witness.Instruction = strings.Replace(original.witness.Instruction, "(AX)", "(SI)", 1)
	original.witness.First = "(SI)"
	original.witness.Encoding = append([]byte(nil), code...)
	original.witness.Encoding[len(code)-2] = 0x0e // ModRM: X1, (SI).
	return original
}

func x86LegacyImmediateSIMDInitializedFunction(t *testing.T, name, operation, arch string) (string, string) {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, operation)
	spec, packedString, err := amd64PackedStringCompareProperties(ins.Op, ins, arch)
	if err != nil {
		t.Fatal(err)
	}
	word, move := goWordSize(arch), "Q"
	if word == 4 {
		move = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\nMOV%s a+%d(FP),SI\nMOV%s b+%d(FP),BX\nMOV%s mask+%d(FP),CX\n",
		name, 3*word+24, move, move, word, move, 2*word, move, 3*word)
	if !packedString || !spec.explicitLength {
		source += fmt.Sprintf("MOV%s SI,AX\n", move)
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && operand.Reg == "X0" {
			source += "MOVOU (SI),X0\n"
			break
		}
	}
	source += "MOVOU (BX),X1\n"
	if packedString && spec.explicitLength {
		source += fmt.Sprintf("MOVL lengthA+%d(FP),AX\nMOVL lengthB+%d(FP),DX\n", 3*word+8, 3*word+16)
	}
	source += "CMPL CX,CX\n" + operation + "\nMOVOU X1,0(DI)\n"
	if packedString {
		if spec.maskResult {
			source += "MOVOU X0,32(DI)\n"
		} else {
			source += "MOVL CX,32(DI)\n"
		}
	}
	source += "SETCS CL\nMOVB CL,48(DI)\nSETEQ CL\nMOVB CL,49(DI)\nSETPS CL\nMOVB CL,50(DI)\nRET\n"
	return source, fmt.Sprintf("func %s(out *[64]byte,a,b *[16]byte,mask uint64,lengthA,lengthB int64)\n", name)
}

func TestX86OfficialLegacyMediaRemainderRowsObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86LegacyMediaRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86LegacyMediaRemainderRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		cases, _, _ := x86LegacyMediaObjectPartitions(t, catalog, arch)
		want := 160
		if arch == "386" {
			want = 70
		}
		if len(rows) != 96 || len(cases) != want {
			t.Fatal("complete source/mode witness union changed", arch, len(rows), len(cases))
		}
		x86Legacy127Objects(t, arch, cases, x86LegacyMediaInitializedFunction)
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_LEGACY_MEDIA_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86LegacyMediaRow
		}{catalog, modes})
	}
}

func TestX86LegacyCryptoOriginalRowsReachInitializedObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			expected := map[string]int{}
			for _, entry := range catalog.Optab {
				if entry.Ytab != "yaes" {
					continue
				}
				for _, row := range entry.Rows {
					id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
					expected[id] = 0
				}
			}
			if len(expected) != 10 {
				t.Fatal("complete original legacy AES/SHA format changed", len(expected))
			}
			_, cases, _ := x86LegacyMediaObjectPartitions(t, catalog, arch)
			// Audit the actual existing initialized input stream only after
			// its stock-Go bytes and public API/object pipeline have run.
			x86Legacy127Objects(t, arch, cases, x86LegacyMediaInitializedFunction)
			if t.Failed() {
				return
			}
			if len(cases) != 20 {
				t.Errorf("crypto object owner must execute only its complete 10-row reg/memory partition: got %d witnesses, want 20", len(cases))
			}
			for _, fixture := range cases {
				if _, selected := expected[fixture.row]; selected {
					expected[fixture.row]++
				}
			}
			for id, count := range expected {
				if count != 2 {
					t.Errorf("original legacy AES/SHA row lost its initialized reg/memory pair: %s: got %d, want 2", id, count)
				}
			}
		})
	}
}

func TestX86LegacyImmediateSIMDOriginalRowsReachInitializedObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	type witnessPair struct {
		RowID                              string
		Canonical, Initialized             goasmrules.X86PackedBinaryWitness
		CanonicalSource, InitializedSource Operand
	}
	identity := map[string][]witnessPair{}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			expected := map[string]int{}
			for _, entry := range catalog.Optab {
				if entry.Ytab != "yxshuf" {
					continue
				}
				for _, row := range entry.Rows {
					id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
					expected[id] = 0
				}
			}
			if len(expected) != 23 {
				t.Fatal("complete original immediate SIMD format changed", len(expected))
			}
			_, _, cases := x86LegacyMediaObjectPartitions(t, catalog, arch)
			x86Legacy127Objects(t, arch, cases, func(name, operation, arch string) (string, string) {
				return x86LegacyImmediateSIMDInitializedFunction(t, name, operation, arch)
			})
			if t.Failed() {
				return
			}
			if len(cases) != 46 {
				t.Errorf("complete immediate SIMD object partition: got %d witnesses, want 46", len(cases))
			}
			for _, fixture := range cases {
				if _, selected := expected[fixture.row]; selected {
					expected[fixture.row]++
				}
			}
			for id, count := range expected {
				if count != 2 {
					t.Errorf("original immediate SIMD row lost its initialized reg/memory pair: %s: got %d, want 2", id, count)
				}
			}
			byCarrier := map[string]goasmrules.X86PackedBinaryWitness{}
			key := func(row, operation string) string {
				return row + "/memory=" + strconv.FormatBool(strings.Contains(operation, "("))
			}
			for _, fixture := range cases {
				byCarrier[key(fixture.row, fixture.witness.Instruction)] = fixture.witness
			}
			adapted := 0
			for _, original := range x86LegacyLiteralSIMDSourceCases(t, catalog, false) {
				if _, selected := expected[original.row]; !selected {
					continue
				}
				initialized, found := byCarrier[key(original.row, original.witness.Instruction)]
				if !found {
					t.Fatal("canonical literal source lost its initialized carrier", original)
				}
				before := append([]byte(nil), original.witness.Encoding...)
				projected := x86LegacyLiteralSIMDInitializedCarrier(t, original, arch)
				if !bytes.Equal(before, original.witness.Encoding) || !reflect.DeepEqual(projected.witness, initialized) {
					t.Fatal("carrier projection mutated its canonical bytes or differs from the actual public input", original.row)
				}
				canonicalSource := x86ScalarLaneInstruction(t, original.witness.Instruction).Args[1]
				initializedSource := x86ScalarLaneInstruction(t, initialized.Instruction).Args[1]
				if original.witness.Instruction != initialized.Instruction {
					adapted++
					want := append([]byte(nil), before...)
					want[len(want)-2] = 0x0e
					unchanged := initialized
					unchanged.First, unchanged.Instruction, unchanged.Encoding = original.witness.First, original.witness.Instruction, original.witness.Encoding
					if canonicalSource.Kind != OpMem || canonicalSource.Mem.Base != AX ||
						initializedSource.Kind != OpMem || initializedSource.Mem.Base != SI || initialized.First != "(SI)" ||
						initialized.Instruction != strings.Replace(original.witness.Instruction, "(AX)", "(SI)", 1) ||
						!bytes.Equal(initialized.Encoding, want) || !reflect.DeepEqual(unchanged, original.witness) {
						t.Fatal("carrier projection changed more than its exact source role, spelling and ModRM", original.row)
					}
					t.Logf("INITIALIZED_CARRIER row=%s canonical=%q bytes=%x initialized=%q bytes=%x", original.row,
						original.witness.Instruction, original.witness.Encoding, initialized.Instruction, initialized.Encoding)
				}
				identity[arch] = append(identity[arch], witnessPair{original.row, original.witness, initialized, canonicalSource, initializedSource})
			}
			if adapted != 2 || len(identity[arch]) != 46 {
				t.Fatal("exact canonical/initialized carrier projection changed", arch, adapted, len(identity[arch]))
			}
		})
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_LEGACY_IMMEDIATE_SIMD_IDENTITY_OUTPUT", identity)
	}
}

func TestX86LegacyImmediateSIMDUnaryInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range []string{"PSHUFL $7,X0,X1", "PSHUFD $7,X0,X1", "PSHUFHW $7,X0,X1", "PSHUFLW $7,X0,X1", "AESKEYGENASSIST $7,X0,X1"} {
			t.Run(arch+"/"+operation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, operation)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal("complete unary immediate typed contract missing", err)
				}
				for _, operand := range effect.operands {
					if operand.operand.Kind == OpReg && operand.operand.Reg == "X1" && operand.read {
						t.Fatal("unary immediate instruction acquired an old-destination read", operation)
					}
				}
				source, declaration := x86LegacyImmediateSIMDInitializedFunction(t, "Unary", operation, arch)
				source = strings.Replace(source, "MOVOU (BX),X1\n", "", 1)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api)
					if err != nil || ir == "" {
						t.Fatal("unary immediate instruction borrowed an old destination", api, err)
					}
				}
			})
		}
	}
}

func TestX86LegacyImmediateSIMDPackedStringLengthRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range []string{"PCMPESTRI $7,X0,X1", "PCMPESTRM $7,(SI),X1"} {
			t.Run(arch+"/"+operation, func(t *testing.T) {
				source, declaration := x86LegacyImmediateSIMDInitializedFunction(t, "Lengths", operation, arch)
				word, move := goWordSize(arch), "Q"
				if word == 4 {
					move = "L"
				}
				for _, item := range []struct {
					register, parameter string
					offset              int
				}{{"AX", "A", 3*word + 8}, {"DX", "B", 3*word + 16}} {
					load := fmt.Sprintf("MOVL length%s+%d(FP),%s\n", item.parameter, item.offset, item.register)
					if strings.Count(source, load) != 1 {
						t.Fatal("missing exact independent length load", load)
					}
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api); err != nil || ir == "" {
							t.Fatal("initialized packed-string control failed", api, err)
						}
						for _, replacement := range []string{"", fmt.Sprintf("MOV%s SI,%s\n", move, item.register)} {
							missing := strings.Replace(source, load, replacement, 1)
							ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, arch, testTargetTriple("linux", arch), api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) ||
								!strings.Contains(err.Error(), "result initialization: unknown effect or undefined input") || !strings.Contains(err.Error(), operation) {
								t.Fatal("undefined or pointer length became a numerical input", item.register, replacement, api, err)
							}
						}
					}
				}
			})
		}
	}
}

// Do not seed unrelated source bytes before scalar memory instructions. The
// existing typed-FP span owner independently checks every required byte; these
// source/object controls do not replace native runtime or page-fault owners.
func TestX86LegacyImmediateSIMDTypedMemoryInputWidths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, item := range []struct {
			operation string
			width     int
		}{
			{"INSERTPS $7,(AX),X1", 4},
			{"ROUNDSS $7,(AX),X1", 4},
			{"ROUNDSD $7,(AX),X1", 8},
			{"ROUNDPS $7,(AX),X1", 16},
			{"ROUNDPD $7,(AX),X1", 16},
		} {
			t.Run(arch+"/"+item.operation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, item.operation)
				width := 0
				if form, known, err := x86RoundProperties(ins, arch); known {
					if err != nil {
						t.Fatal(err)
					}
					width = form.memoryBytes
				} else if form, known, err := x86InsertExtractProperties(ins, arch); known {
					if err != nil {
						t.Fatal(err)
					}
					width = form.spec.chunk
				}
				if width != item.width {
					t.Fatal("actual typed scalar/packed memory width changed", width, item.width)
				}
				source, declaration := x86LegacyImmediateSIMDInitializedFunction(t, "MemoryWidth", item.operation, arch)
				if strings.Contains(source, "MOVOU (SI),X0") {
					t.Fatal("memory-only initializer added an unrelated full-vector source read")
				}
				declaration = strings.Replace(declaration, "a,b *[16]byte", fmt.Sprintf("a *[%d]byte,b *[16]byte", item.width), 1)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api)
					if err != nil || ir == "" {
						t.Fatal("exact-width initialized source rejected", api, err)
					}
				}
			})
		}
	}
}

func TestX86LegacyCryptoInitializedInputBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, item := range []struct {
			operation, removed string
			input              Reg
		}{
			{"AESENC X0,X1", "MOVOU (AX),X0\n", "X0"},
			{"AESENC X0,X1", "MOVOU (BX),X1\n", "X1"},
			{"SHA1MSG1 X0,X1", "MOVOU (AX),X0\n", "X0"},
			{"SHA256MSG2 X0,X1", "MOVOU (BX),X1\n", "X1"},
		} {
			t.Run(arch+"/"+item.operation+"/"+strings.TrimSpace(item.removed), func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, item.operation)
				effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
				if !known || err != nil {
					t.Fatal("complete typed crypto input contract absent", err)
				}
				read := false
				for _, operand := range effect.operands {
					read = read || operand.read && operand.operand.Kind == OpReg && operand.operand.Reg == item.input
				}
				if !read {
					t.Fatal("negative did not remove a required numerical source or old destination", item.input)
				}
				source, declaration := x86LegacyMediaInitializedFunction("CryptoInputs", item.operation, arch)
				if strings.Count(source, item.removed) != 1 {
					t.Fatal("negative must remove exactly one original source or old destination")
				}
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api); err != nil || ir == "" {
						t.Fatal("complete numerical input control rejected", api, err)
					}
					missing := strings.Replace(source, item.removed, "", 1)
					ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, arch, testTargetTriple("linux", arch), api)
					if arch == "386" {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) ||
							!strings.Contains(err.Error(), "result initialization: unknown effect or undefined input") ||
							!strings.Contains(err.Error(), "MOVOU X1,0(DX)") {
							t.Fatal("mode32 invented undefined vector inputs", api, err)
						}
					} else {
						x86VectorScratchCodegenControl(t, missing, declaration, arch, testTargetTriple("linux", arch), ir, err)
					}
				}
			})
		}
		// AESIMC is unary. The same removal must not invent an old-destination
		// dependency merely because the neighboring AES rounds consume it.
		instruction := x86ScalarLaneInstruction(t, "AESIMC X0,X1")
		effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
		if !known || err != nil {
			t.Fatal("unary AESIMC typed contract absent", err)
		}
		for _, operand := range effect.operands {
			if operand.operand.Reg == "X1" && operand.read {
				t.Fatal("unary AESIMC was granted an old-destination read")
			}
		}
		source, declaration := x86LegacyMediaInitializedFunction("CryptoUnary", "AESIMC X0,X1", arch)
		source = strings.Replace(source, "MOVOU (BX),X1\n", "", 1)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api); err != nil || ir == "" {
				t.Fatal("unary AESIMC borrowed an old-destination requirement", arch, api, err)
			}
		}
	}
}

func TestX86LegacyMediaRemainderInitializedInputsRemainRequired(t *testing.T) {
	for _, item := range []struct{ operation, removed string }{
		{"PADDB M0,M1", "MOVQ (BX),M1\n"},
		{"PADDB M0,M1", "MOVQ (AX),M0\n"},
		{"PADDB M0,M1", "EMMS\n"},
		{"CVTSD2SS X0,X1", "MOVOU (BX),X1\n"},
		{"COMISD X0,X1", "MOVOU (AX),X0\n"},
	} {
		t.Run(item.operation+"/"+strings.TrimSpace(item.removed), func(t *testing.T) {
			source, declaration := x86LegacyMediaInitializedFunction("MediaMissing", item.operation, "amd64")
			if strings.Count(source, item.removed) != 1 {
				t.Fatal("negative did not remove exactly one initialized input/state boundary")
			}
			source = strings.Replace(source, item.removed, "", 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if item.operation != "PADDB M0,M1" {
					x86VectorScratchCodegenControl(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", ir, err)
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("source transport supplied missing NUM/old bytes or MMX state", api, err)
				}
			}
		})
	}
}

func TestX86LegacyMediaRemainderVoidAndForeignNativeRemainRejected(t *testing.T) {
	for _, operation := range []string{"PADDB M0,M1", "COMISD X0,X1", "CVTSD2SS X0,X1"} {
		for _, api := range []string{"text", "module", "Go"} {
			source := "TEXT ·MediaVoid(SB),4,$0-0\n" + operation + "\nRET\n"
			if ir, err := x86ScalarFPBitViewAPI(t, source, "func MediaVoid()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("dead Void result hid uninitialized media inputs", operation, api, err)
			}
		}
	}
	source, declaration := x86LegacyMediaInitializedFunction("MediaForeign", "PADDB M0,M1", "amd64")
	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "aarch64-unknown-linux-gnu", api); err == nil || ir != "" {
			t.Fatal("source MMX transport supplied foreign native-target permission", api, err)
		}
	}
}
