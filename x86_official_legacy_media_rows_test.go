package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
		var cases []x86OfficialPackedCase
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: witness})
			}
		}
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
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
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
