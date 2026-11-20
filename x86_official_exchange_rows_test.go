package plan9asm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Original literal bytes and selected row indices are independent of the
// source formatter. AX/AX is a genuine opcode-90 NOP, including its L spelling.
func x86ExchangeOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	type sample struct {
		row             int
		operands, bytes string
	}
	fixtures := map[string][]sample{
		"XCHGB": {{0, "CL,BL", "86cb"}, {0, "CL,0(SI)", "860e"}, {1, "0(SI),BL", "861e"}},
		"XADDB": {{0, "CL,BL", "0fc0cb"}, {0, "CL,0(SI)", "0fc00e"}},
	}
	for _, width := range []struct{ suffix, prefix string }{{"W", "66"}, {"L", ""}, {"Q", "48"}} {
		p := width.prefix
		fixtures["XCHG"+width.suffix] = []sample{
			{0, "AX,BX", p + "93"}, {0, "AX,AX", p + "90"}, {1, "BX,AX", p + "93"},
			{2, "CX,BX", p + "87cb"}, {2, "CX,0(SI)", p + "870e"}, {3, "0(SI),BX", p + "871e"},
		}
		fixtures["XADD"+width.suffix] = []sample{{0, "CX,BX", p + "0fc1cb"}, {0, "CX,0(SI)", p + "0fc10e"}}
	}
	var cases []x86OfficialPackedCase
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		samples, found := fixtures[entry.Opcode]
		if !found {
			continue
		}
		if seen[entry.Opcode] {
			t.Fatal("duplicate exchange source table", entry.Opcode)
		}
		seen[entry.Opcode] = true
		for _, fixture := range samples {
			code, err := hex.DecodeString(fixture.bytes)
			if err != nil || fixture.row >= len(entry.Rows) {
				t.Fatal("independent exchange fixture changed", err)
			}
			cases = append(cases, x86OfficialPackedCase{
				row: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, fixture.row),
				witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " " + fixture.operands,
					Destination: strings.Split(fixture.operands, ",")[1], Encoding: code},
			})
		}
	}
	if len(seen) != 8 || len(cases) != 29 {
		t.Fatal("independent full exchange byte inventory changed", len(seen), len(cases))
	}
	return cases
}

func TestX86ExchangeOriginalCompleteRowsAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	all := x86ExchangeOriginalCases(t, catalog)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			var cases []x86OfficialPackedCase
			for _, original := range all {
				if arch == "386" && strings.HasSuffix(strings.Fields(original.witness.Instruction)[0], "Q") {
					continue
				}
				fixture := original
				fixture.symbol = fmt.Sprint("ExchangeOriginal", len(cases))
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", fixture.symbol)
				fixture.line = strings.Count(source.String(), "\n") + 1
				fmt.Fprintln(&source, fixture.witness.Instruction)
				source.WriteString("RET\n")
				cases = append(cases, fixture)
			}
			want := 29
			if arch == "386" {
				want = 21
			}
			if len(cases) != want || want > 32 {
				t.Fatal("complete exchange mode/byte union changed", len(cases), want)
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
				t.Fatal("independent original exchange byte/row ownership", err)
			}
		})
	}
	for _, fixture := range all {
		if !strings.HasSuffix(strings.Fields(fixture.witness.Instruction)[0], "Q") {
			continue
		}
		t.Run("386-refusal/"+fixture.witness.Instruction, func(t *testing.T) {
			x86ScalarLiteralExpectedGoListing(t, "386", "TEXT ·NoQ(SB),4,$0-0\n"+fixture.witness.Instruction+"\nRET\n", false)
		})
	}
}

func TestX86OfficialExchangeSourceJoinAndInitializedObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	all := x86ExchangeOriginalCases(t, catalog)
	modes := make(map[string][]goasmrules.X86ScalarRMWRow)
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86ExchangeRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		expected := map[string]x86OfficialPackedCase{}
		for _, fixture := range all {
			if arch == "386" && strings.HasSuffix(strings.Fields(fixture.witness.Instruction)[0], "Q") {
				continue
			}
			key := fixture.row + "/" + fixture.witness.Instruction
			if _, found := expected[key]; found {
				t.Fatal("duplicate independent row/instruction owner", key)
			}
			expected[key] = fixture
		}
		filtered := 0
		for _, row := range rows {
			if row.ModeFiltered != "" {
				if arch != "386" || !strings.HasSuffix(row.Opcode, "Q") || len(row.Witnesses) != 0 {
					t.Fatal("source row lost its original mode restriction", row)
				}
				filtered++
				continue
			}
			if len(row.Witnesses) == 0 {
				t.Fatal("unfiltered original exchange row lost its witness", row.ID)
			}
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				fixture, found := expected[key]
				if !found || !bytes.Equal(witness.Encoding, fixture.witness.Encoding) || witness.Destination != fixture.witness.Destination {
					t.Fatal("production exchange view differs from independent original bytes/direction", key, witness, fixture)
				}
				delete(expected, key)
			}
		}
		wantFiltered := 0
		if arch == "386" {
			wantFiltered = 5
		}
		if len(rows) != 18 || len(expected) != 0 || filtered != wantFiltered {
			t.Fatal("complete exchange source/mode join changed", arch, len(rows), len(expected), filtered)
		}
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_EXCHANGE_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			word, move := goWordSize(target.arch), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			count := 0
			for _, fixture := range all {
				if target.arch == "386" && strings.HasSuffix(strings.Fields(fixture.witness.Instruction)[0], "Q") {
					continue
				}
				name := fmt.Sprint("ExchangeSource", count)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s memory+0(FP),SI\n%s old+%d(FP),BX\n%s input+%d(FP),CX\n%s accumulator+%d(FP),AX\n%s\nXOR%s AX,BX\nXOR%s CX,BX\n%s BX,ret+%d(FP)\nRET\n",
					name, 5*word, move, move, word, move, 2*word, move, 3*word, fixture.witness.Instruction, move[3:], move[3:], move, 4*word)
				fmt.Fprintf(&declarations, "func %s(memory *[16]byte,old,input,accumulator uintptr) uintptr\n", name)
				count++
			}
			want := 29
			if target.arch == "386" {
				want = 21
			}
			if count != want || count > 32 {
				t.Fatal("initialized exchange whole-source inventory changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized original exchange source rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}

func x86ExchangeObjectDisassembly(t *testing.T, llc, objdump, triple, ir, level string) string {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "exchange.ll"), filepath.Join(dir, "exchange.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+triple, "-filetype=obj", input, "-o", object))
	bytes, err := os.ReadFile(object)
	if err != nil || len(bytes) == 0 {
		t.Fatal("exchange target object missing", err)
	}
	listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "-d", object))
	t.Logf("EXCHANGE_TARGET_OBJECT triple=%s level=%s bytes=%d\n%s", triple, level, len(bytes), listing)
	return string(listing)
}

func x86ExchangeObjectPrefixError(disassembly, widths string) error {
	header := regexp.MustCompile(`^[0-9a-f]+ <([^>]+)>:$`)
	want := map[string]bool{}
	for _, width := range widths {
		for _, locked := range []bool{false, true} {
			want[fmt.Sprintf("Prefix%c_%t", width, locked)] = locked
		}
	}
	seen := map[string]int{}
	var failures []error
	owner := ""
	previousEnd, previousLock := uint64(0), false
	for _, line := range strings.Split(disassembly, "\n") {
		if match := header.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			owner = strings.TrimPrefix(match[1], "_")
			previousEnd, previousLock = 0, false
			continue
		}
		address, rest, found := strings.Cut(strings.TrimSpace(line), ":")
		pc, err := strconv.ParseUint(address, 16, 64)
		if !found || err != nil {
			continue
		}
		fields := strings.Fields(rest)
		var code []byte
		for len(fields) != 0 && len(fields[0]) == 2 {
			value, err := strconv.ParseUint(fields[0], 16, 8)
			if err != nil {
				break
			}
			code, fields = append(code, byte(value)), fields[1:]
		}
		if len(code) == 0 || len(fields) == 0 {
			continue
		}
		mnemonic := fields[0]
		if strings.HasPrefix(mnemonic, "xadd") || mnemonic == "lock" && len(fields) > 1 && strings.HasPrefix(fields[1], "xadd") {
			locked, expected := want[owner]
			if !expected {
				failures = append(failures, fmt.Errorf("unowned target exchange instruction %s: %s", owner, line))
				continue
			}
			if mnemonic == "lock" {
				mnemonic = fields[1]
			}
			seen[owner]++
			actualLock := code[0] == 0xf0 || previousLock && previousEnd == pc
			if actualLock != locked || mnemonic != "xadd"+strings.ToLower(owner[6:7]) {
				failures = append(failures, fmt.Errorf("%s locked=%t want=%t: %s", owner, actualLock, locked, line))
			}
		}
		previousEnd = pc + uint64(len(code))
		previousLock = len(code) == 1 && code[0] == 0xf0 && mnemonic == "lock"
	}
	for owner := range want {
		if seen[owner] != 1 {
			failures = append(failures, fmt.Errorf("target function %s has %d XADDs, want one", owner, seen[owner]))
		}
	}
	return errors.Join(failures...)
}

func TestX86ExchangeObjectPrefixReaderBoundaries(t *testing.T) {
	// LLVM22's actual default disassembly separates f0 from the following
	// opcode. Keep its observed function/byte shape, including symbol spelling.
	const listing = "0000 <PrefixB_false>:\n0: 0f c0 07 xaddb %al,(%rdi)\n" +
		"0003 <PrefixB_true>:\n3: f0 lock\n4: 0f c0 07 xaddb %al,(%rdi)\n"
	for _, sample := range []struct {
		name, text string
		valid      bool
	}{
		{"observed", listing, true},
		{"platform-underscore", strings.ReplaceAll(listing, "<Prefix", "<_Prefix"), true},
		{"swapped-functions", strings.NewReplacer("PrefixB_false", "PrefixB_true", "PrefixB_true", "PrefixB_false").Replace(listing), false},
		{"other-next-opcode", strings.Replace(listing, "4: 0f", "4: 90 nop\n5: 0f", 1), false},
		{"nonadjacent-prefix", strings.Replace(listing, "4: 0f", "5: 0f", 1), false},
		{"wrong-width", strings.ReplaceAll(listing, "xaddb", "xaddw"), false},
		{"foreign-owner", strings.Replace(listing, "PrefixB_true", "Other", 1), false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if err := x86ExchangeObjectPrefixError(sample.text, "B"); (err == nil) != sample.valid {
				t.Fatal("object prefix reader changed its function/adjacency/width boundary", err)
			}
		})
	}
}

func TestX86ExchangeMemoryPrefixOriginalAndLLVMObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump are required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			widths := "BWLQ"
			if target.arch == "386" {
				widths = "BWL"
			}
			var source, declarations strings.Builder
			var bodies, prefixes []x86OfficialPackedCase
			for _, width := range widths {
				for _, locked := range []bool{false, true} {
					body := fmt.Sprintf("XADD%c CX,1(SI)", width)
					if width == 'B' {
						body = "XADDB CL,1(SI)"
					}
					if locked {
						body = "LOCK\n" + body
					}
					program, declaration := x86UnlockedScalarRMWFixture(target.arch, body, true)
					name := fmt.Sprintf("Prefix%c_%t", width, locked)
					position := strings.Index(program, "\nXADD")
					if position < 0 {
						t.Fatal("original source lost its XADD")
					}
					line := strings.Count(source.String(), "\n") + strings.Count(program[:position+1], "\n") + 1
					end := strings.IndexByte(program[position+1:], '\n') + position + 1
					code := []byte{0x0f, 0xc1, 0x4c, 0x1f, 0xff} // CX,-1(DI)(BX*1).
					if width == 'B' {
						code[1] = 0xc0
					} else if width == 'W' {
						code = append([]byte{0x66}, code...)
					} else if width == 'Q' {
						code = append([]byte{0x48}, code...)
					}
					fixture := x86OfficialPackedCase{symbol: name, row: name, line: line,
						witness: goasmrules.X86PackedBinaryWitness{Instruction: program[position+1 : end], Encoding: code}}
					bodies = append(bodies, fixture)
					if locked {
						fixture.line--
						fixture.witness.Instruction, fixture.witness.Encoding = "LOCK", []byte{0xf0}
					}
					prefixes = append(prefixes, fixture)
					source.WriteString(strings.Replace(program, "·Value", "·"+name, 1))
					declarations.WriteString(strings.Replace(declaration, "Value", name, 1) + "\n")
				}
			}
			// Original assembler output retains every explicit prefix, independently
			// of the translator's template and LLVM's machine encoder.
			listing, err := x86ScalarLiteralGoListing(t, target.arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, original := range [][]x86OfficialPackedCase{bodies, prefixes} {
				if err := x86OfficialPackedVerifyListing(listing, original); err != nil {
					t.Fatal("original Go function lost its exact XADD/prefix bytes", err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized complete bare/LOCK exchange source rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						disassembly := x86ExchangeObjectDisassembly(t, llc, objdump, target.triple, ir, level)
						if err := x86ExchangeObjectPrefixError(disassembly, widths); err != nil {
							t.Error("EXCHANGE_ORIGINAL_PREFIX_CHANGED", api, level, err)
						}
					}
				})
			}
		})
	}
}

func TestX86ExchangeHighByteOriginalPhysicalViews(t *testing.T) {
	for _, stem := range []struct{ name, opcode string }{{"XCHG", "86"}, {"XADD", "0fc0"}} {
		for _, sample := range []struct {
			operands, prefix, modrm string
			context                 bool
		}{
			{"AH,AL", "", "e0", false}, {"AL,AH", "", "c4", false}, {"AH,BL", "", "e3", false},
			{"AH,R8", "41", "e0", true}, {"R8,AH", "44", "c4", true}, {"AH,(R8)", "41", "20", true},
			{"AH,BPB", "40", "e5", true}, {"BPB,AH", "40", "ec", true}, {"AH,SIB", "40", "e6", true}, {"AH,DIB", "40", "e7", true},
			{"BL,BPB", "40", "dd", false}, {"BPB,BL", "40", "eb", false},
		} {
			operation := stem.name + "B " + sample.operands
			t.Run(operation, func(t *testing.T) {
				source := "TEXT ·ExchangeByte(SB),4,$0-0\n" + operation + "\nRET\n"
				code, err := hex.DecodeString(sample.prefix + stem.opcode + sample.modrm)
				if err != nil {
					t.Fatal(err)
				}
				fixture := x86OfficialPackedCase{symbol: "ExchangeByte", line: 2, row: operation,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: operation, Encoding: code}}
				listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
				if err != nil {
					t.Fatal(err)
				}
				if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{fixture}); err != nil {
					t.Fatal("actual physical byte-view oracle", err)
				}
				instruction := x86ScalarLaneInstruction(t, operation)
				spec := amd64ExchangeSpecs[instruction.Op]
				_, err = parseAMD64ExchangeForm("amd64", instruction.Op, spec, instruction)
				if sample.context && !errors.Is(err, ErrProbeNeedsContext) || !sample.context && err != nil {
					t.Error("EXCHANGE_HIGH_BYTE_PHYSICAL_VIEW_CHANGED", sample.context, err)
				}
			})
		}
		t.Run(stem.name+"/LOCK-high-byte-memory", func(t *testing.T) {
			operation := stem.name + "B AH,(R8)"
			source := "TEXT ·LockedByte(SB),4,$0-0\nLOCK\n" + operation + "\nRET\n"
			code, err := hex.DecodeString("41" + stem.opcode + "20")
			if err != nil {
				t.Fatal(err)
			}
			listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
			if err != nil {
				t.Fatal(err)
			}
			for _, original := range []x86OfficialPackedCase{
				{symbol: "LockedByte", line: 2, row: operation, witness: goasmrules.X86PackedBinaryWitness{Instruction: "LOCK", Encoding: []byte{0xf0}}},
				{symbol: "LockedByte", line: 3, row: operation, witness: goasmrules.X86PackedBinaryWitness{Instruction: operation, Encoding: code}},
			} {
				if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{original}); err != nil {
					t.Fatal("original LOCK/REX byte view changed", err)
				}
			}
			instruction := x86ScalarLaneInstruction(t, operation)
			if _, err := parseAMD64ExchangeForm("amd64", instruction.Op, amd64ExchangeSpecs[instruction.Op], instruction); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("LOCK granted an unbound physical high-byte view", err)
			}
		})
	}
}

func TestX86ExchangeHighBytePublicInputBoundaries(t *testing.T) {
	for _, sample := range []struct {
		operation string
		context   bool
		memory    bool
	}{
		{"XADDB AH,AL", false, false}, {"XADDB AL,AH", false, false}, {"XADDB AH,BL", false, false},
		{"XADDB AL,R8", false, false}, {"XADDB AH,R8", true, false}, {"XADDB R8,AH", true, false},
		{"XADDB AH,(R8)", true, true},
	} {
		t.Run(sample.operation, func(t *testing.T) {
			declaration := "func ExchangeInput(memory *[16]byte,seed,old uintptr) uintptr\n"
			address := "MOVQ old+16(FP),R8\n"
			if sample.memory {
				address = "MOVQ memory+0(FP),R8\n"
			}
			source := "TEXT ·ExchangeInput(SB),4,$0-32\nMOVQ seed+8(FP),AX\nMOVQ old+16(FP),BX\n" +
				address + sample.operation + "\nMOVQ AX,ret+24(FP)\nRET\n"
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if sample.context {
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Error("unbound original REX byte view acquired NUM", api, err)
					}
				} else if err != nil || ir == "" {
					t.Error("initialized original byte alias lost its public continuation", api, err)
				}
			}
		})
	}
}
