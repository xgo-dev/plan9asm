package plan9asm

// Original source rows, selected Go bytes and initialized API objects are
// distinct observations. These owners do not establish runtime semantics.
import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var legacyGPRMWDraftNames = regexp.MustCompile(`^(ADC|ADD|AND|OR|SBB|SUB|XOR|INC|DEC|NEG|NOT|BTC|BTR|BTS)[BWLQ]$`)

func x86MoveExtensionOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	seen := map[string]bool{}
	for _, reference := range x86ExtensionNativeOracle {
		var entry goasmrules.X86LegacyOpcode
		for _, candidate := range catalog.Optab {
			if candidate.Opcode == reference.op {
				entry = candidate
			}
		}
		if entry.Opcode == "" || seen[entry.Opcode] || entry.Ytab != reference.table || entry.Prefix != reference.prefix {
			t.Fatal("independent original extension source identity changed", reference.op)
		}
		seen[entry.Opcode] = true
		if arch == "386" && reference.amd64Only {
			continue
		}
		prefix := map[string][]byte{"Pm": {0x0f}, "Pq": {0x66, 0x0f}, "Pe": {0x66}, "Pw": {0x48}, "Px": {}}[reference.prefix]
		code := append([]byte(nil), prefix...)
		for _, atom := range strings.Split(reference.bytes, ",") {
			value, err := strconv.ParseUint(strings.TrimSpace(atom), 0, 8)
			if err != nil {
				t.Fatal(err)
			}
			code = append(code, byte(value))
		}
		for _, source := range []struct {
			operand string
			modrm   byte
		}{{"CX", 0xd9}, {"0(SI)", 0x1e}} {
			cases = append(cases, x86OfficialPackedCase{row: fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab),
				witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " " + source.operand + ",BX", Destination: "BX", Encoding: append(append([]byte(nil), code...), source.modrm)}})
		}
	}
	if len(seen) != 14 || len(cases) != map[string]int{"amd64": 28, "386": 18}[arch] {
		t.Fatal("complete extension source/mode union changed", arch, len(seen), len(cases))
	}
	return cases
}

func TestX86OfficialMoveExtensionOriginalGoBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		cases := x86MoveExtensionOriginalCases(t, catalog, arch)
		t.Run(arch+"/projection", func(t *testing.T) {
			rows, err := goasmrules.X86ScalarMoveExtensionRows(catalog, arch)
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
					if !found || !bytes.Equal(witness.Encoding, original.Encoding) || witness.Destination != original.Destination {
						t.Fatal("extension row/instruction/bytes/destination join differs", key, witness, original)
					}
					delete(expected, key)
				}
			}
			if len(expected) != 0 {
				t.Fatal("original extension source witness omitted", expected)
			}
		})
		x86ImplicitMulDivOriginalByteBatches(t, arch, cases)
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_MOVE_EXTENSION_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}

func TestX86OfficialMoveExtensionInitializedThreeAPIFiveObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		x86Legacy127Objects(t, arch, x86MoveExtensionOriginalCases(t, catalog, arch),
			func(name, instruction, mode string) (string, string) {
				return x86ScalarRMRegisterInitializedFunction(name, instruction, mode)
			})
	}
}

func TestX86OfficialMoveExtensionModePhysicalAliasesActualGo(t *testing.T) {
	observations := 0
	for _, arch := range []string{"amd64", "386"} {
		for _, reference := range x86ExtensionNativeOracle {
			for _, pair := range [][2]string{{"AL", "BX"}, {"AH", "BX"}, {"AH", "R8"}, {"BP", "BX"}, {"SI", "BX"},
				{"DI", "BX"}, {"SP", "BX"}, {"SPB", "BX"}, {"R8", "BX"}, {"CX", "R8"}} {
				observations++
				instruction := reference.op + " " + pair[0] + "," + pair[1]
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					accepted := !(arch == "386" && reference.amd64Only) && pair[0] != "SPB"
					if reference.table != "ymb_rl" && (pair[0] == "AL" || pair[0] == "AH") ||
						arch == "386" && (pair[0] == "R8" || pair[1] == "R8" || reference.table == "ymb_rl" && pair[0] == "SP") {
						accepted = false
					}
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", "", accepted)
					if !accepted {
						return
					}
					ins := x86YMMReadSource(t, instruction)
					form, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch)
					if !known || err != nil {
						t.Fatal("Go-valid extension alias lost its existing typed grammar", err)
					}
					want := Reg(pair[0])
					if reference.table == "ymb_rl" && reference.source == 2 && pair[0] == "AL" {
						want = AX
					} else if pair[0] == "AH" && (reference.source == 2 || arch == "amd64" && (reference.destination == 8 || pair[1] == "R8")) {
						want = SP
					}
					if form.source.Reg != want || form.spec.sourceBits != reference.source*8 {
						t.Fatal("physical source/tuple differs from original encoding", form.source.Reg, want, form.spec.sourceBits)
					}
					// Syntax/physical projection is not a numerical input proof.
				})
			}
		}
	}
	if observations != 280 {
		t.Fatal("complete source/mode/physical-alias observation matrix changed", observations)
	}
}

func x86ImplicitMulDivOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) []x86OfficialPackedCase {
	t.Helper()
	numeric := regexp.MustCompile(`^(?:I?MUL|I?DIV)[BWLQ]$`)
	var cases []x86OfficialPackedCase
	count := 0
	for _, entry := range catalog.Optab {
		if !numeric.MatchString(entry.Opcode) || entry.Ytab != "ydivb" && entry.Ytab != "ydivl" && entry.Ytab != "yimul" {
			continue
		}
		count++
		width := entry.Opcode[len(entry.Opcode)-1]
		if arch == "386" && width == 'Q' {
			continue
		}
		opcode, err := strconv.ParseUint(entry.OpBytes[0], 0, 8)
		if err != nil {
			t.Fatal(err)
		}
		extension, err := strconv.ParseUint(entry.OpBytes[1], 0, 3)
		if err != nil {
			t.Fatal(err)
		}
		var prefix []byte
		if width == 'W' {
			prefix = []byte{0x66}
		} else if width == 'Q' {
			prefix = []byte{0x48}
		}
		register := "CX"
		if width == 'B' {
			register = "CL"
		}
		for _, source := range []struct {
			operand string
			modrm   byte
		}{{register, 0xc1}, {"0(SI)", 0x06}} {
			cases = append(cases, x86OfficialPackedCase{
				row: fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab),
				witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " " + source.operand,
					Destination: "AX", Encoding: append(append([]byte(nil), prefix...), byte(opcode), source.modrm|byte(extension)<<3)},
			})
		}
	}
	if count != 16 || len(cases) != map[string]int{"amd64": 32, "386": 24}[arch] {
		t.Fatal("complete implicit integer family/mode inventory changed", count, arch, len(cases))
	}
	return cases
}

func x86ImplicitMulDivOriginalByteBatches(t *testing.T, arch string, cases []x86OfficialPackedCase) {
	t.Helper()
	for start := 0; start < len(cases); start += 32 {
		end := start + 32
		if end > len(cases) {
			end = len(cases)
		}
		t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
			batch := cases[start:end]
			var source strings.Builder
			for index := range batch {
				batch[index].symbol = fmt.Sprintf("ImplicitRow%d", index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[index].symbol)
				batch[index].line = strings.Count(source.String(), "\n") + 1
				fmt.Fprintln(&source, batch[index].witness.Instruction)
				fmt.Fprintln(&source, "RET")
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
				t.Fatal("original implicit row/register/byte encoding differs", err)
			}
		})
	}
}

func TestX86OfficialImplicitMulDivOriginalGoBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		cases := x86ImplicitMulDivOriginalCases(t, catalog, arch)
		t.Run(arch+"/projection", func(t *testing.T) {
			rows, err := goasmrules.X86ScalarImplicitMulDivRows(catalog, arch)
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
					if !found || !bytes.Equal(witness.Encoding, original.Encoding) || witness.Destination != original.Destination {
						t.Fatal("implicit row/instruction/bytes/destination join differs", key, witness, original)
					}
					delete(expected, key)
				}
			}
			if len(expected) != 0 {
				t.Fatal("implicit original witness omitted", expected)
			}
		})
		x86ImplicitMulDivOriginalByteBatches(t, arch, cases)
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_IMPLICIT_MULDIV_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}

func x86ImplicitMulDivInitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "Q"
	if word == 4 {
		move = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\nMOV%s memory+%d(FP),SI\n"+
		"MOV%s low+%d(FP),AX\nMOV%s high+%d(FP),DX\nMOV%s input+%d(FP),CX\n%s\n"+
		"MOV%s AX,0(DI)\nMOV%s DX,%d(DI)\n",
		name, 5*word, move, move, word, move, 2*word, move, 3*word, move, 4*word, operation, move, move, word)
	// Division's undefined status must never become a public output. Product
	// owners independently observe CF/OF; upper AX/DX bytes remain visible.
	if !strings.Contains(strings.Fields(operation)[0], "DIV") {
		source += fmt.Sprintf("SETCS CL\nMOVB CL,%d(DI)\nSETOS CL\nMOVB CL,%d(DI)\n", 2*word, 2*word+1)
	}
	return source + "RET\n", fmt.Sprintf("func %s(out *[32]byte,memory *[8]byte,low,high,input uintptr)\n", name)
}

func TestX86OfficialImplicitMulDivInitializedThreeAPIFiveObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		x86Legacy127Objects(t, arch, x86ImplicitMulDivOriginalCases(t, catalog, arch), x86ImplicitMulDivInitializedFunction)
	}
}

func TestX86OfficialImplicitMulDivByteAliasesOriginalGo(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	aliases := []struct {
		name    string
		rm, rex byte
	}{
		{"AL", 0, 0}, {"CL", 1, 0}, {"DL", 2, 0}, {"BL", 3, 0},
		{"AH", 4, 0}, {"CH", 5, 0}, {"DH", 6, 0}, {"BH", 7, 0},
		{"AX", 0, 0}, {"CX", 1, 0}, {"DX", 2, 0}, {"BX", 3, 0},
		{"SP", 4, 0x40}, {"BP", 5, 0x40}, {"SI", 6, 0x40}, {"DI", 7, 0x40},
		{"SPB", 4, 0x40}, {"BPB", 5, 0x40}, {"SIB", 6, 0x40}, {"DIB", 7, 0x40},
	}
	for index := 8; index < 16; index++ {
		for _, suffix := range []string{"", "B"} {
			aliases = append(aliases, struct {
				name    string
				rm, rex byte
			}{fmt.Sprintf("R%d%s", index, suffix), byte(index - 8), 0x41})
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		var cases []x86OfficialPackedCase
		synthesized, refused := 0, 0
		for _, entry := range catalog.Optab {
			if entry.Ytab != "ydivb" || !regexp.MustCompile(`^(?:I?MUL|I?DIV)B$`).MatchString(entry.Opcode) {
				continue
			}
			opcode, _ := strconv.ParseUint(entry.OpBytes[0], 0, 8)
			extension, _ := strconv.ParseUint(entry.OpBytes[1], 0, 3)
			for _, alias := range aliases {
				instruction := entry.Opcode + " " + alias.name
				if alias.name == "SPB" || arch == "386" && alias.rex != 0 {
					accepted := arch == "386" && (alias.name == "BP" || alias.name == "SI" || alias.name == "DI")
					if accepted {
						synthesized++
					} else {
						refused++
					}
					t.Run(arch+"-special/"+instruction, func(t *testing.T) {
						// Go synthesizes the three physical byte sources in mode32.
						// Acceptance is separate from the direct-byte expectations.
						// Explicit SPB is rejected in both modes; SP remains its
						// separate legal low-byte spelling in AMD64.
						goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", "", accepted)
					})
					continue
				}
				var code []byte
				if alias.rex != 0 {
					code = append(code, alias.rex)
				}
				code = append(code, byte(opcode), 0xc0|byte(extension)<<3|alias.rm)
				cases = append(cases, x86OfficialPackedCase{row: entry.Opcode + "/byte-alias",
					witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: code}})
			}
		}
		if len(aliases) != 36 || len(cases) != map[string]int{"amd64": 140, "386": 48}[arch] ||
			synthesized != map[string]int{"amd64": 0, "386": 12}[arch] || refused != map[string]int{"amd64": 4, "386": 84}[arch] {
			t.Fatal("complete byte-bank/mode inventory changed", arch, len(cases), synthesized, refused)
		}
		x86ImplicitMulDivOriginalByteBatches(t, arch, cases)
	}
}

func TestX86OfficialImplicitMulDivModeAndOperandRefusals(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, fixture := range x86ImplicitMulDivOriginalCases(t, catalog, "amd64") {
		name := strings.Fields(fixture.witness.Instruction)[0]
		if strings.HasSuffix(name, "Q") {
			t.Run("386-Q/"+fixture.witness.Instruction, func(t *testing.T) {
				goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+fixture.witness.Instruction+"\nRET\n", "", false)
			})
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, source := range []string{"$1", "X0"} {
			t.Run("invalid/"+name+"/"+source, func(t *testing.T) {
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+name+" "+source+"\nRET\n", "", false)
			})
		}
	}
	if len(seen) != 16 {
		t.Fatal("implicit mode/refusal control lost family members", len(seen))
	}
}

// Independent original-table fixture construction. The fixed low registers
// make ModRM direction explicit; the original payload remains the byte source.
// These cases establish encoding, not input definedness or memory authority.
func x86ScalarMultiplyMOVBESourceCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows := 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yimul" && entry.Ytab != "yimul3" && entry.Ytab != "ymovbe" {
			continue
		}
		width := entry.Opcode[len(entry.Opcode)-1]
		for _, row := range entry.Rows {
			rows++
			if arch == "386" && width == 'Q' {
				continue
			}
			var payload []byte
			for _, atom := range entry.OpBytes {
				if atom == "Pm" {
					payload = append(payload, 0x0f)
					continue
				}
				value, err := strconv.ParseUint(atom, 0, 8)
				if err != nil {
					t.Fatal("original GP source atom changed", atom, err)
				}
				payload = append(payload, byte(value))
			}
			var prefix []byte
			if width == 'W' {
				prefix = append(prefix, 0x66)
			}
			if width == 'Q' {
				prefix = append(prefix, 0x48)
			}
			if entry.Ytab == "ymovbe" && width != 'Q' {
				prefix = append(prefix, 0x0f)
			}
			add := func(operands, destination string, code []byte) {
				cases = append(cases, x86OfficialPackedCase{
					row: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex),
					witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " " + operands,
						Destination: destination, Encoding: append(append([]byte(nil), prefix...), code...)},
				})
			}
			offset := row.UnmatchedOffset
			switch entry.Ytab {
			case "yimul":
				switch row.RowIndex {
				case 0:
					add("CX", "AX", []byte{payload[offset], 0xe9})
					add("0(SI)", "AX", []byte{payload[offset], 0x2e})
				case 1, 2:
					value, size := 1, 1
					if row.RowIndex == 2 {
						value, size = 128, 4
						if width == 'W' {
							size = 2
						}
					}
					code := []byte{payload[offset], 0xdb}
					for byteIndex := 0; byteIndex < size; byteIndex++ {
						code = append(code, byte(value>>uint(byteIndex*8)))
					}
					add(fmt.Sprintf("$%d,BX", value), "BX", code)
				case 3:
					add("CX,BX", "BX", []byte{payload[offset], payload[offset+1], 0xd9})
					add("0(SI),BX", "BX", []byte{payload[offset], payload[offset+1], 0x1e})
				}
			case "yimul3":
				value, size := 1, 1
				if row.RowIndex == 1 {
					value, size = 128, 4
					if width == 'W' {
						size = 2
					}
				}
				for _, input := range []struct {
					operand string
					modrm   byte
				}{{"CX", 0xd9}, {"0(SI)", 0x1e}} {
					code := []byte{payload[offset], input.modrm}
					for byteIndex := 0; byteIndex < size; byteIndex++ {
						code = append(code, byte(value>>uint(byteIndex*8)))
					}
					add(fmt.Sprintf("$%d,%s,BX", value, input.operand), "BX", code)
				}
			case "ymovbe":
				code := append([]byte(nil), payload[offset:offset+row.ZOffset+entry.EscapeAdjustment-1]...)
				if row.RowIndex == 0 {
					add("0(SI),BX", "BX", append(code, 0x1e))
				} else {
					add("CX,0(SI)", "0(SI)", append(code, 0x0e))
				}
			}
		}
	}
	if rows != 24 || len(cases) != map[string]int{"amd64": 36, "386": 24}[arch] {
		t.Fatal("complete original GP source/mode count changed", arch, rows, len(cases))
	}
	return cases
}

func TestX86OfficialScalarMultiplyMOVBEOriginalGoBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		cases := x86ScalarMultiplyMOVBESourceCases(t, catalog, arch)
		t.Run(arch+"/projection", func(t *testing.T) {
			rows, err := goasmrules.X86ScalarMultiplyMOVBERows(catalog, arch)
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
					if !found || !bytes.Equal(witness.Encoding, original.Encoding) || witness.Destination != original.Destination {
						t.Fatal("source row/instruction/encoding/destination join differs", key, witness, original)
					}
					delete(expected, key)
				}
			}
			if len(expected) != 0 {
				t.Fatal("original source witnesses omitted from the production projection", expected)
			}
		})
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				batch := cases[start:end]
				var source strings.Builder
				for index := range batch {
					batch[index].symbol = fmt.Sprintf("OriginalGP%d", index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[index].symbol)
					batch[index].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[index].witness.Instruction)
					fmt.Fprintln(&source, "RET")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal(err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("independent original GP row/bytes mismatch", err)
				}
			})
		}
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_SCALAR_MULTIPLY_MOVBE_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}

func TestX86OfficialScalarMultiplyImmediateFirstMatchGoBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		var cases []x86OfficialPackedCase
		for _, value := range []int{-129, -128, 127, 128, 255} {
			for _, canonical := range x86ScalarMultiplyMOVBESourceCases(t, catalog, arch) {
				parts := strings.Split(canonical.row, "/")
				if parts[3] != "yimul" && parts[3] != "yimul3" {
					continue
				}
				row, _ := strconv.Atoi(parts[4])
				short := value >= -128 && value <= 127
				if parts[3] == "yimul" && row != map[bool]int{true: 1, false: 2}[short] ||
					parts[3] == "yimul3" && row != map[bool]int{true: 0, false: 1}[short] {
					continue
				}
				fixture := canonical
				old := "$128"
				if short {
					old = "$1"
				}
				fixture.witness.Instruction = strings.Replace(canonical.witness.Instruction, old, fmt.Sprintf("$%d", value), 1)
				size := 1
				if !short {
					size = 4
					if strings.HasSuffix(parts[2], "W") {
						size = 2
					}
				}
				code := append([]byte(nil), canonical.witness.Encoding[:len(canonical.witness.Encoding)-size]...)
				for index := 0; index < size; index++ {
					code = append(code, byte(value>>uint(index*8)))
				}
				fixture.witness.Encoding = code
				cases = append(cases, fixture)
			}
		}
		if len(cases) != map[string]int{"amd64": 45, "386": 30}[arch] {
			t.Fatal("complete signed-immediate first-match inventory changed", arch, len(cases))
		}
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				batch := cases[start:end]
				var source strings.Builder
				for index := range batch {
					batch[index].symbol = fmt.Sprintf("ImmediateGP%d", index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[index].symbol)
					batch[index].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[index].witness.Instruction)
					fmt.Fprintln(&source, "RET")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal(err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("original Go Yi8/Yi32 first-match or immediate width differs", err)
				}
			})
		}
	}
}

func TestX86OfficialScalarMultiplyMOVBEModeAndRegisterRefusals(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, fixture := range x86ScalarMultiplyMOVBESourceCases(t, catalog, "amd64") {
		instruction := fixture.witness.Instruction
		if strings.HasSuffix(strings.Fields(instruction)[0], "Q") {
			t.Run("386-Q/"+fixture.row+"/"+instruction, func(t *testing.T) {
				goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
			})
		}
		if seen[fixture.row] {
			continue
		}
		seen[fixture.row] = true
		register := "BX"
		if strings.Contains(instruction, "CX") {
			register = "CX"
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run("high-register/"+arch+"/"+fixture.row, func(t *testing.T) {
				line := strings.Replace(instruction, register, "R8", 1)
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+line+"\nRET\n", "", arch == "amd64")
			})
		}
		t.Run("high-byte/"+fixture.row, func(t *testing.T) {
			line := strings.Replace(instruction, register, "AH", 1)
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+line+"\nRET\n", "", false)
		})
	}
	if len(seen) != 24 {
		t.Fatal("mode and register observation lost an original row", len(seen))
	}
}

func x86ScalarMultiplyMOVBEInitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "Q"
	if word == 4 {
		move = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\nMOV%s memory+%d(FP),SI\n"+
		"MOV%s old+%d(FP),AX\nMOV%s AX,BX\nMOV%s AX,DX\nMOV%s input+%d(FP),CX\nCMPL CX,CX\n%s\n"+
		"MOV%s AX,0(DI)\nMOV%s DX,%d(DI)\nMOV%s BX,%d(DI)\n"+
		"SETCS CL\nMOVB CL,%d(DI)\nSETOS CL\nMOVB CL,%d(DI)\nRET\n",
		name, 4*word, move, move, word, move, 2*word, move, move, move, 3*word, operation,
		move, move, word, move, 2*word, 3*word, 3*word+1)
	return source, fmt.Sprintf("func %s(out *[32]byte,memory *[8]byte,old,input uintptr)\n", name)
}

func TestX86OfficialScalarMultiplyMOVBEInitializedThreeAPIFiveObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		cases := x86ScalarMultiplyMOVBESourceCases(t, catalog, arch)
		x86Legacy127Objects(t, arch, cases, x86ScalarMultiplyMOVBEInitializedFunction)
	}
}

func TestX86OfficialScalarRMWCompleteSourceCarrier(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86LockScalarEncoderCarrier(source); err != nil {
		t.Fatal(err)
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, rows := 0, 0
	for _, entry := range catalog.Optab {
		if legacyGPRMWDraftNames.MatchString(entry.Opcode) {
			names++
			rows += len(entry.Rows)
		}
	}
	if names != 53 || rows != 169 {
		t.Fatal("complete source family changed", names, rows)
	}
}

func TestX86OfficialScalarRMWFirstMatchActualGoBytes(t *testing.T) {
	// These are source/encoding anchors, deliberately not claimed as observable
	// translation or numerical execution. Keep the AL/AX original spelling.
	cases := []struct {
		instruction string
		encoding    []byte
	}{
		{"ADDB $128,AL", []byte{0x04, 0x80}},
		{"ADDB $128,AX", []byte{0x80, 0xc0, 0x80}},
		{"ADDL $1,AX", []byte{0x83, 0xc0, 0x01}},
		{"ADDL $128,AX", []byte{0x05, 0x80, 0, 0, 0}},
		{"ADDL $128,BX", []byte{0x81, 0xc3, 0x80, 0, 0, 0}},
		{"ADDL CX,BX", []byte{0x01, 0xcb}},
		{"ADDL 0(SI),BX", []byte{0x03, 0x1e}},
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range cases {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + row.instruction + "\nRET\n"
				actual := x86PackedShiftActualGoBytes(t, arch, source)
				expected := append(append([]byte(nil), row.encoding...), 0xc3)
				if !bytes.Equal(actual, expected) {
					t.Fatalf("original selected row bytes=%x want=%x", actual, expected)
				}
			})
		}
		for _, row := range []struct {
			instruction  string
			short, modrm byte
		}{
			{"INCL AX", 0x40, 0xc0}, {"DECL AX", 0x48, 0xc8},
		} {
			actual := x86PackedShiftActualGoBytes(t, arch, "TEXT f(SB),4,$0-0\n"+row.instruction+"\nRET\n")
			expected := []byte{row.short, 0xc3}
			if arch == "amd64" {
				expected = []byte{0xff, row.modrm, 0xc3}
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("Px1 mode selection %s/%s: %x want=%x", arch, row.instruction, actual, expected)
			}
		}
	}
}

func TestX86OfficialScalarRMWRegisterCarrySeedObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple, want := 8, "Q", "x86_64-unknown-linux-gnu", 106
		if arch == "386" {
			word, move, triple, want = 4, "L", "i386-unknown-linux-gnu", 78
		}
		count, batch := 0, 0
		var source, declarations strings.Builder
		flush := func() {
			if source.Len() == 0 {
				return
			}
			// Full sources contain initialized real inputs and two observable
			// results, not no-result/unused statements or a constant7 return.
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if err != nil || ir == "" {
					t.Fatalf("observable GP producer %s/%s/batch%d: %v", arch, api, batch, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			}
			source.Reset()
			declarations.Reset()
			batch++
		}
		for _, entry := range catalog.Optab {
			op := entry.Opcode
			if !legacyGPRMWDraftNames.MatchString(op) || arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			width, stem := op[len(op)-1], op[:len(op)-1]
			operand, destination := "CX", "AX"
			if width == 'B' {
				operand, destination = "CL", "AL"
			}
			if strings.HasPrefix(stem, "BT") {
				operand = "$1"
			}
			instruction := op + " " + operand + "," + destination
			if stem == "INC" || stem == "DEC" || stem == "NEG" || stem == "NOT" {
				instruction = op + " " + destination
			}
			for _, seed := range []string{"CLC", "STC"} {
				name := fmt.Sprintf("GPRMW%d", count)
				fmt.Fprintf(&declarations, "func %s(old,value uintptr) (data,flags uintptr)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s old+0(FP),AX\nMOV%s value+%d(FP),CX\nCMPL CX,CX\n%s\n%s\n", name, word*4, move, move, word, seed, instruction)
				// MOV observes actual data without changing status. POP's
				// partial-bit identity must be consumed by the next AND only.
				fmt.Fprintf(&source, "MOV%s AX,data+%d(FP)\nPUSHF%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,flags+%d(FP)\nRET\n", move, word*2, move, move, move, x86ScalarRuntimeStatusMask(stem), move, word*3)
				count++
				if count%32 == 0 {
					flush()
				}
			}
		}
		flush()
		if count != want {
			t.Fatal("observable full mnemonic closure changed", arch, count, want)
		}
	}
}

// This adapter gives the GP row its real input/output roles; only the existing
// byte-listing observer consumes a packed-case shell, with no packed initializer
// or vector fields granting data, FLAGS or source-storage capabilities.
func x86OfficialScalarRMWAssembly(cases []x86OfficialPackedCase, witnesses []goasmrules.X86ScalarRMWWitness, arch string) (string, string) {
	word, move := 8, "Q"
	if arch == "386" {
		word, move = 4, "L"
	}
	var source, declarations strings.Builder
	for index, witness := range witnesses {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprintf("GPRow%d", index)
		stem := strings.Fields(witness.Instruction)[0]
		stem = stem[:len(stem)-1]
		memoryResult := witness.Destination == "0(SI)"
		result, size := "(data,flags uintptr)", word*5
		if memoryResult {
			result, size = "(flags uintptr)", word*4
		}
		fmt.Fprintf(&declarations, "func %s(memory *[16]byte,old,value uintptr) %s\n", fixture.symbol, result)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),SI\nMOV%s old+%d(FP),AX\nMOV%s AX,BX\nMOV%s value+%d(FP),CX\nCMPL CX,CX\nCLC\n",
			fixture.symbol, size, move, move, word, move, move, word*2)
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, witness.Instruction)
		flagOffset := word * 3
		if !memoryResult {
			register := "BX"
			if witness.Destination == "AX" || witness.Destination == "AL" {
				register = "AX"
			}
			fmt.Fprintf(&source, "MOV%s %s,data+%d(FP)\n", move, register, word*3)
			flagOffset += word
		}
		fmt.Fprintf(&source, "PUSHF%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,flags+%d(FP)\nRET\n",
			move, move, move, x86ScalarRuntimeStatusMask(stem), move, flagOffset)
	}
	return source.String(), declarations.String()
}

func TestX86OfficialScalarRMWRowsSelectedGoBytesThreeAPIsObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, mode := range []struct {
		arch, triple     string
		selected, shapes int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 167, 278},
		{"386", "i386-unknown-linux-gnu", 124, 202},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			rows, err := goasmrules.X86ScalarRMWRows(catalog, mode.arch)
			if err != nil {
				t.Fatal(err)
			}
			var witnesses []goasmrules.X86ScalarRMWWitness
			var cases []x86OfficialPackedCase
			selected := 0
			for _, row := range rows {
				if row.ModeFiltered != "" {
					continue
				}
				selected++
				for _, witness := range row.Witnesses {
					cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: goasmrules.X86PackedBinaryWitness{Instruction: witness.Instruction, Encoding: witness.Encoding}})
					witnesses = append(witnesses, witness)
				}
			}
			if len(rows) != 169 || selected != mode.selected || len(witnesses) != mode.shapes {
				t.Fatal("source/mode/selected denominator changed", len(rows), selected, len(witnesses))
			}
			for start := 0; start < len(cases); start += 32 {
				end := start + 32
				if end > len(cases) {
					end = len(cases)
				}
				t.Run(fmt.Sprintf("batch%02d", start/32), func(t *testing.T) {
					batch := cases[start:end]
					source, declarations := x86OfficialScalarRMWAssembly(batch, witnesses[start:end], mode.arch)
					listing, err := x86ScalarLiteralGoListing(t, mode.arch, source)
					if err != nil {
						t.Fatal(err)
					}
					if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
						t.Fatal("actual selected Go byte identity", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declarations, mode.arch, mode.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized data/defined FLAGS continuation", err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, mode.triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86OfficialScalarRMWOriginalShadowsAndModeSelection(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86ScalarRMWRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		byName := map[string][]goasmrules.X86ScalarRMWRow{}
		for _, row := range rows {
			byName[row.Opcode] = append(byName[row.Opcode], row)
		}
		var cases []x86OfficialPackedCase
		var source strings.Builder
		add := func(from, selected goasmrules.X86ScalarRMWRow, witness goasmrules.X86ScalarRMWWitness) {
			name := fmt.Sprintf("Shadow%d", len(cases))
			line := strings.Count(source.String(), "\n") + 2
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, witness.Instruction)
			cases = append(cases, x86OfficialPackedCase{row: from.ID + " -> " + selected.ID, symbol: name, line: line,
				witness: goasmrules.X86PackedBinaryWitness{Instruction: witness.Instruction, Encoding: witness.Encoding}})
		}
		for _, entry := range catalog.Optab {
			group := byName[entry.Opcode]
			if len(group) == 0 || arch == "386" && entry.Prefix == "Pw" {
				continue
			}
			switch entry.Ytab {
			case "yxorb":
				add(group[1], group[0], group[0].Witnesses[0])
				add(group[3], group[2], group[2].Witnesses[0])
				// Class match sees AX before Pb converts it to AL. Therefore
				// this spelling selects generic /digit, not accumulator opcode.
				alias := group[1].Witnesses[0]
				alias.Instruction = strings.Replace(alias.Instruction, "BL", "AX", 1)
				alias.Encoding = append([]byte(nil), alias.Encoding...)
				alias.Encoding[1] &^= 7
				add(group[0], group[1], alias)
			case "yaddl":
				short := group[0].Witnesses[0]
				short.Instruction = strings.Replace(short.Instruction, "BX", "AX", 1)
				short.Encoding = append([]byte(nil), short.Encoding...)
				short.Encoding[len(short.Encoding)-2] &^= 7
				add(group[1], group[0], short)
				add(group[2], group[0], group[0].Witnesses[0])
				add(group[2], group[1], group[1].Witnesses[0])
				add(group[4], group[3], group[3].Witnesses[0])
			case "yincl":
				if arch == "386" {
					add(group[1], group[0], group[0].Witnesses[0])
				} else {
					add(group[0], group[1], group[1].Witnesses[0])
				}
			}
		}
		want := 107
		if arch == "386" {
			want = 79
		}
		if len(cases) != want {
			t.Fatal("ordered shadow/mode observations changed", arch, len(cases), want)
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("actual Go first-match/alias selection", arch, err)
		}
		for _, fixture := range cases {
			t.Logf("SCALAR_GO_SELECTION arch=%s mapping=%q source=%q encoding=%x", arch, fixture.row,
				fixture.witness.Instruction, fixture.witness.Encoding)
		}
	}
	// Preserve all45 Q source rows: each has valid amd64 syntax which the actual
	// 386 assembler must reject independently, rather than one combined failing
	// source hiding acceptance of another row. These are source rejection only.
	rows, err := goasmrules.X86ScalarRMWRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	qrows := 0
	for _, row := range rows {
		if !strings.HasSuffix(row.Opcode, "Q") {
			continue
		}
		qrows++
		t.Run(row.ID, func(t *testing.T) {
			if len(row.Witnesses) == 0 {
				t.Fatal("valid amd64 source row lost its syntax")
			}
			listing, _ := x86ScalarLiteralExpectedGoListing(t, "386", "TEXT f(SB),4,$0-0\n"+row.Witnesses[0].Instruction+"\nRET\n", false)
			t.Logf("SCALAR_GO_MODE_REJECTION row=%q source=%q diagnostic=%q", row.ID, row.Witnesses[0].Instruction, listing)
		})
	}
	if qrows != 45 {
		t.Fatal("Q-width mode boundary changed", qrows)
	}
}

func TestX86OfficialScalarRMWObservableInputAndFlagBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "L", 4, "i386-unknown-linux-gnu"
		}
		body := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOV%s old+0(FP),AX\nMOV%s value+%d(FP),CX\nCMPL CX,CX\nCLC\nANDB CL,AL\nMOV%s AX,data+%d(FP)\nPUSHF%s\nPOP%s AX\nAND%s $2245,AX\nMOV%s AX,flags+%d(FP)\nRET\n", word*4, move, move, word, move, word*2, move, move, move, move, word*3)
		for _, control := range []struct {
			name, from, to string
			pass           bool
		}{
			{"complete", "", "", true},
			{"undefined-AF", "$2245", "$2261", false},
			{"unmasked-flags", "AND" + move + " $2245,AX\n", "", false},
			{"expired-popped-bits", "AND" + move + " $2245,AX", "NOP\nAND" + move + " $2245,AX", false},
			{"missing-old", "MOV" + move + " old+0(FP),AX\n", "", false},
			{"missing-source", "MOV" + move + fmt.Sprintf(" value+%d(FP),CX\n", word), "", false},
			{"unknown-carry", "CMPL CX,CX\nCLC\nANDB CL,AL", "ADCB CL,AL", false},
		} {
			t.Run(arch+"/"+control.name, func(t *testing.T) {
				source := body
				if control.from != "" {
					if strings.Count(source, control.from) != 1 {
						t.Fatal("mutation not uniquely source-bound")
					}
					source = strings.Replace(source, control.from, control.to, 1)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(old,value uintptr) (data,flags uintptr)", arch, triple, api)
					if control.pass && (err != nil || ir == "") || !control.pass && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
						t.Fatal("real data/defined-status proof changed", api, control.pass, err)
					}
				}
			})
		}
	}
}
