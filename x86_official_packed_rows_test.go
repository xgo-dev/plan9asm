package plan9asm

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86OfficialPackedCase struct {
	row, symbol string
	line        int
	witness     goasmrules.X86PackedBinaryWitness
}

// This joins official table ownership to physical Go bytes and initialized
// public API translation. It is object coverage, not executed semantics.
// Existing independent family runtime oracles remain a separate gate.
func TestX86OfficialPackedRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedBinaryPilotRows, 159, 480, 2)
}

func TestX86OfficialAverageMultiplyRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedAverageMultiplyRows, 90, 258, 0)
}

func TestX86OfficialLogicalRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedLogicalRows, 132, 504, 0)
}

func TestX86OfficialUnpackRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedUnpackRows, 108, 360, 0)
}

func TestX86OfficialNarrowRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedNarrowRows, 36, 114, 0)
}

func TestX86OfficialPerLaneShiftRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedPerLaneShiftRows, 64, 236, 0)
}

func TestX86OfficialSignRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedSignRows, 9, 18, 0)
}

func TestX86OfficialAbsRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjectsUsing(t, goasmrules.X86PackedAbsRows, 33, 108, 0, x86OfficialAbsAssembly)
}

func TestX86OfficialHorizontalIntegerRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedHorizontalIntegerRows, 18, 36, 0)
}

func TestX86OfficialByteShuffleRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedByteShuffleRows, 9, 24, 0)
}

func TestX86OfficialIntegerCompareRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedIntegerCompareRows, 72, 168, 0)
}

func TestX86OfficialMaskBlendRowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86PackedMaskBlendRows, 36, 144, 0)
}

func TestX86OfficialMinMaxRowsInitializedThreeAPIsObjects(t *testing.T) {
	verified := x86OfficialPackedRowsObjects(t, goasmrules.X86PackedIntegerMinMaxRows, 132, 432, 0)
	narrowEVEX := 0
	for _, fixture := range verified {
		w := fixture.witness
		name := strings.Fields(w.Instruction)[0]
		if w.Generation == "evex" && w.Width < 512 && !w.Masked && !w.Broadcast && !strings.HasSuffix(name, "Q") {
			narrowEVEX++
		}
	}
	if narrowEVEX != 48 {
		t.Fatalf("only %d/48 original unmasked non-Q EVEX X/Y witnesses verified", narrowEVEX)
	}
	t.Log("48 non-Q unmasked EVEX X/Y register/memory forms retain their actual Go EVEX bytes through initialized APIs and LLVM objects; low-bank VEX success is not substituted")
}

func x86OfficialPackedRowsObjects(t *testing.T,
	buildRows func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error),
	wantRows, wantFormats, wantAliases int) []x86OfficialPackedCase {
	t.Helper()
	return x86OfficialPackedRowsObjectsUsing(t, buildRows, wantRows, wantFormats, wantAliases, x86OfficialPackedAssembly)
}

func x86OfficialPackedRowsObjectsUsing(t *testing.T,
	buildRows func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error),
	wantRows, wantFormats, wantAliases int,
	assembly func([]x86OfficialPackedCase) (string, string)) []x86OfficialPackedCase {
	t.Helper()
	return x86OfficialPackedRowsObjectsInspect(t, buildRows, wantRows, wantFormats, wantAliases, assembly,
		func(*testing.T, string, []x86OfficialPackedCase) {})
}

func x86OfficialPackedRowsObjectsInspect(t *testing.T,
	buildRows func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error),
	wantRows, wantFormats, wantAliases int,
	assembly func([]x86OfficialPackedCase) (string, string),
	inspect func(*testing.T, string, []x86OfficialPackedCase)) []x86OfficialPackedCase {
	t.Helper()
	return x86OfficialPackedRowsObjectsForTarget(t, "amd64", "x86_64-unknown-linux-gnu",
		buildRows, wantRows, wantFormats, wantAliases, assembly, inspect)
}

func x86OfficialPackedRowsObjectsForTarget(t *testing.T, arch, triple string,
	buildRows func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error),
	wantRows, wantFormats, wantAliases int,
	assembly func([]x86OfficialPackedCase) (string, string),
	inspect func(*testing.T, string, []x86OfficialPackedCase)) []x86OfficialPackedCase {
	t.Helper()
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := buildRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var cases, aliases []x86OfficialPackedCase
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: witness})
			if row.Opcode == "PADDL" {
				witness.Instruction = strings.Replace(witness.Instruction, "PADDL ", "PADDD ", 1)
				aliases = append(aliases, x86OfficialPackedCase{row: "alias/PADDD/" + row.ID, witness: witness})
			}
		}
	}
	if len(rows) != wantRows || len(cases) != wantFormats || len(aliases) != wantAliases {
		t.Fatalf("official binary denominator drift: rows=%d canonical=%d aliases=%d", len(rows), len(cases), len(aliases))
	}
	cases = append(cases, aliases...)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	_, driverHash := x86LEAActualSDKDriver(t)
	t.Logf("row-owned oracle SDK=%s driverSHA=%x; %s only, MMX excluded", runtime.Version(), driverHash, arch)
	passed := 0
	for start := 0; start < len(cases); start += 32 {
		end := start + 32
		if end > len(cases) {
			end = len(cases)
		}
		batch := cases[start:end]
		if t.Run(fmt.Sprintf("batch%02d", start/32), func(t *testing.T) {
			source, declaration := assembly(batch)
			listing, err := x86ScalarLiteralGoListing(t, arch, source)
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
				t.Fatalf("original Go encoding identity: %v\n%s", err, listing)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil {
						t.Fatal(err)
					}
					inspect(t, ir, batch)
					x86ResultInitializationObject(t, llc, triple, ir, api)
				})
			}
		}) {
			passed += len(batch)
		}
	}
	if passed != len(cases) {
		t.Fatalf("only %d/%d row-owned formats passed all original-encoding/public-API/object gates", passed, len(cases))
	}
	t.Logf("%d canonical rows / %d legal format witnesses plus %d aliases: original Go encoding and row-owned functions through all three public APIs + LLVM22 objects passed; no runtime claim",
		wantRows, wantFormats, wantAliases)
	return cases
}

func x86OfficialAbsAssembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		w := fixture.witness
		registers := [3]int{0, 1, 0}
		if !w.Memory {
			registers[0], _ = strconv.Atoi(w.First[1:])
		}
		registers[2], _ = strconv.Atoi(w.Destination[1:])
		body, declaration := x86PackedAbsSignInitializedInstruction(index, w.Instruction, "amd64", registers)
		fixture.symbol = fmt.Sprint("AbsSign", index)
		for offset, instruction := range strings.Split(body, "\n") {
			if instruction == w.Instruction {
				fixture.line = line + offset
			}
		}
		source.WriteString(body)
		declarations.WriteString(declaration)
		line += strings.Count(body, "\n")
	}
	return source.String(), declarations.String()
}

func x86OfficialPackedAssembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declaration strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprintf("Row%d", index)
		w := fixture.witness
		fmt.Fprintf(&declaration, "func %s(out,a,b *byte,mask uint64)\n", fixture.symbol)
		prefix := fmt.Sprintf("TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\n", fixture.symbol)
		move := "VMOVUPS"
		if w.Generation == "legacy" {
			move = "MOVOU"
		}
		seed := ""
		if !w.Memory && w.First != "" {
			if _, valid := amd64ParseKReg(Reg(w.First)); valid {
				seed = fmt.Sprintf("MOVQ (AX),CX\nKMOVQ CX,%s\n", w.First)
			} else if isX86YrlRegisterForArch(Reg(w.First), "amd64") {
				seed = fmt.Sprintf("MOVQ (AX),%s\n", w.First)
			} else {
				prefix += fmt.Sprintf("%s (AX),%s\n", move, w.First)
			}
		}
		if w.Second != "" {
			prefix += fmt.Sprintf("%s (BX),%s\n", move, w.Second)
		}
		if w.Masked {
			prefix += "MOVQ mask+24(FP),CX\nKMOVQ CX,K1\n"
			// A masked K result writes zero for disabled lanes; it never
			// merges an old destination as a masked vector result does.
			if !w.Zeroing && !w.MaskResult {
				prefix += fmt.Sprintf("%s (BX),%s\n", move, w.Destination)
			}
		}
		// Finish pointer-dependent vector/old/mask seeds before a GP input
		// replaces AX. K data comes from a, independently of the mask argument.
		prefix += seed
		fixture.line = line + strings.Count(prefix, "\n")
		store := move
		if w.MaskResult {
			store = "KMOVQ"
		}
		body := prefix + w.Instruction + fmt.Sprintf("\n%s %s,(DX)\nRET\n", store, w.Destination)
		source.WriteString(body)
		line += strings.Count(body, "\n")
	}
	return source.String(), declaration.String()
}

var x86OfficialPackedListingInstruction = regexp.MustCompile(`^\s*0x([0-9a-f]+)\s+([0-9]+)\s+\(.*:([0-9]+)\)\s+([A-Z0-9._]+)(?:\s|$)`)

func x86OfficialPackedVerifyListing(listing string, cases []x86OfficialPackedCase) error {
	owners := map[string]x86OfficialPackedCase{}
	for _, fixture := range cases {
		owners[fixture.symbol] = fixture
	}
	type instruction struct {
		pc, line int
		op       string
	}
	seen := map[string]bool{}
	var owner string
	var code []byte
	var instructions []instruction
	size := 0
	finish := func() error {
		if owner == "" {
			return nil
		}
		fixture := owners[owner]
		if len(instructions) < 2 || len(code) != size || size == 0 || code[size-1] != 0xc3 ||
			instructions[len(instructions)-1].op != "RET" || instructions[len(instructions)-1].pc != size-1 {
			return fmt.Errorf("%s has incomplete Go instruction/byte boundaries", fixture.row)
		}
		matches := 0
		for index, ins := range instructions {
			if ins.line != fixture.line {
				continue
			}
			matches++
			name := strings.Split(strings.Fields(fixture.witness.Instruction)[0], ".")[0]
			if name == "PADDD" {
				name = "PADDL" // Go's frontend alias must retain canonical bytes.
			}
			if strings.Split(ins.op, ".")[0] != name || index+1 == len(instructions) {
				return fmt.Errorf("%s has changed/missing original source instruction", fixture.row)
			}
			end := instructions[index+1].pc
			if ins.pc < 0 || end > len(code) || !bytes.Equal(code[ins.pc:end], fixture.witness.Encoding) {
				return fmt.Errorf("%s %s: original bytes at %d:%d differ from %x", fixture.row,
					fixture.witness.Instruction, ins.pc, end, fixture.witness.Encoding)
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s has %d original source-row matches", fixture.row, matches)
		}
		seen[owner] = true
		return nil
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "STEXT") {
			if err := finish(); err != nil {
				return err
			}
			symbol := strings.TrimPrefix(fields[0], "literal.")
			// Historical Go prints an empty local package even with -p.
			// Accept only these two observed owners, never arbitrary packages.
			if symbol == fields[0] {
				symbol = strings.TrimPrefix(fields[0], `"".`)
			}
			if fields[1] != "STEXT" && fields[1] != "STEXTFIPS" {
				return fmt.Errorf("unknown Go text symbol kind %s", fields[1])
			}
			if _, ok := owners[symbol]; !ok || seen[symbol] || symbol == fields[0] {
				return fmt.Errorf("unowned or duplicate Go function %s", fields[0])
			}
			owner, code, instructions, size = symbol, nil, nil, 0
			for _, field := range fields[2:] {
				if strings.HasPrefix(field, "size=") {
					value, err := strconv.Atoi(strings.TrimPrefix(field, "size="))
					if err != nil || value <= 0 || size != 0 {
						return fmt.Errorf("invalid Go function size: %s", line)
					}
					size = value
				}
			}
			continue
		}
		// Other object symbols have their own byte columns, not function code.
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "S") && !strings.HasPrefix(fields[0], "0x") {
			if err := finish(); err != nil {
				return err
			}
			owner = ""
		}
		if owner == "" {
			continue
		}
		if encoded := x86InsertExtractListedBytes(line); len(encoded) != 0 {
			pc, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 32)
			if err != nil || int(pc) != len(code) {
				return fmt.Errorf("noncontiguous original Go byte columns: %s", line)
			}
			code = append(code, encoded...)
			continue
		}
		match := x86OfficialPackedListingInstruction.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pc, pcErr := strconv.ParseUint(match[1], 16, 32)
		decimal, decimalErr := strconv.ParseUint(match[2], 10, 32)
		sourceLine, lineErr := strconv.Atoi(match[3])
		if pcErr != nil || decimalErr != nil || lineErr != nil || pc != decimal || int(pc) >= size {
			return fmt.Errorf("invalid original Go PC/source row: %s", line)
		}
		if match[4] == "TEXT" || match[4] == "FUNCDATA" || match[4] == "PCDATA" {
			continue
		}
		if len(instructions) == 0 && pc != 0 || len(instructions) != 0 && int(pc) <= instructions[len(instructions)-1].pc {
			return fmt.Errorf("non-increasing original Go instruction PCs: %s", line)
		}
		instructions = append(instructions, instruction{int(pc), sourceLine, match[4]})
	}
	if err := finish(); err != nil {
		return err
	}
	if len(seen) != len(cases) {
		return fmt.Errorf("only %d/%d original Go functions verified", len(seen), len(cases))
	}
	return nil
}

func TestX86OfficialPackedRowListingRejectsFalseIdentity(t *testing.T) {
	cases := []x86OfficialPackedCase{{row: "avx/fixture", symbol: "Row0", line: 2,
		witness: goasmrules.X86PackedBinaryWitness{Instruction: "VPADDD X16,X17,X18", Encoding: []byte{0x62, 0xa1, 0x75, 0, 0xfe, 0xd0}}}}
	byteRow := func(hex, ascii string) string {
		return fmt.Sprintf("  0x0000%-48s  %s\n", " "+hex, ascii)
	}
	originalBytes := byteRow("62 a1 75 00 fe d0 c3", "b.u....")
	listing := `literal.Row0 STEXT nosplit asm size=7 align=0x0 args=0x0 locals=0x0
  0x0000 00000 (literal.s:1) TEXT literal.Row0(SB), NOSPLIT|NOFRAME, $0-0
  0x0000 00000 (literal.s:1) FUNCDATA $0, gclocals(SB)
  0x0000 00000 (literal.s:2) VPADDD X16, X17, X18
  0x0006 00006 (literal.s:3) RET
` + originalBytes
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal(err)
	}
	for _, compatible := range []string{
		strings.ReplaceAll(listing, "literal.Row0", `"".Row0`),
		strings.Replace(listing, "STEXT ", "STEXTFIPS ", 1),
	} {
		if err := x86OfficialPackedVerifyListing(compatible, cases); err != nil {
			t.Fatal("known SDK listing spelling lost row ownership", err)
		}
	}
	for name, changed := range map[string]string{
		"unknown text kind":   strings.Replace(listing, "STEXT ", "STEXTFOREIGN ", 1),
		"VEX instead of EVEX": strings.Replace(listing, originalBytes, byteRow("c5 f1 75 00 fe d0 c3", "..u...."), 1),
		"register extension":  strings.Replace(listing, "a1 75", "e1 75", 1),
		"partial instruction": strings.Replace(listing, "0x0006 00006", "0x0005 00005", 1),
		"wrong source row":    strings.Replace(listing, "literal.s:2", "literal.s:4", 1),
		"wrong owner":         strings.ReplaceAll(listing, "literal.Row0", "literal.Row1"),
		"missing owner":       "",
		"duplicate owner":     listing + listing,
		"truncated bytes":     strings.Replace(listing, originalBytes, byteRow("62 a1 75 00 fe d0", "b.u..."), 1),
		"trailing bytes":      strings.Replace(listing, originalBytes, byteRow("62 a1 75 00 fe d0 c3 90", "b.u....."), 1),
		"byte gap":            strings.Replace(listing, "0x0000 62", "0x0001 62", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := x86OfficialPackedVerifyListing(changed, cases); err == nil {
				t.Fatal("unverified official row identity accepted")
			}
		})
	}
}
