package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86LegacyShiftRotateCompleteSourceRecords(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, group2, double, q := map[string]bool{}, 0, 0, 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yshb" && entry.Ytab != "yshl" {
			continue
		}
		names[entry.Opcode] = true
		group2 += len(entry.Rows)
		if strings.HasSuffix(entry.Opcode, "Q") {
			q += len(entry.Rows)
		}
	}
	for _, row := range catalog.Movtab {
		if row.Code != "movDoubleShift" {
			continue
		}
		if !names[row.Opcode] || row.From3 != "Yrl" || row.To != "Yml" {
			t.Fatal("foreign double-shift roles", row)
		}
		double++
		if strings.HasSuffix(row.Opcode, "Q") {
			q++
		}
	}
	if len(names) != 32 || group2 != 120 || double != 18 || q != 38 {
		t.Fatal("complete legacy closure changed", len(names), group2, double, q)
	}
}

func TestX86LegacyShiftRotateFirstMatchAndCLActualGoBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		var cases []x86OfficialPackedCase
		for _, anchor := range []struct {
			row  string
			code []byte
		}{
			{"SHLL $0,AX", []byte{0xc1, 0xe0, 0}},
			{"SHLL $1,AX", []byte{0xd1, 0xe0}},
			{"SHLL $7,AX", []byte{0xc1, 0xe0, 7}},
			{"SALL $1,AX", []byte{0xd1, 0xe0}},
			{"SHLL CL,AX", []byte{0xd3, 0xe0}},
			{"SHLL CX,AX", []byte{0xd3, 0xe0}},
			{"SHLB CL,BL", []byte{0xd2, 0xe3}},
			{"SHLB CX,BL", []byte{0xd2, 0xe3}},
			{"SHLW $1,AX,BX", []byte{0x66, 0x0f, 0xa4, 0xc3, 1}},
			{"SHLW $-1,AX,BX", []byte{0x66, 0x0f, 0xa4, 0xc3, 0xff}},
			{"SHLW CL,AX,BX", []byte{0x66, 0x0f, 0xa5, 0xc3}},
			{"SHLW CX,AX,BX", []byte{0x66, 0x0f, 0xa5, 0xc3}},
		} {
			name := fmt.Sprint("ShiftAnchor", len(cases))
			line := strings.Count(source.String(), "\n") + 2
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, anchor.row)
			cases = append(cases, x86OfficialPackedCase{row: "independent/legacy-shift/" + anchor.row, symbol: name, line: line,
				witness: goasmrules.X86PackedBinaryWitness{Instruction: anchor.row, Encoding: anchor.code}})
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("first-match/SAL/SHL/CL/CX byte identity", arch, err)
		}
	}
}

func TestX86LegacyShiftRotateExistingObservableProducer(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "Q", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "L", "i386-unknown-linux-gnu"
		}
		var source, declarations strings.Builder
		for index, row := range []struct {
			instruction string
			mask        uint64
		}{
			{"SHLL $0,BX", 0x8d5}, {"SHLL $1,BX", 0x8c5}, {"SHLL $7,BX", 0xc5},
			{"RCLL CX,BX", 0xd5}, {"SHRB CX,BL", 0xc4},
			{"SHLW $16,AX,BX", 0xc5}, {"SHLW CX,AX,BX", 0},
		} {
			name := fmt.Sprint("ShiftProof", index)
			fmt.Fprintf(&declarations, "func %s(memory *[16]byte,old,value,count uintptr) (data,flags uintptr)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),SI\nMOV%s old+%d(FP),BX\nMOV%s value+%d(FP),AX\nMOV%s count+%d(FP),CX\nCMPL AX,AX\nCLC\n%s\nMOV%s BX,data+%d(FP)\nPUSHF%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,flags+%d(FP)\nRET\n",
				name, word*6, move, move, word, move, word*2, move, word*3, row.instruction, move, word*4, move, move, move, row.mask, move, word*5)
		}
		x86LEAActualTargetGoObject(t, arch, triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("existing initialized data/count/CF and scoped status producer", arch, api, err)
			}
			x86ResultInitializationObject(t, llc, triple, ir, "legacy-shift-existing-"+api)
		}
	}
}

func x86OfficialScalarShiftAssembly(cases []x86OfficialPackedCase, witnesses []goasmrules.X86ScalarRMWWitness, arch string) (string, string) {
	word, move := 8, "Q"
	if arch == "386" {
		word, move = 4, "L"
	}
	var source, declarations strings.Builder
	for index, witness := range witnesses {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprint("ShiftRow", index)
		opcode, operands, _ := strings.Cut(witness.Instruction, " ")
		bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[opcode[len(opcode)-1]]
		choice := bits == 16 && strings.Count(operands, ",") == 2 && !strings.HasPrefix(operands, "$")
		metadata := x86ShiftMemoryRuntimeMetadata(x86ShiftMemoryOracle{text: witness.Instruction, bits: bits, valueChoice: choice})
		result, size := "(data,flags uintptr)", word*6
		if witness.Destination == "0(SI)" {
			result, size = "(flags uintptr)", word*5
		}
		fmt.Fprintf(&declarations, "func %s(memory *[16]byte,old,value,count uintptr) %s\n", fixture.symbol, result)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),SI\nMOV%s old+%d(FP),BX\nMOV%s value+%d(FP),AX\nMOV%s count+%d(FP),CX\nCMPL AX,AX\nCLC\n",
			fixture.symbol, size, move, move, word, move, word*2, move, word*3)
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, witness.Instruction)
		flagOffset := word * 4
		if witness.Destination != "0(SI)" {
			fmt.Fprintf(&source, "MOV%s BX,data+%d(FP)\n", move, word*4)
			flagOffset += word
		}
		fmt.Fprintf(&source, "PUSHF%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,flags+%d(FP)\nRET\n",
			move, move, move, metadata.flags, move, flagOffset)
	}
	return source.String(), declarations.String()
}

func TestX86LegacyShiftRotateRowsSelectedGoBytesThreeAPIObjects(t *testing.T) {
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
		{"amd64", "x86_64-unknown-linux-gnu", 138, 356},
		{"386", "i386-unknown-linux-gnu", 100, 264},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			rows, err := goasmrules.X86ScalarShiftRotateRows(catalog, mode.arch)
			if err != nil {
				t.Fatal(err)
			}
			var cases []x86OfficialPackedCase
			var witnesses []goasmrules.X86ScalarRMWWitness
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
			if len(rows) != 138 || selected != mode.selected || len(witnesses) != mode.shapes {
				t.Fatal("shift source/mode/witness denominator changed", len(rows), selected, len(witnesses))
			}
			for start := 0; start < len(cases); start += 32 {
				end := start + 32
				if end > len(cases) {
					end = len(cases)
				}
				t.Run(fmt.Sprintf("batch%02d", start/32), func(t *testing.T) {
					batch := cases[start:end]
					source, declarations := x86OfficialScalarShiftAssembly(batch, witnesses[start:end], mode.arch)
					listing, err := x86ScalarLiteralGoListing(t, mode.arch, source)
					if err != nil {
						t.Fatal(err)
					}
					if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
						t.Fatal("selected original Go shift row bytes", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declarations, mode.arch, mode.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized count/data/carry/status continuation", api, err)
								return
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

func TestX86LegacyShiftRotateShadowsAliasesAndMode(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86ScalarShiftRotateRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		group2, doubles := map[string][]goasmrules.X86ScalarRMWRow{}, map[string][]goasmrules.X86ScalarRMWRow{}
		for _, row := range rows {
			if row.ModeFiltered != "" {
				continue
			}
			if strings.HasPrefix(row.ID, "optab/") {
				group2[row.Opcode] = append(group2[row.Opcode], row)
			} else {
				doubles[row.Opcode] = append(doubles[row.Opcode], row)
			}
		}
		var source strings.Builder
		var cases []x86OfficialPackedCase
		add := func(from, selected goasmrules.X86ScalarRMWRow) {
			for _, w := range selected.Witnesses {
				name := fmt.Sprint("ShiftShadow", len(cases))
				line := strings.Count(source.String(), "\n") + 2
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, w.Instruction)
				cases = append(cases, x86OfficialPackedCase{row: from.ID + " -> " + selected.ID, symbol: name, line: line,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: w.Instruction, Encoding: w.Encoding}})
			}
		}
		// Original table order owns these alternatives. A matching alternative
		// is not a second hit on the later source row.
		for _, entry := range catalog.Optab {
			g := group2[entry.Opcode]
			if len(g) == 0 {
				continue
			}
			add(g[1], g[0])
			if entry.Ytab == "yshl" {
				add(g[3], g[2])
			}
		}
		for _, entry := range catalog.Movtab {
			g := doubles[entry.Opcode]
			if entry.Code == "movDoubleShift" && entry.From == "Ycx" && len(g) != 0 {
				add(g[2], g[1])
			}
		}
		want := 124
		if arch == "386" {
			want = 88
		}
		if len(cases) != want {
			t.Fatal("shadow selection denominator changed", arch, len(cases), want)
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("actual Go shift first-match selection", err)
		}
		for _, fixture := range cases {
			t.Logf("SHIFT_GO_SELECTION arch=%s mapping=%q source=%q encoding=%x", arch, fixture.row, fixture.witness.Instruction, fixture.witness.Encoding)
		}
	}
	rows, err := goasmrules.X86ScalarShiftRotateRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	q := 0
	for _, row := range rows {
		if !strings.HasSuffix(row.Opcode, "Q") {
			continue
		}
		q++
		t.Run(row.ID, func(t *testing.T) {
			if len(row.Witnesses) == 0 {
				t.Fatal("Q source lost its valid amd64 spelling")
			}
			listing, _ := x86ScalarLiteralExpectedGoListing(t, "386", "TEXT f(SB),4,$0-0\n"+row.Witnesses[0].Instruction+"\nRET\n", false)
			t.Logf("SHIFT_GO_MODE_REJECTION row=%q source=%q diagnostic=%q", row.ID, row.Witnesses[0].Instruction, listing)
		})
	}
	if q != 38 {
		t.Fatal("Q source mode boundary changed", q)
	}
}

func TestX86LegacyShiftRotateObservableInputBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "Q", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "L", "i386-unknown-linux-gnu"
		}
		for _, control := range []string{"complete", "missing-old", "missing-count", "missing-carry", "missing-double-data", "unmasked-flags", "expired-popped-bits"} {
			t.Run(arch+"/"+control, func(t *testing.T) {
				instruction := "RCLL CX,BX"
				if control == "missing-double-data" {
					instruction = "SHLL $1,AX,BX"
				}
				w := goasmrules.X86ScalarRMWWitness{Instruction: instruction, Destination: "BX"}
				cases := []x86OfficialPackedCase{{row: "independent/shift-input/" + control}}
				source, declaration := x86OfficialScalarShiftAssembly(cases, []goasmrules.X86ScalarRMWWitness{w}, arch)
				from, to := "", ""
				switch control {
				case "missing-old":
					from = fmt.Sprintf("MOV%s old+%d(FP),BX\n", move, word)
				case "missing-count":
					from = fmt.Sprintf("MOV%s count+%d(FP),CX\n", move, word*3)
				case "missing-carry":
					from = "CMPL AX,AX\nCLC\n"
				case "missing-double-data":
					from = fmt.Sprintf("MOV%s value+%d(FP),AX\n", move, word*2)
				case "unmasked-flags":
					from = fmt.Sprintf("AND%s $213,AX\n", move)
				case "expired-popped-bits":
					from = fmt.Sprintf("POP%s AX\nAND%s", move, move)
					to = fmt.Sprintf("POP%s AX\nNOP\nAND%s", move, move)
				}
				if from != "" {
					if strings.Count(source, from) != 1 {
						t.Fatal("mutation not bound to one producer fragment", control, source)
					}
					source = strings.Replace(source, from, to, 1)
				}
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					pass := control == "complete"
					if pass && (err != nil || ir == "") || !pass && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
						t.Fatal("source count/data/CF/status proof changed", api, control, err)
					}
				}
			})
		}
	}
}
