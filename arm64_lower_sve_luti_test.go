package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVELUTICompleteGo127Family(t *testing.T) {
	const header = "TEXT sveluti(SB),$0-0\n"
	var source strings.Builder
	source.WriteString(header)
	var assembly []string
	for _, row := range []struct {
		op, width string
		tables    int
		laneCount int
	}{
		{"luti2", "b", 1, 4},
		{"luti2", "h", 1, 8},
		{"luti4", "b", 1, 2},
		{"luti4", "h", 1, 4},
		{"luti4", "h", 2, 4},
		{"luti6", "b", 2, 0},
		{"luti6", "h", 2, 2},
	} {
		table := "z23." + row.width
		if row.tables == 2 {
			table = "z31." + row.width + ", z0." + row.width
		}
		for lane := 0; lane == 0 || lane < row.laneCount; lane++ {
			index := "z6"
			if row.laneCount > 0 {
				index += fmt.Sprintf("[%d]", lane)
			}
			fmt.Fprintf(&source, "\tZ%s %s, [%s], Z13.%s\n",
				strings.ToUpper(row.op), strings.ToUpper(index), strings.ToUpper(table), strings.ToUpper(row.width))
			assembly = append(assembly, fmt.Sprintf("%s z13.%s, {%s}, %s", row.op, row.width, table, index))
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	words := assembleARM64LLVMWords(t, assembly, "+lut,+sve2p3")
	var rawSource strings.Builder
	rawSource.WriteString(header)
	for _, word := range words {
		fmt.Fprintf(&rawSource, "\tWORD $%#08x\n", word)
	}
	rawSource.WriteString("\tRET\n")
	rawFile, err := Parse(ArchARM64, rawSource.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"sveluti": {Name: "sveluti", Ret: Void}},
			}
			ll, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := Translate(rawFile, options)
			if err != nil {
				t.Fatalf("translate LUTI words: %v", err)
			}
			_, namedBody, namedOK := strings.Cut(ll, "\ntarget triple")
			_, rawBody, rawOK := strings.Cut(raw, "\ntarget triple")
			if !namedOK || !rawOK || namedBody != rawBody {
				t.Fatal("named and raw LUTI forms did not lower identically")
			}
			for _, want := range []string{
				`"target-features"="+lut,+sve,+sve2,+sve2p3"`,
				"@llvm.aarch64.sve.luti2.lane.nxv16i8",
				"@llvm.aarch64.sve.luti2.lane.nxv8i16",
				"@llvm.aarch64.sve.luti4.lane.nxv16i8",
				"@llvm.aarch64.sve.luti4.lane.nxv8i16",
				"@llvm.aarch64.sve.luti4.lane.x2.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZLUTI lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			object := compileLLVMToObject(t, llc, triple, "arm64-sve-luti.ll", "arm64-sve-luti.o", ll)
			if triple == arm64LinuxGNUTriple {
				masks := make([]uint32, len(words))
				for i := range masks {
					masks[i] = 0xffe0fc00 // Preserve the opcode, destination width and index lane.
				}
				requireARM64ObjectWordSequence(t, object, words, masks, assembly)
			}
		})
	}
}

func TestTranslateARM64SVELUTIRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLUTI2 Z1[4], [Z2.B], Z3.B",
		"ZLUTI2 Z1[8], [Z2.H], Z3.H",
		"ZLUTI2 Z1[1], [Z2.S], Z3.S",
		"ZLUTI2 Z1[1], [Z2.B], Z3.H",
		"ZLUTI4 Z1[2], [Z2.B], Z3.B",
		"ZLUTI4 Z1[4], [Z2.H], Z3.H",
		"ZLUTI4 Z1[4], [Z2.H, Z3.H], Z4.H",
		"ZLUTI4 Z1[1], [Z2.B, Z3.B], Z4.B",
		"ZLUTI4 Z1[1], [Z2.H, Z4.H], Z5.H",
		"ZLUTI4 Z1[1], [Z2.H, Z3.H, Z4.H], Z5.H",
		"ZLUTI6 Z1[0], [Z2.B, Z3.B], Z4.B",
		"ZLUTI6 Z1, [Z2.H, Z3.H], Z4.H",
		"ZLUTI6 Z1[2], [Z2.H, Z3.H], Z4.H",
		"ZLUTI6 Z1, [Z2.B], Z4.B",
		"ZLUTI6 Z1, [Z2.B, Z4.B], Z4.B",
		"ZLUTI6 Z1, [Z2.B, Z3.H], Z4.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveluti(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveluti": {Name: "badsveluti", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's LUTI forms", instruction)
			}
		})
	}
}
