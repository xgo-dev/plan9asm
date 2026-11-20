package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86FloatingImmediateControlTestNames = `
	VGETMANTPS VGETMANTPD VGETMANTSS VGETMANTSD
	VRNDSCALEPS VRNDSCALEPD VRNDSCALESS VRNDSCALESD
	VREDUCEPS VREDUCEPD VREDUCESS VREDUCESD
	VFIXUPIMMPS VFIXUPIMMPD VFIXUPIMMSS VFIXUPIMMSD
	VRANGEPS VRANGEPD VRANGESS VRANGESD`

func TestX86FloatingImmediateControlCompleteOriginalRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, name := range strings.Fields(x86FloatingImmediateControlTestNames) {
		names[name] = true
	}
	originals := map[string]X86AVXRule{}
	for index, row := range avx {
		if names[row.Opcode] {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = row
		}
	}
	if len(names) != 20 || len(originals) != 80 {
		t.Fatal("complete control family changed", len(names), len(originals))
	}
	// Existing helper only: this must reach an unsupported-format RED, not a
	// future selector/API symbol compilation error. Not run during preparation.
	rows, err := x86PackedBinaryRows(legacy, avx, x86FloatingImmediateControlTestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions := map[string]bool{}, map[string]bool{}
	byTable, widths := map[string]int{}, map[int]int{}
	masked, zeroing, broadcast, sae, memory := 0, 0, 0, 0, 0
	for _, row := range rows {
		from, found := originals[row.ID]
		if !found || seen[row.ID] {
			t.Fatal("lost exact original row", row)
		}
		seen[row.ID] = true
		byTable[from.Ytab]++
		width := map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[from.Classes[1]]
		bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[width]
		unary, scalar := from.Ytab == "_yvgetmantpd", from.Ytab == "_yvfixupimmsd"
		wantMasked := strings.Contains(strings.Join(from.Classes, ","), "Yknot0")
		for _, w := range row.Witnesses {
			fields := strings.Fields(w.Instruction)
			if len(fields) != 2 {
				t.Fatal("lost source syntax", w)
			}
			args := strings.Split(fields[1], ",")
			second, arity := bank+"17", 4
			if unary {
				second, arity = "", 3
			}
			if wantMasked {
				arity++
			}
			isSAE := strings.Contains(fields[0], ".SAE")
			if len(args) != arity || args[0] != "$7" || instructions[w.Instruction] ||
				w.First != args[1] || w.First != bank+"16" && w.First != "(AX)" ||
				w.Second != second || w.Destination != bank+"18" || args[len(args)-1] != w.Destination ||
				w.Generation != "evex" || w.Width != width || w.MaskResult || w.Masked != wantMasked ||
				w.Masked && args[len(args)-2] != "K1" || w.Zeroing && !w.Masked ||
				w.Zeroing != strings.HasSuffix(fields[0], ".Z") || w.Memory != (w.First == "(AX)") ||
				w.Broadcast != strings.Contains(fields[0], ".BCST") || w.Broadcast && (!w.Memory || scalar) ||
				isSAE && (w.Memory || !scalar && width != 512) ||
				len(w.Encoding) != 7 || w.Encoding[0] != 0x62 || w.Encoding[6] != 7 {
				t.Fatal("immediate/arity/scalar/tuple/mask/control roles conflated", row.ID, w)
			}
			// Unary packed reserves vvvv/V'; scalar upper and binary data use it.
			if unary && (w.Encoding[2]&0x78 != 0x78 || w.Encoding[3]&8 == 0) ||
				!unary && (w.Encoding[2]&0x78 != 0x70 || w.Encoding[3]&8 != 0) {
				t.Fatal("reserved vvvv and live scalar/binary source conflated", row.ID, w)
			}
			instructions[w.Instruction] = true
			widths[width]++
			if w.Masked {
				masked++
			}
			if w.Zeroing {
				zeroing++
			}
			if w.Broadcast {
				broadcast++
			}
			if isSAE {
				sae++
			}
			if w.Memory {
				memory++
			}
		}
	}
	if len(rows) != 80 || len(seen) != len(originals) || len(instructions) != 390 ||
		byTable["_yvgetmantpd"] != 36 || byTable["_yvfixupimmpd"] != 24 || byTable["_yvfixupimmsd"] != 20 ||
		widths[128] != 180 || widths[256] != 90 || widths[512] != 120 ||
		masked != 260 || zeroing != 130 || broadcast != 90 || sae != 60 || memory != 210 {
		t.Fatal("complete control projection changed", len(rows), len(instructions), byTable, widths, masked, zeroing, broadcast, sae, memory)
	}
}

func TestX86FloatingImmediateControlRejectsForeignFormatAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"VGETMANTPD", "VFIXUPIMMPD", "VRNDSCALESD"} {
		for _, mutation := range []string{"signed immediate", "K0 mask", "K result", "tuple", "prefix", "map", "rounding", "offset", "forbidden control", "W", "source carrier", "short opcode", "extent", "row index"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				found := 0
				index := 1
				if mutation == "forbidden control" && name != "VRNDSCALESD" {
					index = 3 // Packed X must not inherit the Z row's SAE.
				}
				for _, original := range rules {
					if original.Opcode != name || original.RowIndex != index {
						continue
					}
					found++
					if _, err := x86PackedAVXRowWitnesses(original); err != nil {
						t.Fatal("negative needs valid original", err)
					}
					row := original
					row.Classes = append([]string(nil), row.Classes...)
					row.OpBytes = append([]string(nil), row.OpBytes...)
					switch mutation {
					case "signed immediate":
						row.Classes[0] = "Yi8"
					case "K0 mask":
						row.Classes[len(row.Classes)-2] = "Yk"
					case "K result":
						row.Classes[len(row.Classes)-1] = "Yk"
					case "tuple":
						row.OpBytes[row.EncodingOffset+1] = strings.ReplaceAll(strings.ReplaceAll(row.OpBytes[row.EncodingOffset+1], "evexN64", "evexN32"), "evexN8", "evexN16")
					case "prefix":
						row.OpBytes[row.EncodingOffset] = strings.Replace(row.OpBytes[row.EncodingOffset], "evex66", "evexF2", 1)
					case "map":
						row.OpBytes[row.EncodingOffset] = strings.Replace(row.OpBytes[row.EncodingOffset], "evex0F3A", "evex0F38", 1)
					case "rounding":
						row.OpBytes[row.EncodingOffset+1] += "|evexRoundingEnabled"
					case "offset":
						row.EncodingOffset++
					case "forbidden control":
						control := "evexSaeEnabled"
						if name == "VRNDSCALESD" {
							control = "evexBcstN8"
						}
						row.OpBytes[row.EncodingOffset+1] += "|" + control
					case "W":
						row.OpBytes[row.EncodingOffset] = strings.Replace(row.OpBytes[row.EncodingOffset], "evexW1", "evexW0", 1)
					case "source carrier":
						row.Classes[1] = "YymEvex"
					case "short opcode":
						row.Opcode = ""
					case "extent":
						row.OpBytes = append(row.OpBytes, "0")
					case "row index":
						row.RowIndex++
					}
					if _, err := x86PackedAVXRowWitnesses(row); err == nil {
						t.Fatal("foreign control format accepted", row)
					}
				}
				if found != 1 {
					t.Fatal("missing original negative owner", found)
				}
			})
		}
	}
}
