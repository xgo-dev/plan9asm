package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Independent complete ordinary packed numeric namespace. Scalar, pure
// precision, F16C and decoder-only FP16/BF16 families have separate owners.
const x86PackedNumericConversionTestNames = `
	CVTPS2PL CVTTPS2PL CVTPD2PL CVTTPD2PL CVTPL2PS CVTPL2PD
	VCVTPS2DQ VCVTTPS2DQ VCVTPD2DQX VCVTPD2DQY VCVTTPD2DQX VCVTTPD2DQY VCVTPD2DQ VCVTTPD2DQ
	VCVTPD2QQ VCVTPD2UQQ VCVTTPD2QQ VCVTTPD2UQQ VCVTPS2UDQ VCVTTPS2UDQ VCVTUDQ2PS
	VCVTQQ2PD VCVTUQQ2PD VCVTPS2QQ VCVTPS2UQQ VCVTTPS2QQ VCVTTPS2UQQ VCVTUDQ2PD
	VCVTPD2UDQX VCVTTPD2UDQX VCVTQQ2PSX VCVTUQQ2PSX
	VCVTPD2UDQY VCVTTPD2UDQY VCVTQQ2PSY VCVTUQQ2PSY
	VCVTPD2UDQ VCVTTPD2UDQ VCVTQQ2PS VCVTUQQ2PS VCVTDQ2PS VCVTDQ2PD`

func TestX86PackedNumericConversionCompleteOfficialTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// This existing entry point must reach a real format RED, not fail to
	// compile against a future conversion selector or carrier helper.
	rows, err := x86PackedBinaryRows(legacy, avx, x86PackedNumericConversionTestNames)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]bool{}
	for _, name := range strings.Fields(x86PackedNumericConversionTestNames) {
		selected[name] = true
	}
	type original struct {
		classes              []string
		generation, features string
		masked               bool
	}
	originals := map[string]original{}
	mmx := 0
	for _, entry := range legacy.Optab {
		if !selected[entry.Opcode] {
			continue
		}
		for _, row := range entry.Rows {
			if row.Classes[0] == "Ymm" || row.Classes[len(row.Classes)-1] == "Ymr" {
				mmx++
				continue
			}
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			originals[id] = original{row.Classes, "legacy", "", false}
		}
	}
	for index, row := range avx {
		if !selected[row.Opcode] {
			continue
		}
		kind, features := "vex", ""
		if strings.HasPrefix(row.ZCase, "Zevex_") {
			kind, features = "evex", row.OpBytes[row.EncodingOffset+1]
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)
		originals[id] = original{row.Classes, kind, features, row.ZCase == "Zevex_rm_k_r"}
	}
	sizes := map[string]int{"Yxm": 16, "YxmEvex": 16, "Yym": 32, "YymEvex": 32, "Yzm": 64, "Yxr": 16, "YxrEvex": 16, "Yyr": 32, "YyrEvex": 32, "Yzr": 64}
	seen, names, instructions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	rowKinds, formats := map[string]int{}, map[string]int{}
	widths, encodingWidths := map[int]int{}, map[int]int{}
	broadcast, masked, zeroing, rounding, sae, different := 0, 0, 0, 0, 0, 0
	for _, row := range rows {
		from, valid := originals[row.ID]
		if !valid || seen[row.ID] || len(row.Witnesses) == 0 {
			t.Fatal("packed numeric conversion lost an original ordinary row", row)
		}
		seen[row.ID], names[row.Opcode] = true, true
		rowKinds[from.generation]++
		sourceBytes, destinationBytes := sizes[from.classes[0]], sizes[from.classes[len(from.classes)-1]]
		encodingWidth := sourceBytes * 8
		if destinationBytes > sourceBytes {
			encodingWidth = destinationBytes * 8
		}
		for _, witness := range row.Witnesses {
			fields := strings.Fields(witness.Instruction)
			if len(fields) != 2 || len(witness.Encoding) < 3 {
				t.Fatal("packed conversion lost source or bytes", row.ID, witness)
			}
			operands := strings.Split(fields[1], ",")
			first := strings.ToUpper(from.classes[0][1:2]) + "0"
			destination := strings.ToUpper(from.classes[len(from.classes)-1][1:2]) + "2"
			if from.generation == "legacy" {
				destination = "X1"
			}
			if from.generation == "evex" {
				first = first[:1] + "16"
				destination = destination[:1] + "18"
			}
			if instructions[witness.Instruction] || strings.Split(fields[0], ".")[0] != row.Opcode ||
				witness.First != operands[0] || witness.Destination != destination || operands[len(operands)-1] != destination ||
				witness.First != first && witness.First != "(AX)" || witness.Memory != (witness.First == "(AX)") ||
				witness.Generation != from.generation || witness.Masked != from.masked || witness.Width != destinationBytes*8 || witness.MaskResult ||
				witness.Zeroing != strings.HasSuffix(fields[0], ".Z") || witness.Zeroing && !witness.Masked ||
				witness.Broadcast != strings.Contains(fields[0], ".BCST") || witness.Broadcast && !witness.Memory ||
				witness.Masked && operands[1] != "K1" ||
				from.generation == "legacy" && witness.Second != destination || from.generation != "legacy" && witness.Second != "" {
				t.Fatal("conversion conflated physical carriers, tuple, mask, or syntax read metadata", row.ID, witness)
			}
			instructions[witness.Instruction] = true
			isRound, isSAE := strings.Contains(fields[0], "_SAE"), strings.Contains(fields[0], ".SAE")
			if witness.Broadcast && !hasEncodingTerm(from.features, "evexBcstN4") && !hasEncodingTerm(from.features, "evexBcstN8") ||
				isRound && (!hasEncodingTerm(from.features, "evexRoundingEnabled") || witness.Memory) ||
				isSAE && (!hasEncodingTerm(from.features, "evexSaeEnabled") || witness.Memory) {
				t.Fatal("conversion borrowed a foreign broadcast/ER/SAE source capability", row.ID, witness)
			}
			if from.generation == "evex" {
				if len(witness.Encoding) != 6 || witness.Encoding[0] != 0x62 || witness.Encoding[2]&0x78 != 0x78 || witness.Encoding[3]&8 == 0 {
					t.Fatal("conversion lost unary reserved vvvv/V' or EVEX identity", row.ID, witness)
				}
				if !isRound && !isSAE && 128<<(witness.Encoding[3]>>5&3) != encodingWidth {
					t.Fatal("conversion encoded destination width in place of source/result carrier geometry", row.ID, witness)
				}
			}
			formats[from.generation]++
			widths[witness.Width]++
			encodingWidths[encodingWidth]++
			if witness.Broadcast {
				broadcast++
			}
			if witness.Masked {
				masked++
			}
			if witness.Zeroing {
				zeroing++
			}
			if isRound {
				rounding++
			}
			if isSAE {
				sae++
			}
			if sourceBytes != destinationBytes {
				different++
			}
		}
	}
	if len(rows) != 162 || len(seen) != len(originals) || len(names) != 42 || mmx != 6 ||
		rowKinds["legacy"] != 6 || rowKinds["vex"] != 12 || rowKinds["evex"] != 144 ||
		formats["legacy"] != 12 || formats["vex"] != 24 || formats["evex"] != 840 ||
		widths[128] != 298 || widths[256] != 278 || widths[512] != 300 ||
		encodingWidths[128] != 240 || encodingWidths[256] != 228 || encodingWidths[512] != 408 ||
		broadcast != 216 || masked != 560 || zeroing != 280 || rounding != 168 || sae != 24 || different != 306 {
		t.Fatal("complete42 conversion row/control denominator changed", len(rows), len(names), mmx, rowKinds, formats, widths, encodingWidths, broadcast, masked, zeroing, rounding, sae, different)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"CVTPL2PD (AX),X1", []byte{0xf3, 0x0f, 0xe6, 0x08}},
		{"CVTPD2PL X0,X1", []byte{0xf2, 0x0f, 0xe6, 0xc8}},
		{"CVTTPS2PL X0,X1", []byte{0xf3, 0x0f, 0x5b, 0xc8}},
		{"VCVTDQ2PS Y0,Y2", []byte{0xc5, 0xfc, 0x5b, 0xd0}},
		{"VCVTDQ2PD X0,Y2", []byte{0xc5, 0xfe, 0xe6, 0xd0}},
		{"VCVTPD2DQY Y0,X2", []byte{0xc5, 0xff, 0xe6, 0xd0}},
		{"VCVTPD2UDQY Y16,X18", []byte{0x62, 0xa1, 0xfc, 0x28, 0x79, 0xd0}},
		{"VCVTPS2QQ Y16,Z18", []byte{0x62, 0xa1, 0x7d, 0x48, 0x7b, 0xd0}},
		{"VCVTQQ2PS Z16,Y18", []byte{0x62, 0xa1, 0xfc, 0x48, 0x5b, 0xd0}},
		{"VCVTUDQ2PD (AX),X18", []byte{0x62, 0xe1, 0x7e, 0x08, 0x7a, 0x10}},
		{"VCVTTPD2UQQ.BCST.Z (AX),K1,Z18", []byte{0x62, 0xe1, 0xfd, 0xd9, 0x78, 0x10}},
	})
}

func TestX86PackedNumericConversionMMXOriginalRowsRemainSeparate(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	ordinary, mmx, inputs, outputs := 0, 0, 0, 0
	for _, entry := range legacy.Optab {
		if entry.Ytab != "yxcvm1" && entry.Ytab != "yxcvm2" {
			continue
		}
		if len(entry.Rows) != 2 {
			t.Fatal("packed conversion lost its complete ordinary/MMX source rows", entry)
		}
		for _, row := range entry.Rows {
			if row.RowIndex == 0 && strings.Join(row.Classes, ",") == "Yxm,Yxr" {
				ordinary++
				continue
			}
			if row.RowIndex != 1 || row.ZCase != "Zm_r_xm" || row.ZOffset != 2 || row.UnmatchedOffset != 2 {
				t.Fatal("MMX source row metadata changed", entry, row)
			}
			switch strings.Join(row.Classes, ",") {
			case "Ymm,Yxr":
				inputs++
			case "Yxm,Ymr":
				outputs++
			default:
				t.Fatal("MMX acquired a GP/vector source-role reinterpretation", entry, row)
			}
			mmx++
		}
	}
	if ordinary != 6 || mmx != 6 || inputs != 2 || outputs != 4 {
		t.Fatal("complete legacy ordinary/MMX source denominator changed", ordinary, mmx, inputs, outputs)
	}
	// This owner inventories source rows only. It proves no new MMX native
	// caller, region/EMMS closure or successful/failed translator execution.
}

func TestX86PackedNumericConversionRejectsForeignCarrierAndControlAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"wide source carrier", "wide larger X tuple", "narrow destination", "narrow encoding width", "narrow input tuple", "same source carrier", "same input tuple", "exact integer widening ER", "narrow alias ER", "ER plus SAE", "BCST element width", "K0 writemask class", "GP result", "GP vector input"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VCVTPS2QQ", 0
			switch mutation {
			case "wide larger X tuple":
				index = 2
			case "narrow destination":
				name = "VCVTQQ2PS"
			case "narrow encoding width":
				name = "VCVTPD2UDQY"
			case "narrow input tuple":
				name = "VCVTPD2UDQX"
			case "same source carrier":
				name = "VCVTPD2QQ"
			case "same input tuple":
				name, index = "VCVTPD2QQ", 2
			case "exact integer widening ER":
				name, index = "VCVTUDQ2PD", 4
			case "narrow alias ER":
				name = "VCVTQQ2PSX"
			case "K0 writemask class":
				name, index = "VCVTPD2QQ", 1
			case "GP result":
				name, index = "VCVTPS2UDQ", 2
			case "GP vector input":
				name, index = "VCVTUDQ2PS", 2
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				if _, err := x86PackedAVXRowWitnesses(original); err != nil {
					t.Fatal("negative requires its complete original row to remain valid", original, err)
				}
				row := original
				row.Classes = append([]string(nil), row.Classes...)
				row.OpBytes = append([]string(nil), row.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "wide source carrier":
					row.Classes[0] = "YxmEvex"
				case "wide larger X tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN8", "evexN16", 1)
				case "narrow destination":
					row.Classes[len(row.Classes)-1] = "Yzr"
				case "narrow encoding width":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex256", "evex128", 1)
				case "narrow input tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN8", 1)
				case "same source carrier":
					row.Classes[0] = "YymEvex"
				case "same input tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN8", 1)
				case "exact integer widening ER", "narrow alias ER":
					row.OpBytes[feature] += "|evexRoundingEnabled"
				case "ER plus SAE":
					row.OpBytes[feature] += "|evexSaeEnabled"
				case "BCST element width":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexBcstN4", "evexBcstN8", 1)
				case "K0 writemask class":
					row.Classes[1] = "Yk"
				case "GP result":
					row.Classes[len(row.Classes)-1] = "Yrl"
				case "GP vector input":
					row.Classes[0] = "Yrl"
				}
				if strings.Join(row.Classes, ",") == strings.Join(original.Classes, ",") && strings.Join(row.OpBytes, ",") == strings.Join(original.OpBytes, ",") {
					t.Fatal("conversion negative did not mutate its original row", mutation, row)
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("packed conversion borrowed a foreign domain/carrier/tuple/control", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("conversion negative lost its exact original Go row", name, index, found)
			}
		})
	}
}
