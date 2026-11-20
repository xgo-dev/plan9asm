package goasmrules

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86FMA3OfficialRowsAndFullControlWitnesses(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	family := regexp.MustCompile(`^V(FM(ADD|SUB)|FNM(ADD|SUB)|FMADDSUB|FMSUBADD)(132|213|231)(PS|PD|SS|SD)$`)
	names := map[string]bool{}
	var rows []X86PackedBinaryRow
	var official, expected, rejected, broadcast, rounding, zeroing int
	var generations, formats, widths [3]int
	var firstError error
	for index, rule := range avx {
		if !family.MatchString(rule.Opcode) {
			continue
		}
		names[rule.Opcode] = true
		official++
		counts := []int{2, 2, 7, 14, 3, 6, 3, 6}
		if strings.HasSuffix(rule.Opcode, "SS") || strings.HasSuffix(rule.Opcode, "SD") {
			if rule.Ytab != "_yvaddsd" {
				t.Fatal("scalar FMA3 changed official operand grammar", rule)
			}
			counts = []int{2, 6, 12}
		} else if rule.Ytab != "_yvaddpd" {
			t.Fatal("packed FMA3 changed official operand grammar", rule)
		}
		if rule.RowIndex < 0 || rule.RowIndex >= len(counts) {
			t.Fatal("FMA3 acquired an unreviewed official row", rule)
		}
		expected += counts[rule.RowIndex]
		witnesses, err := x86PackedAVXRowWitnesses(rule)
		if err != nil {
			rejected++
			if firstError == nil {
				firstError = fmt.Errorf("%s/%d: %w", rule.Opcode, rule.RowIndex, err)
			}
			continue
		}
		if len(witnesses) != counts[rule.RowIndex] {
			t.Fatalf("%s/%d: got %d control witnesses, want %d", rule.Opcode, rule.RowIndex, len(witnesses), counts[rule.RowIndex])
		}
		rows = append(rows, X86PackedBinaryRow{
			ID:     fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex),
			Opcode: rule.Opcode, Witnesses: witnesses,
		})
		generation := 1
		if witnesses[0].Generation == "evex" {
			generation = 2
		}
		generations[generation]++
		for _, witness := range witnesses {
			formats[generation]++
			width, ok := map[int]int{128: 0, 256: 1, 512: 2}[witness.Width]
			if !ok || witness.Generation != witnesses[0].Generation || witness.MaskResult {
				t.Fatal("FMA3 lost carrier, generation or vector destination", rule, witness)
			}
			widths[width]++
			if generation == 2 && (!strings.HasSuffix(witness.Second, "17") ||
				!strings.HasSuffix(witness.Destination, "18") || witness.Encoding[0] != 0x62) {
				t.Fatal("original EVEX FMA3 witness can fall back to VEX", rule, witness)
			}
			if witness.Broadcast {
				broadcast++
				if !witness.Memory || rule.Ytab != "_yvaddpd" {
					t.Fatal("scalar or register FMA3 acquired broadcast", rule, witness)
				}
			}
			if strings.Contains(witness.Instruction, "_SAE") {
				rounding++
				if witness.Memory || witness.Broadcast || generation != 2 || rule.Ytab == "_yvaddpd" && witness.Width != 512 {
					t.Fatal("FMA3 rounding escaped its original register-only control grammar", rule, witness)
				}
			}
			if witness.Zeroing {
				zeroing++
				if !witness.Masked {
					t.Fatal("zeroing FMA3 lost its nonzero mask", rule, witness)
				}
			}
		}
	}
	if len(names) != 60 || official != 360 || expected != 2028 {
		t.Fatalf("official FMA3 scope drift: names=%d rows=%d control expectations=%d", len(names), official, expected)
	}
	if rejected != 0 {
		t.Fatalf("%d/%d original FMA3 rows lack witness grammar (policy expects %d witnesses): %v", rejected, official, expected, firstError)
	}
	if len(rows) != 360 || generations != [3]int{0, 96, 264} || formats != [3]int{0, 192, 1836} ||
		widths != [3]int{876, 396, 756} || broadcast != 324 || rounding != 720 || zeroing != 612 {
		t.Fatalf("FMA3 row/control inventory drift: rows=%d generations=%v formats=%v widths=%v broadcast=%d rounding=%d zeroing=%d",
			len(rows), generations, formats, widths, broadcast, rounding, zeroing)
	}
	t.Log("360 original rows / 2028 candidate control witnesses; original Go bytes, initialized APIs, objects and runtime require their separate owners")
}

func TestX86FMA3OfficialScalarTupleAndRoundingEncoding(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []struct {
		opcode, instruction string
		row                 int
		encoding            []byte
	}{
		{"VFMADD132PS", "VFMADD132PS X0,X1,X2", 0, []byte{0xc4, 0xe2, 0x71, 0x98, 0xd0}},
		{"VFMSUB213PD", "VFMSUB213PD (AX),Y1,Y2", 1, []byte{0xc4, 0xe2, 0xf5, 0xaa, 0x10}},
		{"VFNMADD231PS", "VFNMADD231PS.RN_SAE Z16,Z17,Z18", 2, []byte{0x62, 0xa2, 0x75, 0x10, 0xbc, 0xd0}},
		{"VFNMSUB132PD", "VFNMSUB132PD.RZ_SAE.Z Z16,Z17,K1,Z18", 3, []byte{0x62, 0xa2, 0xf5, 0xf1, 0x9e, 0xd0}},
		{"VFMADD132SD", "VFMADD132SD.RD_SAE X16,X17,X18", 1, []byte{0x62, 0xa2, 0xf5, 0x30, 0x99, 0xd0}},
		{"VFMADD132SS", "VFMADD132SS.RU_SAE.Z X16,X17,K1,X18", 2, []byte{0x62, 0xa2, 0x75, 0xd1, 0x99, 0xd0}},
		{"VFMADD132SD", "VFMADD132SD (AX),X17,X18", 1, []byte{0x62, 0xe2, 0xf5, 0x00, 0x99, 0x10}},
		{"VFMADD132PS", "VFMADD132PS.BCST.Z (AX),X17,K1,X18", 5, []byte{0x62, 0xe2, 0x75, 0x91, 0x98, 0x10}},
	} {
		t.Run(anchor.instruction, func(t *testing.T) {
			found := false
			for _, rule := range avx {
				if rule.Opcode != anchor.opcode || rule.RowIndex != anchor.row {
					continue
				}
				witnesses, err := x86PackedAVXRowWitnesses(rule)
				if err != nil {
					t.Fatal(err)
				}
				for _, witness := range witnesses {
					if witness.Instruction == anchor.instruction {
						found = true
						if !bytes.Equal(witness.Encoding, anchor.encoding) {
							t.Fatalf("original FMA3 tuple/RC bytes are %x, want %x", witness.Encoding, anchor.encoding)
						}
					}
				}
			}
			if !found {
				t.Fatal("original FMA3 row/control witness is absent")
			}
		})
	}
}

func TestX86FMA3OfficialScalarMetadataFailsClosed(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range avx {
		if rule.Opcode != "VFMADD132SD" || rule.RowIndex != 1 {
			continue
		}
		for _, test := range []struct {
			name   string
			mutate func(*X86AVXRule)
		}{
			{"carrier tuple", func(r *X86AVXRule) { r.OpBytes[3] = strings.Replace(r.OpBytes[3], "evexN8", "evexN16", 1) }},
			{"wrong precision tuple", func(r *X86AVXRule) { r.OpBytes[3] = strings.Replace(r.OpBytes[3], "evexN8", "evexN4", 1) }},
			{"scalar broadcast", func(r *X86AVXRule) { r.OpBytes[3] += " | evexBcstN8" }},
			{"standalone SAE", func(r *X86AVXRule) { r.OpBytes[3] += " | evexSaeEnabled" }},
			{"W conflict", func(r *X86AVXRule) { r.OpBytes[2] += " | evexW0" }},
			{"future flag", func(r *X86AVXRule) { r.OpBytes[3] += " | futureFlag" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				local := rule
				local.OpBytes = append([]string(nil), rule.OpBytes...)
				test.mutate(&local)
				if witnesses, err := x86PackedAVXRowWitnesses(local); err == nil || len(witnesses) != 0 {
					t.Fatal("unknown scalar tuple/control metadata acquired witnesses", witnesses, err)
				}
			})
		}
		return
	}
	t.Fatal("original scalar FMA3 row is absent")
}
