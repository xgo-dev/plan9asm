package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestX86NumericalConversionBoundariesOriginalCompleteFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := append(x86PackedConversionOracleRows(arch), x86SignedPackedFloatRows(arch)...)
			var body strings.Builder
			body.WriteString("RET\n") // Dead source still has exact native boundaries.
			for _, row := range rows {
				body.WriteString(row + "\n")
				if strings.Contains(row, " (AX),") {
					body.WriteString(strings.Replace(row, " (AX),", " table+7(SB),", 1) + "\n")
				}
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, body.String())
			mode := 64
			if arch == "386" {
				mode = 32
			}
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil {
				t.Fatal(err)
			}
			var actual []int64
			for index, boundary := range boundaries {
				actual = append(actual, boundary.PC)
				end := int64(len(code))
				if index+1 < len(pcs) {
					end = pcs[index+1]
				}
				if boundary.PC != pcs[index] || boundary.Length != int(end-pcs[index]) {
					t.Fatalf("conversion boundary %+v differs from original Go [%d,%d)", boundary, pcs[index], end)
				}
				if x86NumericalVectorPrefix(code[boundary.PC:], mode) {
					if _, found := scalar[boundary.PC]; found {
						t.Fatal("vector boundary acquired a scalar numerical-read role")
					}
				}
				for cut := boundary.PC + 1; cut < end; cut++ {
					partial, scalar, err := x86NumericalNativeBoundaries(code[boundary.PC:cut], mode)
					if !errors.Is(err, ErrProbeNeedsContext) || partial != nil || scalar != nil {
						t.Fatalf("truncated conversion acquired a partial proof: %x, %v", code[boundary.PC:cut], err)
					}
				}
			}
			if !reflect.DeepEqual(actual, pcs) {
				t.Fatal("complete Go listing and machine boundaries disagree")
			}
		})
	}
}

func TestX86NumericalConversionBoundariesDoNotGrantRawRIP(t *testing.T) {
	for _, family := range []struct {
		row    string
		decode x86RawInstructionDecoder
	}{
		{"VCVTDQ2PS table(SB),Y1", decodedX86SameWidthConversionInstruction},
		{"VCVTDQ2PS table(SB),Z1", decodedX86SameWidthConversionInstruction},
		{"VCVTDQ2PD table(SB),Y1", decodedX86PackedDoubleDwordInstruction},
		{"VCVTDQ2PD table(SB),Z1", decodedX86PackedDoubleDwordInstruction},
		{"VCVTPS2DQ table(SB),Y1", decodedX86PackedNumericConversionInstruction},
		{"VCVTPS2DQ table(SB),Z1", decodedX86PackedNumericConversionInstruction},
		{"VCVTTPD2DQY table(SB),X1", decodedX86PackedDoubleDwordInstruction},
		{"VCVTUQQ2PS table(SB),Y1", decodedX86PackedNumericConversionInstruction},
	} {
		t.Run(family.row, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", family.row+"\nRET")
			if len(pcs) != 2 {
				t.Fatal("unexpected original Go expansion", pcs)
			}
			if _, _, known, err := family.decode(code, 64); !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatalf("source decoder acquired a physical RIP permission: known=%t, %v", known, err)
			}
			got, length, known, err := decodedX86NumericalConversionBoundary(code, 64, x86RawMemoryDecoder{physicalPC: true})
			if err != nil || !known || length != int(pcs[1]) || got.Args[0].Mem.Base != "RIP" {
				t.Fatalf("observer lost the original physical operand/length: %+v, %d, %v", got, length, err)
			}
		})
	}
}

func TestX86NumericalConversionBoundariesReservedFields(t *testing.T) {
	for _, row := range []string{"VCVTDQ2PS (AX),Z1", "VCVTDQ2PD (AX),Z1", "VCVTUQQ2PS (AX),Y1"} {
		code, _ := x86NumericalBoundaryGoBytes(t, "amd64", row)
		if len(code) != 6 || code[0] != 0x62 {
			t.Fatalf("expected an independent EVEX witness for %s: %x", row, code)
		}
		for name, mutate := range map[string]func([]byte){
			"reserved map":      func(b []byte) { b[1] |= 8 },
			"missing fixed bit": func(b []byte) { b[2] &^= 4 },
			"reserved vvvv":     func(b []byte) { b[2] &^= 8 },
			"reserved V prime":  func(b []byte) { b[3] &^= 8 },
			"reserved VL":       func(b []byte) { b[3] |= 0x60 },
			"zero K0":           func(b []byte) { b[3] |= 0x80 },
		} {
			t.Run(row+"/"+name, func(t *testing.T) {
				changed := append([]byte(nil), code...)
				mutate(changed)
				for _, prefix := range [][]byte{nil, {0x90, 0xc3}} {
					whole := append(append([]byte(nil), prefix...), changed...)
					boundaries, scalar, err := x86NumericalNativeBoundaries(whole, 64)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatalf("reserved conversion retained a partial proof: %x, %v", whole, err)
					}
				}
			})
		}
	}
}
