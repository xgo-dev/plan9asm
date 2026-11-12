package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// These syntax inventories predate the numerical-byte observer. They enumerate
// Go's complete FMA3, binary-floating and SQRT shapes independently of the
// decoder's opcode maps. Existing family roots bind their complete Go rows and
// attributes; this consumer must observe their actual physical boundaries too.
func x86NumericalFloatingBoundaryRows(arch, family string) []string {
	var rows []string
	switch family {
	case "FMA3":
		rows = x86FMA3NamedFormats(arch)
	case "arithmetic":
		rows = append(rows, x86FloatAddSubFormats(arch)...)
		rows = append(rows, x86FloatMulDivFormats(arch)...)
		rows = append(rows, x86FloatingMinMaxFormats(arch)...)
	case "sqrt":
		rows = x86SqrtInputRows(arch)
	default:
		panic("unknown independent floating family")
	}
	var complete []string
	for _, row := range rows {
		if !strings.HasPrefix(row, "V") {
			continue // Ordinary legacy boundaries already use independent x86asm.
		}
		complete = append(complete, row)
		if strings.Contains(row, "(AX)") {
			for _, address := range []string{"-129(AX)(CX*4)", "table+17(SB)"} {
				complete = append(complete, strings.ReplaceAll(row, "(AX)", address))
			}
		} else if arch == "amd64" {
			// Force the otherwise overlapping unmasked X/Y rows to EVEX,
			// without copying an exhaustive register Cartesian product.
			complete = append(complete, strings.NewReplacer(
				"X0", "X28", "X1", "X29", "X2", "X30",
				"Y0", "Y28", "Y1", "Y29", "Y2", "Y30",
				"Z0", "Z28", "Z1", "Z29", "Z2", "Z30").Replace(row))
		}
	}
	return complete
}

func x86CheckNumericalFloatingBoundaries(t *testing.T, code []byte, pcs []int64, mode, vectors int) {
	t.Helper()
	original := append([]byte(nil), code...)
	boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
	if err != nil {
		t.Fatal("complete original floating instruction lost its native boundary", err)
	}
	if !bytes.Equal(code, original) || len(boundaries) != len(pcs) {
		t.Fatal("complete original Go instruction bytes or PC inventory changed", len(boundaries), len(pcs))
	}
	for index, boundary := range boundaries {
		end := int64(len(code))
		if index+1 < len(pcs) {
			end = pcs[index+1]
		}
		if boundary.PC != pcs[index] || boundary.Length != int(end-pcs[index]) {
			t.Fatalf("row %d: observed %+v, original Go [%d,%d)", index, boundary, pcs[index], end)
		}
		instruction := code[boundary.PC:end]
		if index < vectors {
			if !x86NumericalVectorPrefix(instruction, mode) {
				t.Fatalf("original vector row became a legacy instruction: %x", instruction)
			}
			if _, exists := scalar[boundary.PC]; exists {
				t.Fatalf("boundary-only floating instruction acquired a scalar input observation: %x", instruction)
			}
		}
		for cut := 0; cut < len(instruction); cut++ {
			partial, values, err := x86NumericalNativeBoundaries(instruction[:cut], mode)
			if !errors.Is(err, ErrProbeNeedsContext) || partial != nil || values != nil {
				t.Fatalf("incomplete original instruction acquired a partial observation: %x cut=%d: %v", instruction, cut, err)
			}
		}
	}
	if len(scalar) != len(pcs)-vectors || scalar[pcs[vectors]].Op != x86asm.CMP ||
		scalar[pcs[vectors+1]].Op != x86asm.RET {
		t.Fatal("vector boundaries replaced the independent scalar CMP/RET observations", scalar)
	}
}

func TestX86NumericalNativeBoundariesCompleteFloatingFamiliesOriginalGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, family := range []string{"FMA3", "arithmetic", "sqrt"} {
			t.Run(arch+"/"+family, func(t *testing.T) {
				rows := x86NumericalFloatingBoundaryRows(arch, family)
				members := make(map[string]bool)
				for _, row := range rows {
					members[strings.Split(strings.Fields(row)[0], ".")[0]] = true
				}
				want := map[string]int{"FMA3": 60, "arithmetic": 24, "sqrt": 4}[family]
				if len(rows) == 0 || len(members) != want {
					t.Fatal("independent complete floating member inventory changed", family, len(members), want)
				}
				code, pcs := x86NumericalBoundaryGoBytes(t, arch,
					strings.Join(rows, "\n")+"\nCMPB feature+7(SB),$1\nRET")
				if len(pcs) != len(rows)+2 {
					t.Fatal("actual Go expanded or omitted an independent row", len(rows), len(pcs))
				}
				mode := 64
				if arch == "386" {
					mode = 32
				}
				x86CheckNumericalFloatingBoundaries(t, code, pcs, mode, len(rows))
				t.Logf("complete actual Go %s %s: members=%d physical rows=%d; every byte cut rejected",
					arch, family, len(members), len(rows))
			})
		}
	}
}

func TestX86NumericalFloatingBoundaryRIPIsNotSourceOrNumericalAuthority(t *testing.T) {
	for _, row := range []struct {
		instruction string
		decode      x86RawInstructionDecoder
	}{
		{"VFNMADD231SD table+17(SB),X1,X2", decodedX86VEXFMA3Instruction},
		{"VFMADD213SD table-17(SB),X1,X2", decodedX86VEXFMA3Instruction},
		{"VFMADDSUB132PS.BCST.Z table(SB),Z1,K7,Z2", decodedX86VEXFMA3Instruction},
		{"VADDSD table+17(SB),X1,X2", decodedX86VEXBinaryFloatInstruction},
		{"VMULPS.BCST.Z table-17(SB),Z1,K7,Z2", decodedX86VEXBinaryFloatInstruction},
		{"VMINPD.BCST table(SB),Y1,Y2", decodedX86VEXBinaryFloatInstruction},
		{"VSQRTSD table+17(SB),X1,X2", decodedX86VEXBinaryFloatInstruction},
		{"VSQRTPS.BCST.Z table-17(SB),K7,Z2", decodedX86SameWidthConversionInstruction},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row.instruction+"\nRET")
			if len(pcs) != 2 {
				t.Fatal("original physical RIP source changed its instruction count", pcs)
			}
			_, _, known, err := row.decode(code[:pcs[1]], 64)
			if !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatal("default raw decoder acquired source/literal permission", known, err)
			}
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
			if err != nil || len(boundaries) != 2 || boundaries[0].Length != int(pcs[1]) ||
				len(scalar) != 1 || scalar[pcs[1]].Op != x86asm.RET {
				t.Fatal("physical RIP must provide only a complete byte boundary", boundaries, scalar, err)
			}
			var source strings.Builder
			source.WriteString("TEXT ·Value(SB),4,$0-0\n")
			for _, value := range code {
				fmt.Fprintf(&source, "BYTE $%#02x\n", value)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value()", "amd64",
					"x86_64-unknown-linux-gnu", api)
				// The assembler object's relocation is deliberately not linked.
				// Copying its zero disp32 into BYTE source leaves no actual pool:
				// this is malformed literal/source rejection, not missing NUM.
				if ir != "" || err == nil {
					t.Fatal("an unlinked RIP relocation became a public literal source", api, err)
				}
			}
		})
	}
}

func TestX86NumericalFloatingBoundaryCannotCreateLiteralNumericalInputs(t *testing.T) {
	for _, row := range []struct {
		name      string
		opcode    byte
		prefix    byte
		width     int
		evex      bool
		broadcast bool
	}{
		{"LiteralAddSD", 0x58, 3, 16, false, false},
		{"LiteralMulPS", 0x59, 0, 32, false, false},
		{"LiteralMinPD", 0x5d, 1, 16, false, false},
		{"LiteralDivPD", 0x5e, 1, 64, true, false},
		{"LiteralMaxPS", 0x5f, 0, 32, true, true},
		{"LiteralSubSS", 0x5c, 2, 16, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			code := x86RawBinaryFloatLiteral(row.opcode, row.prefix, row.evex, row.width, row.broadcast)
			source := x86RawVectorLiteralSource(x86RawVectorLiteralCase{name: row.name, code: code})
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
			if err != nil || len(file.Data) != 1 || len(file.Data[0].Payload) == 0 {
				t.Fatal("independent complete inline literal/RET prerequisite failed", err)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			for _, api := range []string{"text", "module", "Go"} {
				declaration := "func " + row.name + "()"
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64",
					"x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Fatal("complete initialized inline literal positive control failed", api, err)
				}
				for _, missing := range []string{"VPXORD Z0,Z0,Z0\n", "KMOVD AX,K7\n"} {
					if missing == "KMOVD AX,K7\n" && !row.evex {
						continue
					}
					changed := strings.Replace(source, missing, "", 1)
					if changed == source {
						t.Fatal("missing-input control did not change the real source", missing)
					}
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64",
						"x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("complete literal bytes invented missing vector/mask NUM inputs", api, missing, err)
					}
				}
			}
		})
	}
}

func TestX86NumericalFloatingBoundariesRetainCompleteEncodingGuards(t *testing.T) {
	wrongFMAControl := encodeX86VEXFMA3(0x98, false, false, 2, 1, 0)
	wrongFMAControl[2] &^= 1 // FMA3 requires the 66 mandatory prefix.
	wrongFloatWidth := encodeX86EVEXBinaryFloat(0x58, 0, 0, false, false, 0, 2, 1, 0)
	wrongFloatWidth[2] |= 0x80 // EVEX PS requires W0; WIG is VEX-only.
	wrongEVEXReserved := encodeX86EVEXFMA3(0x98, false, 0, false, false, 0, 2, 1, 0)
	wrongEVEXReserved[2] &^= 4
	scalarFMABroadcast := encodeX86EVEXFMA3(0x99, false, 0, true, false, 0, 2, 1, 0)
	scalarFMABroadcast[5] = 0x10 // A scalar memory source has no broadcast form.
	scalarFloatBroadcast := encodeX86EVEXBinaryFloat(0x58, 2, 0, true, false, 0, 2, 1, 0)
	scalarFloatBroadcast[5] = 0x10
	packedSqrtReserved := encodeX86VEXBinaryFloat(0x51, 0, true, false, false, 2, 0, 0)
	packedSqrtReserved[2] ^= 8 // Unary SQRT reserves VEX.vvvv.
	for name, code := range map[string][]byte{
		"FMA mandatory prefix": wrongFMAControl,
		"FMA scalar VEX L":     encodeX86VEXFMA3(0x99, false, true, 2, 1, 0),
		"FMA reserved EVEX":    wrongEVEXReserved,
		"FMA reserved length":  encodeX86EVEXFMA3(0x98, false, 3, false, false, 0, 2, 1, 0),
		"FMA zero without K":   encodeX86EVEXFMA3(0x98, false, 0, false, true, 0, 2, 1, 0),
		"FMA scalar BCST":      scalarFMABroadcast,
		"float fixed EVEX W":   wrongFloatWidth,
		"float scalar VEX L":   encodeX86VEXBinaryFloat(0x58, 2, true, true, false, 2, 1, 0),
		"float length":         encodeX86EVEXBinaryFloat(0x58, 0, 3, false, false, 0, 2, 1, 0),
		"float zero without K": encodeX86EVEXBinaryFloat(0x58, 0, 0, false, true, 0, 2, 1, 0),
		"float scalar BCST":    scalarFloatBroadcast,
		"packed sqrt vvvv":     packedSqrtReserved,
	} {
		for _, mode := range []int{32, 64} {
			t.Run(fmt.Sprintf("%s/%d", name, mode), func(t *testing.T) {
				for _, prefix := range [][]byte{nil, {0x90, 0xc3}, {0xeb, 0x7f}} {
					whole := append(append([]byte(nil), prefix...), code...)
					boundaries, scalar, err := x86NumericalNativeBoundaries(whole, mode)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatalf("invalid/unreachable floating bytes retained a partial observation: %x %v", whole, err)
					}
				}
			})
		}
	}
	for _, code := range [][]byte{
		// Keep the mode32 vector discriminator intact; only vvvv/V' selects
		// an unavailable physical bank. Extended R/B can instead encode LES
		// or BOUND in that mode and is not an invalid vector witness.
		encodeX86VEXFMA3(0x98, true, true, 2, 15, 0),
		encodeX86EVEXFMA3(0xb9, true, 0, false, false, 0, 2, 31, 0),
		encodeX86VEXBinaryFloat(0x58, 1, true, true, true, 2, 15, 0),
		encodeX86EVEXBinaryFloat(0x5f, 1, 0, false, false, 0, 2, 31, 0),
	} {
		boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
		if err != nil || len(boundaries) != 1 || boundaries[0].Length != len(code) || len(scalar) != 0 {
			t.Fatal("complete actual mode64 physical bank lost its boundary", boundaries, scalar, err)
		}
		if !x86NumericalVectorPrefix(code, 32) {
			t.Fatal("mode32 negative no longer has a physical vector prefix", code)
		}
		if boundaries, scalar, err := x86NumericalNativeBoundaries(code, 32); !errors.Is(err, ErrProbeNeedsContext) ||
			boundaries != nil || scalar != nil {
			t.Fatal("physical mode32 acquired an extended vector bank", boundaries, scalar, err)
		}
	}
}

func TestX86NumericalFloatingBoundaryKeepsMode32LegacyDiscriminator(t *testing.T) {
	// These exact bytes were the incorrect high-bank vector negatives in the
	// first GREEN candidate. In mode32 they are complete ordinary instructions,
	// independently decoded by x86asm, not vector encodings with bad registers.
	for _, fixture := range []struct {
		code []byte
		ops  []x86asm.Op
	}{
		{[]byte{0xc4, 0x42, 0x8d, 0x98, 0xfd}, []x86asm.Op{x86asm.LES, x86asm.CWDE, x86asm.STD}},
		{[]byte{0xc4, 0x41, 0x8d, 0x58, 0xfd}, []x86asm.Op{x86asm.LES, x86asm.POP, x86asm.STD}},
	} {
		if x86NumericalVectorPrefix(fixture.code, 32) || !x86NumericalVectorPrefix(fixture.code, 64) {
			t.Fatal("physical legacy/vector discriminator changed", fixture.code)
		}
		boundaries, scalar, err := x86NumericalNativeBoundaries(fixture.code, 32)
		if err != nil || len(boundaries) != len(fixture.ops) || len(scalar) != len(fixture.ops) {
			t.Fatal("legitimate mode32 legacy sequence lost its complete boundary", boundaries, scalar, err)
		}
		pc := 0
		for index, opcode := range fixture.ops {
			native, err := x86asm.Decode(fixture.code[pc:], 32)
			if err != nil || native.Op != opcode || native.Len <= 0 ||
				boundaries[index].PC != int64(pc) || boundaries[index].Length != native.Len || scalar[int64(pc)] != native {
				t.Fatal("mode32 scalar identity differs from independent x86asm", index, native, err)
			}
			pc += native.Len
		}
		if pc != len(fixture.code) {
			t.Fatal("mode32 observer discarded native legacy bytes", pc, len(fixture.code))
		}
	}
}
