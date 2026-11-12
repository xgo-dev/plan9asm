package plan9asm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Observe original Go bytes and independently listed PCs, not the translator's
// raw decoder or its typed instruction tables. These fixtures contain one TEXT
// and no data, alignment directives, or assembler-inserted frame instructions.
func x86NumericalBoundaryGoBytes(t *testing.T, arch, body string) ([]byte, []int64) {
	t.Helper()
	code, pcs, _ := x86NumericalBoundaryGoBytesAndListing(t, arch, body)
	return code, pcs
}

func x86NumericalBoundaryGoBytesAndListing(t *testing.T, arch, body string) ([]byte, []int64, []byte) {
	t.Helper()
	listing := x86InsertExtractGoListing(t, arch, "TEXT boundary(SB),4,$0-0\n"+body+"\n")
	var code []byte
	var pcs []int64
	for _, line := range strings.Split(string(listing), "\n") {
		if chunk := x86InsertExtractListedBytes(line); len(chunk) != 0 {
			fields := strings.Fields(line)
			pc, err := strconv.ParseInt(fields[0], 0, 64)
			if err != nil || pc != int64(len(code)) {
				t.Fatalf("noncontiguous original Go bytes: %s", line)
			}
			code = append(code, chunk...)
		}
		match := goAMD64FrameRow.FindStringSubmatch(line)
		if match == nil || strings.HasPrefix(match[3], "TEXT") {
			continue
		}
		pc, err := strconv.ParseInt(match[1], 16, 64)
		if err != nil || len(pcs) != 0 && pc <= pcs[len(pcs)-1] {
			t.Fatalf("ambiguous original Go instruction PC: %s", line)
		}
		pcs = append(pcs, pc)
	}
	if len(code) == 0 || len(pcs) == 0 || pcs[0] != 0 {
		t.Fatal("missing original Go instruction bytes/PCs")
	}
	return code, pcs, listing
}

func TestX86NumericalNativeBoundariesOriginalGoMixedEVEX(t *testing.T) {
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", "VMOVDQU64 table<>(SB),Z0\nCMPB feature+7(SB),$1\nRET")
	boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for _, boundary := range boundaries {
		got = append(got, boundary.PC)
	}
	if !reflect.DeepEqual(got, pcs) || len(scalar) != 2 || scalar[pcs[1]].Op != x86asm.CMP || scalar[pcs[2]].Op != x86asm.RET {
		t.Fatalf("actual Go boundaries %v, got %+v; scalar=%v", pcs, boundaries, scalar)
	}
}

func x86NumericalBoundaryForms(arch string) []string {
	var rows []string
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, op := range []string{"VMOVAPS", "VMOVAPD", "VMOVUPS", "VMOVUPD", "VMOVDQA", "VMOVDQU", "VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
			legacy := op == "VMOVDQA" || op == "VMOVDQU"
			if legacy && bank == "Z" {
				continue
			}
			for _, operand := range []string{bank + "1", "(AX)", "-128(AX)(CX*4)", "table+7(SB)", "8(AX)(FS)", "8(AX)(GS)"} {
				rows = append(rows, fmt.Sprintf("%s %s,%s2", op, operand, bank), fmt.Sprintf("%s %s2,%s", op, bank, operand))
				if !legacy {
					rows = append(rows, fmt.Sprintf("%s.Z %s,K7,%s2", op, operand, bank), fmt.Sprintf("%s %s2,K1,%s", op, bank, operand))
				}
			}
		}
		for _, op := range []string{"VANDPS", "VANDPD", "VANDNPS", "VANDNPD", "VORPS", "VORPD", "VXORPS", "VXORPD", "VPAND", "VPANDN", "VPOR", "VPXOR", "VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ"} {
			legacy := op == "VPAND" || op == "VPANDN" || op == "VPOR" || op == "VPXOR"
			if legacy && bank == "Z" {
				continue
			}
			for _, operand := range []string{bank + "1", "-64(AX)(CX*2)", "table-4(SB)"} {
				rows = append(rows, fmt.Sprintf("%s %s,%s2,%s3", op, operand, bank, bank))
				if !legacy && arch == "amd64" {
					rows = append(rows, fmt.Sprintf("%s.Z %s,%s2,K7,%s3", op, operand, bank, bank))
					if operand != bank+"1" {
						rows = append(rows, fmt.Sprintf("%s.BCST.Z %s,%s2,K7,%s3", op, operand, bank, bank))
					}
				}
			}
		}
		if arch == "amd64" {
			for _, operand := range []string{bank + "31", "table+17(SB)", "-64(AX)(CX*8)"} {
				for _, immediate := range []int{0, 17, 150, 255} {
					rows = append(rows, fmt.Sprintf("VPCLMULQDQ $%d,%s,%s30,%s29", immediate, operand, bank, bank))
					for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
						rows = append(rows, fmt.Sprintf("%s $%d,%s,%s30,%s29", op, immediate, operand, bank, bank),
							fmt.Sprintf("%s.Z $%d,%s,%s30,K7,%s29", op, immediate, operand, bank, bank))
						if operand != bank+"31" {
							rows = append(rows, fmt.Sprintf("%s.BCST.Z $%d,%s,%s30,K1,%s29", op, immediate, operand, bank, bank))
						}
					}
				}
			}
		}
	}
	for _, family := range []struct {
		stem, lane, input, output string
	}{
		{"F", "128", "X", "Y"}, {"I", "128", "X", "Y"},
		{"F", "32X4", "X", "Y"}, {"F", "32X4", "X", "Z"},
		{"F", "64X2", "X", "Y"}, {"F", "64X2", "X", "Z"},
		{"I", "32X4", "X", "Y"}, {"I", "32X4", "X", "Z"},
		{"I", "64X2", "X", "Y"}, {"I", "64X2", "X", "Z"},
		{"F", "32X8", "Y", "Z"}, {"F", "64X4", "Y", "Z"},
		{"I", "32X8", "Y", "Z"}, {"I", "64X4", "Y", "Z"},
	} {
		for _, operand := range []string{family.input + "1", "table+31(SB)", "-128(AX)(CX*4)"} {
			rows = append(rows, fmt.Sprintf("VEXTRACT%s%s $255,%s2,%s", family.stem, family.lane, family.output, operand))
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("VINSERT%s%s $255,%s,%s2,%s3", family.stem, family.lane, operand, family.output, family.output))
				if family.lane != "128" {
					rows = append(rows, fmt.Sprintf("VINSERT%s%s.Z $255,%s,%s2,K7,%s3", family.stem, family.lane, operand, family.output, family.output),
						fmt.Sprintf("VEXTRACT%s%s $255,%s2,K7,%s", family.stem, family.lane, family.output, operand))
				}
			}
		}
	}
	return append(rows, "PCLMULQDQ $255,X1,X2", "VZEROUPPER", "VZEROALL")
}

func TestX86NumericalNativeBoundariesWholeFamilyOriginalGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86NumericalBoundaryForms(arch)
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPB feature+7(SB),$1\nRET")
			mode := 64
			if arch == "386" {
				mode = 32
			}
			original := append([]byte(nil), code...)
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil {
				t.Fatal(err)
			}
			if len(pcs) != len(rows)+2 || len(boundaries) != len(pcs) || !bytes.Equal(code, original) {
				t.Fatalf("source rows=%d Go PCs=%d boundaries=%d or bytes changed", len(rows), len(pcs), len(boundaries))
			}
			for i, boundary := range boundaries {
				end := int64(len(code))
				if i+1 < len(pcs) {
					end = pcs[i+1]
				}
				if boundary.PC != pcs[i] || boundary.Length != int(end-pcs[i]) {
					t.Fatalf("row %d: boundary %+v, actual Go [%d,%d)", i, boundary, pcs[i], end)
				}
				if native, exists := scalar[boundary.PC]; exists {
					independent, err := x86asm.Decode(code[boundary.PC:], mode)
					if err != nil || native != independent || native.Len != boundary.Length {
						t.Fatal("scalar map was not the exact independent x86asm decode", boundary)
					}
				}
				instruction := code[boundary.PC:end]
				for cut := 1; cut < len(instruction); cut++ {
					if partial, values, err := x86NumericalNativeBoundaries(instruction[:cut], mode); err == nil || partial != nil || values != nil {
						t.Fatalf("row %d cut %d of %x accepted: %v", i, cut, instruction, err)
					}
				}
			}
			t.Logf("actual Go %s: %d complete family forms, every instruction byte cut rejected", arch, len(rows))
		})
	}
}

func TestX86NumericalNativeBoundariesFailuresDiscardAll(t *testing.T) {
	for name, code := range map[string][]byte{
		"empty":                nil,
		"call":                 {0xe8, 0, 0, 0, 0},
		"indirect-call":        {0xff, 0xd0},
		"indirect-memory-call": {0xff, 0x10},
		"far-call":             {0x9a, 0, 0, 0, 0, 0, 0},
		"far-memory-call":      {0xff, 0x18},
		"truncated-escape":     {0x0f},
		"unknown-evex":         {0x62, 0xf1, 0x7c, 0x48, 0xff, 0xc0},
		"unknown-vex-map2":     {0xc4, 0xe2, 0x79, 0xff, 0xc0},
		"overlong":             append(bytes.Repeat([]byte{0x64}, 15), 0x90),
	} {
		for _, mode := range []int{32, 64} {
			for _, leading := range [][]byte{nil, {0x90, 0xc3}, {0xeb, 0x7f}} {
				t.Run(fmt.Sprintf("%s/%d/%x", name, mode, leading), func(t *testing.T) {
					if len(code) == 0 && len(leading) != 0 {
						return
					}
					whole := append(append([]byte(nil), leading...), code...)
					got, scalar, err := x86NumericalNativeBoundaries(whole, mode)
					if !errors.Is(err, ErrProbeNeedsContext) || got != nil || scalar != nil {
						t.Fatalf("incomplete/forbidden stream acquired a partial proof: %x %+v %v %v", whole, got, scalar, err)
					}
				})
			}
		}
	}
	for _, mode := range []int{0, 16, 128} {
		if _, _, err := x86NumericalNativeBoundaries([]byte{0x90}, mode); err == nil {
			t.Fatal("invalid mode accepted", mode)
		}
	}
}

func TestX86NumericalNativeBoundariesMode32LegacyPrefixIdentity(t *testing.T) {
	for _, opcode := range []byte{0x62, 0xc4, 0xc5} {
		code := []byte{opcode, 0x00, 0xc3}
		got, scalar, err := x86NumericalNativeBoundaries(code, 32)
		if err != nil || len(got) != 2 || got[0].Length != 2 || len(scalar) != 2 {
			t.Fatalf("mode32 BOUND/LES/LDS confused with EVEX/VEX: %x %+v %v %v", code, got, scalar, err)
		}
		if _, _, err := x86NumericalNativeBoundaries(code, 64); err == nil {
			t.Fatalf("legacy-only bytes became mode64 vector boundary: %x", code)
		}
	}
	// EVEX.R' extends the destination independently of the legacy-vs-EVEX
	// discriminator. Go syntax acceptance alone cannot bind this high bank.
	if _, _, err := x86NumericalNativeBoundaries([]byte{0x62, 0xe1, 0x7d, 0x08, 0x6f, 0xc1}, 32); err == nil {
		t.Fatal("unbound mode32 high vector register accepted")
	}
}

func TestX86NumericalNativeBoundariesPhysicalRIPDoesNotGrantSource(t *testing.T) {
	for _, displacement := range []int32{-2147483648, -1, 0, 2147483647} {
		code := []byte{0x15, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(code[1:], uint32(displacement))
		for _, segment := range []Reg{"", FS, GS} {
			physical := x86RawMemoryDecoder{physicalPC: true}
			for _, scale := range []int{1, 4, 8, 16, 32, 64} {
				operand, length, err := physical.evex(code, 64, 1, 1, segment, "Z", scale)
				if err != nil || length != 5 || operand.Kind != OpMem || operand.Mem.Base != "RIP" || operand.Mem.Off != int64(displacement) || operand.Mem.Segment != segment || operand.Mem.Index != "" {
					t.Fatalf("physical RIP+disp32 not preserved: %x %+v %d %v", code, operand, length, err)
				}
				if _, _, err := (x86RawMemoryDecoder{}).evex(code, 64, 1, 1, segment, "Z", scale); err == nil {
					t.Fatal("default raw memory decoder accepted unbound RIP")
				}
				for cut := 1; cut < 5; cut++ {
					if _, _, err := physical.evex(code[:cut], 64, 0, 0, segment, "Z", scale); err == nil {
						t.Fatal("truncated original disp32 accepted", cut)
					}
				}
			}
			absolute, _, err := physical.evex(code, 32, 0, 0, segment, "X", 1)
			if err != nil || absolute.Mem.Base != "" || absolute.Mem.Off != int64(displacement) {
				t.Fatal("386 absolute disp32 became RIP", absolute, err)
			}
		}
	}
}

func TestX86NumericalNativeBoundariesDefaultRawFamiliesRemainStrict(t *testing.T) {
	for _, family := range []struct {
		instruction string
		decode      x86RawInstructionDecoder
	}{
		{"VMOVDQU64 table(SB),Z2", decodedX86EVEXPackedIntegerMoveInstruction},
		{"VMOVAPD table(SB),Z2", decodedX86PackedMoveInstruction},
		{"VMOVAPS table(SB),Y2", decodedX86PackedMoveInstruction},
		{"VMOVNTDQ Y2,table(SB)", decodedX86VEXNonTemporalMoveInstruction},
		{"VMOVNTDQA table(SB),Y2", decodedX86VEXNonTemporalMoveInstruction},
		{"VMOVNTPD Y2,table(SB)", decodedX86VEXNonTemporalMoveInstruction},
		{"VMOVNTPS Y2,table(SB)", decodedX86VEXNonTemporalMoveInstruction},
		{"VPANDD table(SB),Z1,Z2", decodedX86EVEXPackedLogicalInstruction},
		{"VANDPS table(SB),Z1,Z2", decodedX86RawEVEXFloatLogicalInstruction},
		{"VANDPD table(SB),Y1,Y2", decodedX86VEXPackedFloatLogicalInstruction},
		{"VPXOR table(SB),Y1,Y2", decodedX86VEXPackedIntegerLogicalInstruction},
		{"VPCLMULQDQ $255,table(SB),Z1,Z2", decodedX86RawCLMULInstruction},
		{"VPCLMULQDQ $255,table(SB),Y1,Y2", decodedX86RawCLMULInstruction},
		{"VPTERNLOGD $150,table(SB),Z1,Z2", decodedX86TernaryLogicInstruction},
		{"VINSERTF32X4 $255,table(SB),Z1,Z2", decodedX86EVEXPackedInsertInstruction},
		{"VINSERTF128 $255,table(SB),Y1,Y2", decodedX86VINSERT128Instruction},
		{"VEXTRACTF32X4 $255,Z2,table(SB)", decodedX86VEXTRACT128Instruction},
		{"VEXTRACTF128 $255,Y2,table(SB)", decodedX86VEXTRACT128Instruction},
		{"VPBROADCASTB table(SB),Y2", decodedX86VEXPackedBroadcastInstruction},
		{"VPBROADCASTQ.Z table(SB),K7,Z2", decodedX86VEXPackedBroadcastInstruction},
		{"VPCMPEQB table(SB),Y1,Y2", decodedX86PackedIntegerCompareInstruction},
		{"VPCMPGTD.BCST table(SB),Z1,K7,K2", decodedX86PackedIntegerCompareInstruction},
		{"VMOVD table(SB),X2", decodedX86VMOVQInstruction},
		{"VMOVQ table(SB),X31", decodedX86VMOVQInstruction},
		{"VPTEST table(SB),Y2", decodedX86VEXVectorTestInstruction},
		{"VTESTPS table(SB),X2", decodedX86VEXVectorTestInstruction},
		{"VTESTPD table(SB),Y2", decodedX86VEXVectorTestInstruction},
	} {
		t.Run(family.instruction, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", family.instruction+"\nRET")
			if len(pcs) != 2 {
				t.Fatal("unexpected original Go expansion", pcs)
			}
			if _, _, known, err := family.decode(code, 64); !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatalf("default raw source acquired RIP authority: known=%t err=%v", known, err)
			}
			got, scalar, err := x86NumericalNativeBoundaries(code, 64)
			if err != nil || len(got) != 2 || got[0].Length != int(pcs[1]) || len(scalar) != 1 || scalar[pcs[1]].Op != x86asm.RET {
				t.Fatalf("byte-only observation lost whole native boundaries: %+v %v %v", got, scalar, err)
			}
		})
	}
}

func TestX86NumericalNativeBoundariesMalformedEVEXAndImmediateDomain(t *testing.T) {
	move := []byte{0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x15, 0, 0, 0, 0}
	for name, mutate := range map[string]func([]byte){
		"reserved-map":      func(code []byte) { code[1] |= 8 },
		"missing-fixed-bit": func(code []byte) { code[2] &^= 4 },
		"reserved-vvvv":     func(code []byte) { code[2] &^= 8 },
		"reserved-V-prime":  func(code []byte) { code[3] &^= 8 },
		"reserved-VL":       func(code []byte) { code[3] |= 0x60 },
		"broadcast-move":    func(code []byte) { code[3] |= 0x10 },
		"zero-mask-K0":      func(code []byte) { code[3] |= 0x80 },
		"zero-memory-store": func(code []byte) {
			code[3] |= 0x81
			code[4] = 0x7f
		},
		"unregistered-opcode": func(code []byte) { code[4] = 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			code := append([]byte(nil), move...)
			mutate(code)
			if got, scalar, err := x86NumericalNativeBoundaries(code, 64); err == nil || got != nil || scalar != nil {
				t.Fatalf("malformed EVEX produced boundaries: %x %+v %v %v", code, got, scalar, err)
			}
		})
	}
	for _, prefix := range []byte{0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x48} {
		if _, _, err := x86NumericalNativeBoundaries(append([]byte{prefix}, move...), 64); err == nil {
			t.Fatal("unbound/forbidden vector prefix accepted", prefix)
		}
	}
	var body strings.Builder
	for immediate := 0; immediate < 256; immediate++ {
		for _, instruction := range []string{
			"VPCLMULQDQ $%d,table(SB),Z1,Z2",
			"VPTERNLOGD $%d,table(SB),Z1,Z2",
			"VPTERNLOGQ $%d,table(SB),Z1,Z2",
			"VINSERTI64X2 $%d,table(SB),Z1,Z2",
			"VEXTRACTI64X2 $%d,Z2,table(SB)",
		} {
			fmt.Fprintf(&body, instruction+"\n", immediate)
		}
	}
	body.WriteString("RET\n")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String())
	got, scalar, err := x86NumericalNativeBoundaries(code, 64)
	if err != nil || len(got) != 1281 || len(scalar) != 1 {
		t.Fatalf("complete original Go imm8 boundaries: count=%d scalar=%d err=%v", len(got), len(scalar), err)
	}
	for i, pc := range pcs {
		if got[i].PC != pc {
			t.Fatal("original Go immediate row lost its boundary", i, pc, got[i])
		}
	}
}

func TestX86NumericalNativeBoundariesExistingVEXNonTemporal(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var body strings.Builder
			for _, op := range []string{"VMOVNTDQ", "VMOVNTDQA", "VMOVNTPD", "VMOVNTPS"} {
				for _, bank := range []string{"X", "Y"} {
					for _, memory := range []string{"(AX)", "-64(AX)(CX*4)", "table+7(SB)", "8(AX)(GS)"} {
						first, second := bank+"2", memory
						if op == "VMOVNTDQA" {
							first, second = second, first
						}
						fmt.Fprintf(&body, "%s %s,%s\n", op, first, second)
					}
				}
			}
			body.WriteString("RET\n")
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, body.String())
			mode := 64
			if arch == "386" {
				mode = 32
			}
			// These first two VEX names really exist in x/arch's opcode enum.
			// The old whole-TEXT loop accepted them: do not shrink that domain.
			for _, index := range []int{0, 8} {
				native, err := x86asm.Decode(code[pcs[index]:], mode)
				if err != nil || native.Op != []x86asm.Op{x86asm.VMOVNTDQ, x86asm.VMOVNTDQA}[index/8] || native.Len != int(pcs[index+1]-pcs[index]) {
					t.Fatalf("original trusted VEX observation changed: %+v %v", native, err)
				}
			}
			got, scalar, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil || len(got) != len(pcs) || len(scalar) != 1 {
				t.Fatalf("existing VEX boundary coverage regressed: %+v %v %v", got, scalar, err)
			}
			for i, pc := range pcs {
				if got[i].PC != pc {
					t.Fatal("original non-temporal Go boundary differs", got[i], pc)
				}
				end := int64(len(code))
				if i+1 < len(pcs) {
					end = pcs[i+1]
				}
				for cut := pc + 1; cut < end; cut++ {
					if _, _, err := x86NumericalNativeBoundaries(code[pc:cut], mode); err == nil {
						t.Fatal("non-temporal truncated boundary accepted", pc, cut, end)
					}
				}
			}
		})
	}
}
