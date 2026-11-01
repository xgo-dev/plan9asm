package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// The closed source namespace is an inventory, not an opcode-value table.
const x86SpecialVectorStateNames = " V4FMADDPS V4FMADDSS V4FNMADDPS V4FNMADDSS VADDSUBPD VADDSUBPS VAESDEC " +
	"VAESDECLAST VAESENC VAESENCLAST VAESIMC VAESKEYGENASSIST VBLENDPD VBLENDPS " +
	"VBLENDVPD VBLENDVPS VCMPPD VCMPPS VCMPSD VCMPSS VCOMISD " +
	"VCOMISS VDPPD VDPPS VEXP2PD VEXP2PS VFPCLASSPDX VFPCLASSPDY " +
	"VFPCLASSPDZ VFPCLASSPSX VFPCLASSPSY VFPCLASSPSZ VFPCLASSSD VFPCLASSSS VGETEXPPD " +
	"VGETEXPPS VGETEXPSD VGETEXPSS VHADDPD VHADDPS VHSUBPD VHSUBPS " +
	"VLDMXCSR VMPSADBW VP4DPWSSD VP4DPWSSDS VPBLENDD VPBLENDVB VPBLENDW " +
	"VPCLMULQDQ VPCMPESTRI VPCMPESTRM VPCMPISTRI VPCMPISTRM VPHMINPOSUW VPSADBW " +
	"VPSHUFBITQMB VPTEST VRCP28PD VRCP28PS VRCP28SD VRCP28SS VRCPPS " +
	"VRCPSS VROUNDPD VROUNDPS VROUNDSD VROUNDSS VRSQRT28PD VRSQRT28PS " +
	"VRSQRT28SD VRSQRT28SS VRSQRTPS VRSQRTSS VSCALEFPD VSCALEFPS VSCALEFSD " +
	"VSCALEFSS VSQRTPD VSQRTPS VSQRTSD VSQRTSS VSTMXCSR VTESTPD " +
	"VTESTPS VUCOMISD VUCOMISS VZEROALL VZEROUPPER "

func x86SpecialVectorStateName(opcode string) bool {
	return strings.Contains(x86SpecialVectorStateNames, " "+opcode+" ")
}

// Preserve the existing twenty-two successful row paths. No failure fallback
// is used: the remaining rows enter the new grammar before old dispatch.
func x86SpecialVectorStateRoute(rule X86AVXRule) bool {
	if !x86SpecialVectorStateName(rule.Opcode) {
		return false
	}
	if rule.EncodingOffset < 0 || rule.EncodingOffset >= len(rule.OpBytes) {
		return true
	}
	header := rule.OpBytes[rule.EncodingOffset]
	if rule.Ytab == "_yvaddsd" || rule.Ytab == "_yvaddsubpd" && hasEncodingTerm(header, "vex66") ||
		rule.Ytab == "_yvcvtdq2ps" && !hasEncodingTerm(header, "evexW1") {
		return false
	}
	return true
}

type x86SpecialVectorRow struct {
	physical                         x86VectorResultFormat
	immediate, registerMask, quartet bool
	selector                         int
}

// Decode only the immutable fixed prefix atoms, using the existing atom reader
// and byte encoder. The source payload remains the sole opcode-value owner.
func x86SpecialVectorHeader(rule X86AVXRule, offset int) (x86PackedAVXOpcode, map[string]bool, int, error) {
	var op x86PackedAVXOpcode
	if rule.Prefix != "Pavx" || offset < 0 || offset >= len(rule.OpBytes) {
		return op, nil, 0, fmt.Errorf("fixed source prefix/payload boundary differs")
	}
	kind := "vex"
	if hasEncodingTerm(rule.OpBytes[offset], "evex128") || hasEncodingTerm(rule.OpBytes[offset], "evex256") || hasEncodingTerm(rule.OpBytes[offset], "evex512") {
		kind = "evex"
	}
	optional := []string{
		kind + "128", kind + "256", kind + "512", kind + "66", kind + "F3", kind + "F2", kind + "0F", kind + "0F38", kind + "0F3A", kind + "W0", kind + "W1",
	}
	if kind == "vex" {
		optional = append(optional, "vexWIG")
	}
	atoms, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{"avxEscape"}, optional)
	if err != nil {
		return op, nil, 0, err
	}
	op.kind = kind
	widths, maps, prefixes := 0, 0, 0
	for index, word := range []string{"128", "256", "512"} {
		if atoms[kind+word] {
			op.length = byte(index)
			widths++
		}
	}
	for index, word := range []string{"0F", "0F38", "0F3A"} {
		if atoms[kind+word] {
			op.mapByte = byte(index + 1)
			maps++
		}
	}
	for index, word := range []string{"66", "F3", "F2"} {
		if atoms[kind+word] {
			op.pp = byte(index + 1)
			prefixes++
		}
	}
	wordModes := 0
	for _, mode := range []string{"W0", "W1", "WIG"} {
		if atoms[kind+mode] {
			wordModes++
		}
	}
	if widths != 1 || maps != 1 || prefixes > 1 || wordModes != 1 || kind == "vex" && op.length == 2 {
		return op, nil, 0, fmt.Errorf("fixed prefix width/map/W are not unique")
	}
	if atoms[kind+"W1"] {
		op.wBit = 0x80
	}
	stride := 2
	flags := map[string]bool{}
	if kind == "evex" {
		stride = 3
		if offset+stride > len(rule.OpBytes) {
			return op, nil, 0, fmt.Errorf("truncated EVEX payload")
		}
		flags, err = x86PackedEncodingAtoms(rule.OpBytes[offset+1], nil, []string{
			"evexN4", "evexN8", "evexN16", "evexN32", "evexN64", "evexBcstN4", "evexBcstN8",
			"evexZeroingEnabled", "evexRoundingEnabled", "evexSaeEnabled",
		})
		if err != nil {
			return op, nil, 0, err
		}
	}
	if offset+stride > len(rule.OpBytes) {
		return op, nil, 0, fmt.Errorf("truncated fixed payload")
	}
	value, err := strconv.ParseUint(rule.OpBytes[offset+stride-1], 0, 8)
	if err != nil {
		return op, nil, 0, err
	}
	op.opcode = byte(value)
	return op, flags, stride, nil
}

func x86SpecialVectorFormatForRule(rule X86AVXRule) (x86SpecialVectorRow, error) {
	var f x86SpecialVectorRow
	fail := func() (x86SpecialVectorRow, error) {
		return f, fmt.Errorf("special vector source roles/header/tuple/ordinal differ")
	}
	op, flags, _, err := x86SpecialVectorHeader(rule, rule.EncodingOffset)
	if err != nil {
		return f, err
	}
	classes := append([]string(nil), rule.Classes...)
	f.selector = 7
	f.registerMask = rule.ZCase == "Zvex_hr_rm_v_r"
	if f.registerMask {
		if len(classes) != 4 {
			return fail()
		}
		classes = classes[1:]
	} else if len(classes) > 0 && (classes[0] == "Yu8" || classes[0] == "Yi8") {
		f.immediate = true
		if classes[0] == "Yi8" {
			f.selector = -1
		}
		classes = classes[1:]
	}
	f.physical.masked = strings.Contains(rule.ZCase, "_k_")
	if f.physical.masked {
		if len(classes) < 3 || classes[len(classes)-2] != "Yknot0" {
			return fail()
		}
		classes = append(classes[:len(classes)-2], classes[len(classes)-1])
	}
	if len(classes) != 2 && len(classes) != 3 {
		return fail()
	}
	f.physical.unary = len(classes) == 2
	f.physical.maskResult = classes[len(classes)-1] == "Yk"
	f.physical.width = 128 << op.length
	f.physical.encoding = op
	f.quartet = !f.physical.unary && strings.HasSuffix(classes[1], "Multi4")
	bank := map[int]string{128: "x", 256: "y", 512: "z"}[f.physical.width]
	memory, register := "Y"+bank+"m", "Y"+bank+"r"
	if op.kind == "evex" && bank != "z" {
		memory += "Evex"
		register += "Evex"
	}
	if f.quartet {
		if classes[0] != "Ym" || classes[1] != register+"Multi4" || f.physical.maskResult {
			return fail()
		}
	} else if classes[0] != memory {
		return fail()
	}
	if !f.physical.unary && !f.quartet && classes[1] != register {
		return fail()
	}
	if !f.physical.maskResult && classes[len(classes)-1] != register {
		return fail()
	}
	if f.registerMask && (op.kind != "vex" || rule.Classes[0] != register) {
		return fail()
	}
	want := "Z" + op.kind + "_rm_v_r"
	if f.registerMask {
		want = "Zvex_hr_rm_v_r"
	} else if f.immediate {
		want = "Z" + op.kind + "_i_rm_r"
		if !f.physical.unary {
			want = "Z" + op.kind + "_i_rm_v_r"
		}
	}
	if f.physical.masked {
		want = "Zevex_rm_v_k_r"
		if f.physical.unary {
			want = "Zevex_rm_k_r"
		}
		if f.immediate {
			want = "Zevex_i_rm_k_r"
			if !f.physical.unary {
				want = "Zevex_i_rm_v_k_r"
			}
		}
	}
	if rule.ZCase != want {
		return fail()
	}
	if op.kind == "evex" {
		tuple, tupleTerms := 0, 0
		for _, n := range []int{4, 8, 16, 32, 64} {
			if flags["evexN"+strconv.Itoa(n)] {
				tuple = n
				tupleTerms++
			}
		}
		expected := f.physical.width / 8
		if strings.HasSuffix(rule.Opcode, "SS") && !strings.HasPrefix(rule.Opcode, "VP") {
			expected = 4
		}
		if strings.HasSuffix(rule.Opcode, "SD") && !strings.HasPrefix(rule.Opcode, "VP") {
			expected = 8
		}
		if f.quartet {
			expected = 16
		}
		if tupleTerms != 1 || tuple != expected || flags["evexBcstN4"] && flags["evexBcstN8"] || flags["evexRoundingEnabled"] && flags["evexSaeEnabled"] {
			return fail()
		}
		f.physical.broadcast = flags["evexBcstN4"] || flags["evexBcstN8"]
		f.physical.sae = flags["evexSaeEnabled"]
		f.physical.rounding = flags["evexRoundingEnabled"]
		if f.physical.masked && !f.physical.maskResult && !flags["evexZeroingEnabled"] {
			return fail()
		}
		if f.physical.maskResult && flags["evexZeroingEnabled"] {
			return fail()
		}
	}
	// Count the original fixed-payload blocks, including shared masked pairs.
	row, offset := 0, 0
	for offset < len(rule.OpBytes) {
		block, features, stride, err := x86SpecialVectorHeader(rule, offset)
		if err != nil {
			return f, err
		}
		paired := block.kind == "evex" && (features["evexZeroingEnabled"] || f.physical.maskResult)
		signedImmediate := block.kind == "vex" && f.immediate && (f.selector < 0 || op.kind == "vex" && rule.ZOffset == 0)
		if offset == rule.EncodingOffset {
			expectedRow, expectedZ := row, stride
			if paired {
				expectedZ = 0
				if f.physical.masked {
					expectedRow++
					expectedZ = stride
				}
			}
			if signedImmediate {
				expectedZ = 0
				if f.selector < 0 {
					expectedRow++
					expectedZ = stride
				}
			}
			if rule.RowIndex != expectedRow || rule.ZOffset != expectedZ {
				return fail()
			}
		}
		row++
		if paired || signedImmediate {
			row++
		}
		offset += stride
	}
	return f, nil
}

func x86SpecialVectorStateRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	if rule.ZCase == "Zvex" || rule.ZCase == "Zvex_rm_v_ro" {
		op, _, _, err := x86SpecialVectorHeader(rule, 0)
		if err != nil {
			return nil, err
		}
		if rule.EncodingOffset != 0 || rule.RowIndex != 0 {
			return nil, fmt.Errorf("state source offset/ordinal differs")
		}
		if rule.ZCase == "Zvex" {
			if len(rule.Classes) != 0 || rule.ZOffset != 2 || len(rule.OpBytes) != 2 {
				return nil, fmt.Errorf("zero-state source operands differ")
			}
			code := op.bytes(0x78, 0xe0, 0, 0)
			code = code[:len(code)-1]
			return []X86PackedBinaryWitness{{Instruction: rule.Opcode, Generation: "vex", Encoding: code}}, nil
		}
		if len(rule.Classes) != 1 || rule.Classes[0] != "Ym" || rule.ZOffset != 3 || len(rule.OpBytes) != 3 {
			return nil, fmt.Errorf("MXCSR source memory/digit differs")
		}
		digit, err := strconv.ParseUint(rule.OpBytes[2], 0, 3)
		if err != nil {
			return nil, err
		}
		read := rule.Opcode == "VLDMXCSR"
		w := X86PackedBinaryWitness{Instruction: rule.Opcode + " (AX)", Generation: "vex", Memory: read, Encoding: op.bytes(0x78, 0xe0, 0, byte(digit)<<3)}
		if read {
			w.First = "(AX)"
		} else {
			w.Destination = "(AX)"
		}
		return []X86PackedBinaryWitness{w}, nil
	}
	f, err := x86SpecialVectorFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	rows := f.physical.witnessesWithControl(rule.Opcode, f.immediate, f.selector)
	if f.registerMask {
		for index := range rows {
			w := &rows[index]
			mask := string(w.Destination[0]) + "3"
			name, args, _ := strings.Cut(w.Instruction, " ")
			w.Instruction = name + " " + mask + "," + args
			w.Encoding = append(w.Encoding, 0x30)
		}
	}
	if f.quartet {
		selected := rows[:0]
		for _, w := range rows {
			if !w.Memory {
				continue
			}
			bank := string(w.Second[0])
			first := bank + "16"
			group := "[" + bank + "16-" + bank + "19]"
			destination := string(w.Destination[0]) + "20"
			w.Instruction = strings.Replace(w.Instruction, ","+w.Second, ","+group, 1)
			w.Instruction = strings.TrimSuffix(w.Instruction, w.Destination) + destination
			w.Instruction = strings.Replace(w.Instruction, "(AX)", "(BX)", 1)
			w.First = "(BX)"
			w.Second, w.Destination = first, destination
			w.Encoding[2] |= 8   // vvvv low bits select the aligned base16, not17.
			w.Encoding[5] = 0x23 // ModRM.reg is destination20; existing group producer uses BX.
			selected = append(selected, w)
		}
		rows = selected
	}
	if strings.HasPrefix(rule.Opcode, "VPCMPESTR") || strings.HasPrefix(rule.Opcode, "VPCMPISTR") {
		for index := range rows {
			w := &rows[index]
			if !w.Memory {
				continue
			}
			// EAX/EDX are implicit numeric lengths, so use the independent BX
			// address role rather than invent pointer-to-number authority.
			w.First = "(BX)"
			w.Instruction = strings.Replace(w.Instruction, "(AX)", "(BX)", 1)
			at := len(w.Encoding) - 2 // ModRM precedes the original imm8.
			w.Encoding[at] = w.Encoding[at]&^7 | 3
		}
	}
	return rows, nil
}
