package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

type x86BroadcastSourceKind uint8

const (
	x86BroadcastVectorMemory x86BroadcastSourceKind = iota
	x86BroadcastGP
	x86BroadcastKData
	x86BroadcastMemory
)

// Source carrier, source tuple and result width are independent format facts.
// This is an encoding-row projection, not numerical or storage authority.
type x86PackedBroadcastFormat struct {
	source       x86BroadcastSourceKind
	width, tuple int
	masked       bool
	encoding     x86PackedAVXOpcode
}

func x86PackedBroadcastFormatForRule(rule X86AVXRule) (x86PackedBroadcastFormat, error) {
	f := x86PackedBroadcastFormat{masked: rule.ZCase == "Zevex_rm_k_r"}
	f.encoding.kind = "vex"
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	if evex {
		f.encoding.kind = "evex"
	}
	fail := func() (x86PackedBroadcastFormat, error) {
		return f, fmt.Errorf("broadcast source/tuple/width differs from its official format")
	}
	if rule.Prefix != "Pavx" || rule.ZCase != "Zvex_rm_v_r" && rule.ZCase != "Zevex_rm_v_r" && !f.masked ||
		len(rule.Classes) != 2 && !f.masked || f.masked && (len(rule.Classes) != 3 || rule.Classes[1] != "Yknot0") {
		return fail()
	}
	destinations := map[string]int{"Yxr": 128, "Yyr": 256}
	if evex {
		destinations = map[string]int{"YxrEvex": 128, "YyrEvex": 256, "Yzr": 512}
	}
	f.width = destinations[rule.Classes[len(rule.Classes)-1]]
	minimum, maximum, vexAllowed := 128, 512, false
	switch rule.Ytab {
	case "_yvpbroadcastb":
		if len(rule.Opcode) != len("VPBROADCASTB") {
			return fail()
		}
		f.tuple = map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[rule.Opcode[len(rule.Opcode)-1]]
		if f.tuple == 0 {
			return fail()
		}
		vexAllowed = true
		if rule.Classes[0] == "Yrl" {
			f.source, f.tuple = x86BroadcastGP, 0
			if !evex {
				return fail()
			}
		}
	case "_yvbroadcastss":
		f.tuple, vexAllowed = 4, true
	case "_yvbroadcastsd":
		f.tuple, minimum, vexAllowed = 8, 256, true
	case "_yvbroadcasti32x2":
		f.tuple = 8
	case "_yvbroadcastf32x2":
		f.tuple, minimum = 8, 256
	case "_yvbroadcastf32x4":
		f.source, f.tuple, minimum = x86BroadcastMemory, 16, 256
	case "_yvbroadcastf32x8":
		f.source, f.tuple, minimum = x86BroadcastMemory, 32, 512
	case "_yvpbroadcastmb2q":
		f.source = x86BroadcastKData
		if f.masked {
			return fail()
		}
	case "_yvbroadcastf128":
		f.source, f.tuple, minimum, maximum, vexAllowed = x86BroadcastMemory, 16, 256, 256, true
		if evex || f.masked {
			return fail()
		}
	default:
		return fail()
	}
	class := "Yxm"
	if evex {
		class += "Evex"
	}
	switch f.source {
	case x86BroadcastGP:
		class = "Yrl"
	case x86BroadcastKData:
		class = "Yk"
	case x86BroadcastMemory:
		class = "Ym"
	}
	if rule.Classes[0] != class || f.width < minimum || f.width > maximum || !evex && !vexAllowed ||
		f.source == x86BroadcastVectorMemory && f.tuple == 0 {
		return fail()
	}
	stride, offset := 2, 2
	if evex {
		stride, offset = 3, 0
		if f.masked || f.source == x86BroadcastKData {
			offset = 3
		}
	}
	if rule.ZOffset != offset || rule.EncodingOffset < 0 || rule.EncodingOffset+stride > len(rule.OpBytes) {
		return fail()
	}
	pp, w := "66", "W0"
	if f.source == x86BroadcastKData {
		pp = "F3"
	}
	if evex && (rule.Opcode == "VBROADCASTSD" || strings.Contains(rule.Opcode, "64X") || strings.HasSuffix(rule.Opcode, "Q")) {
		w = "W1"
	}
	kind := f.encoding.kind
	atoms, err := x86PackedEncodingAtoms(rule.OpBytes[rule.EncodingOffset], []string{
		"avxEscape", kind + strconv.Itoa(f.width), kind + pp, kind + "0F38", kind + w,
	}, nil)
	if err != nil {
		return fail()
	}
	if evex {
		required := []string{"evexZeroingEnabled"}
		if f.source == x86BroadcastKData {
			required = []string{"0"}
		} else if f.tuple != 0 {
			required = append(required, "evexN"+strconv.Itoa(f.tuple))
		}
		if _, err := x86PackedEncodingAtoms(rule.OpBytes[rule.EncodingOffset+1], required, nil); err != nil {
			return fail()
		}
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[rule.EncodingOffset+stride-1], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding.mapByte, f.encoding.pp, f.encoding.opcode = 2, 1, byte(opcode)
	if pp == "F3" {
		f.encoding.pp = 2
	}
	if atoms[kind+"W1"] {
		f.encoding.wBit = 0x80
	}
	f.encoding.length = byte(map[int]int{128: 0, 256: 1, 512: 2}[f.width])
	return f, nil
}

func x86PackedBroadcastRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86PackedBroadcastFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	evex := f.encoding.kind == "evex"
	sources := []string{"X0", "(AX)"}
	if evex {
		sources[0] = "X16"
	}
	switch f.source {
	case x86BroadcastGP:
		sources = []string{"AX"}
	case x86BroadcastKData:
		sources = []string{"K0"}
	case x86BroadcastMemory:
		sources = []string{"(AX)"}
	}
	bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[f.width]
	destination := bank + "2"
	if evex {
		destination = bank + "18"
	}
	var witnesses []X86PackedBinaryWitness
	for _, source := range sources {
		controls := []string{""}
		if f.masked {
			controls = append(controls, ".Z")
		}
		for _, suffix := range controls {
			operands := source + "," + destination
			p0, p2, modrm := byte(0xe0), f.encoding.length<<5|8, byte(0xd0)
			if source == "X16" {
				p0 = 0xa0
			}
			if source == "(AX)" {
				modrm = 0x10
			}
			if f.masked {
				operands, p2 = source+",K1,"+destination, p2|1
			}
			if suffix != "" {
				p2 |= 0x80
			}
			witnesses = append(witnesses, X86PackedBinaryWitness{
				Instruction: rule.Opcode + suffix + " " + operands, Generation: f.encoding.kind,
				First: source, Destination: destination, Width: f.width,
				Memory: source == "(AX)", Masked: f.masked, Zeroing: suffix != "",
				Encoding: f.encoding.bytes(0x78, p0, p2, modrm),
			})
		}
	}
	return witnesses, nil
}
