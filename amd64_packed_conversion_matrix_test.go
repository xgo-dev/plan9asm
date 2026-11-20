package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent Go/Intel encoding inventory. No expected class, tuple, opcode
// or semantic width is obtained from the production conversion tables.
type x86PackedConversionOracle struct {
	name, shape, control, pp, opcode string
	input, output, w                 int
	legacy, vex                      bool
}

func x86PackedConversionOracleSpecs() []x86PackedConversionOracle {
	return []x86PackedConversionOracle{
		{"CVTPS2PL", "single", "", "Pe", "0x5b", 32, 32, 0, true, false},
		{"CVTTPS2PL", "single", "", "Pf3", "0x5b", 32, 32, 0, true, false},
		{"CVTPD2PL", "narrow16", "", "Pf2", "0xe6", 64, 32, 0, true, false},
		{"CVTTPD2PL", "narrow16", "", "Pe", "0xe6", 64, 32, 0, true, false},
		{"VCVTPS2DQ", "same", "round", "66", "0x5B", 32, 32, 0, false, true},
		{"VCVTTPS2DQ", "same", "sae", "F3", "0x5B", 32, 32, 0, false, true},
		{"VCVTPD2DQX", "narrow16", "", "F2", "0xE6", 64, 32, 1, false, true},
		{"VCVTPD2DQY", "narrow32", "", "F2", "0xE6", 64, 32, 1, false, true},
		{"VCVTPD2DQ", "narrow64", "round", "F2", "0xE6", 64, 32, 1, false, false},
		{"VCVTTPD2DQX", "narrow16", "", "66", "0xE6", 64, 32, 1, false, true},
		{"VCVTTPD2DQY", "narrow32", "", "66", "0xE6", 64, 32, 1, false, true},
		{"VCVTTPD2DQ", "narrow64", "sae", "66", "0xE6", 64, 32, 1, false, false},
		{"VCVTPD2QQ", "same", "round", "66", "0x7B", 64, 64, 1, false, false},
		{"VCVTPD2UQQ", "same", "round", "66", "0x79", 64, 64, 1, false, false},
		{"VCVTTPD2QQ", "same", "sae", "66", "0x7A", 64, 64, 1, false, false},
		{"VCVTTPD2UQQ", "same", "sae", "66", "0x78", 64, 64, 1, false, false},
		{"VCVTPS2UDQ", "same", "round", "", "0x79", 32, 32, 0, false, false},
		{"VCVTTPS2UDQ", "same", "sae", "", "0x78", 32, 32, 0, false, false},
		{"VCVTUDQ2PS", "same", "round", "F2", "0x7A", 32, 32, 0, false, false},
		{"VCVTQQ2PD", "same", "round", "F3", "0xE6", 64, 64, 1, false, false},
		{"VCVTUQQ2PD", "same", "round", "F3", "0x7A", 64, 64, 1, false, false},
		{"VCVTPS2QQ", "wide", "round", "66", "0x7B", 32, 64, 0, false, false},
		{"VCVTPS2UQQ", "wide", "round", "66", "0x79", 32, 64, 0, false, false},
		{"VCVTTPS2QQ", "wide", "sae", "66", "0x7A", 32, 64, 0, false, false},
		{"VCVTTPS2UQQ", "wide", "sae", "66", "0x78", 32, 64, 0, false, false},
		{"VCVTUDQ2PD", "wide", "", "F3", "0x7A", 32, 64, 0, false, false},
		{"VCVTPD2UDQX", "narrow16", "", "", "0x79", 64, 32, 1, false, false},
		{"VCVTPD2UDQY", "narrow32", "", "", "0x79", 64, 32, 1, false, false},
		{"VCVTPD2UDQ", "narrow64", "round", "", "0x79", 64, 32, 1, false, false},
		{"VCVTTPD2UDQX", "narrow16", "", "", "0x78", 64, 32, 1, false, false},
		{"VCVTTPD2UDQY", "narrow32", "", "", "0x78", 64, 32, 1, false, false},
		{"VCVTTPD2UDQ", "narrow64", "sae", "", "0x78", 64, 32, 1, false, false},
		{"VCVTQQ2PSX", "narrow16", "", "", "0x5B", 64, 32, 1, false, false},
		{"VCVTQQ2PSY", "narrow32", "", "", "0x5B", 64, 32, 1, false, false},
		{"VCVTQQ2PS", "narrow64", "round", "", "0x5B", 64, 32, 1, false, false},
		{"VCVTUQQ2PSX", "narrow16", "", "F2", "0x7A", 64, 32, 1, false, false},
		{"VCVTUQQ2PSY", "narrow32", "", "F2", "0x7A", 64, 32, 1, false, false},
		{"VCVTUQQ2PS", "narrow64", "round", "F2", "0x7A", 64, 32, 1, false, false},
	}
}

type x86PackedOracleShape struct{ source, destination, lanes int }

func (spec x86PackedConversionOracle) shapes() []x86PackedOracleShape {
	var widths []int
	switch spec.shape {
	case "single", "narrow16":
		widths = []int{16}
	case "narrow32":
		widths = []int{32}
	case "narrow64":
		widths = []int{64}
	default:
		widths = []int{16, 32, 64}
	}
	var result []x86PackedOracleShape
	for _, width := range widths {
		source, destination := width, width
		lanes := width * 8 / spec.input
		if spec.shape == "wide" {
			source, lanes = width/2, width*8/spec.output
		} else if strings.HasPrefix(spec.shape, "narrow") {
			destination = width / 2
		}
		if source < 16 {
			source = 16
		}
		if destination < 16 {
			destination = 16
		}
		result = append(result, x86PackedOracleShape{source, destination, lanes})
	}
	return result
}

func TestX86PackedConversionIndependentCompleteGoRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxcvm1 = []ytab{\n\t{Zm_r_xm, 2, argList{Yxm, Yxr}},\n\t{Zm_r_xm, 2, argList{Yxm, Ymr}},\n}") {
		t.Fatal("complete legacy operand table changed")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, spec := range x86PackedConversionOracleSpecs() {
		if spec.legacy {
			mmxPrefix, mmxOpcode := "Pm", "0x2d"
			if spec.input == 64 {
				mmxPrefix = "Pe"
			}
			if strings.Contains(spec.name, "CVTT") {
				mmxOpcode = "0x2c"
			}
			want := fmt.Sprintf("{A%s, yxcvm1, Px, opBytes{%s, %s, %s, %s}}", spec.name, spec.pp, spec.opcode, mmxPrefix, mmxOpcode)
			if !strings.Contains(string(legacy), want) {
				t.Fatal("legacy opcode attributes changed", want)
			}
			count += 2
			continue
		}
		shapes := spec.shapes()
		table := "_yvcvtpd2qq"
		switch {
		case spec.shape == "same" && spec.vex:
			table = "_yvcvtdq2ps"
		case spec.shape == "wide":
			table = "_yvcvtps2qq"
			if spec.name == "VCVTUDQ2PD" {
				table = "_yvcvtudq2pd"
			}
		case spec.shape == "narrow64":
			table = "_yvcvtpd2dq"
		case spec.shape == "narrow16", spec.shape == "narrow32":
			table = "_yvcvtpd2udq" + strings.ToLower(spec.name[len(spec.name)-1:])
			if spec.vex {
				table = strings.Replace(table, "udq", "dq", 1)
			}
		}
		type row struct {
			classes []string
			zcase   string
			offset  int
		}
		var rows []row
		var opbytes []string
		prefix := map[int]string{16: "x", 32: "y", 64: "z"}
		appendShape := func(shape x86PackedOracleShape, evex bool) {
			encoding, word, extra := "vex", 0, ""
			if evex {
				encoding, word, extra = "evex", spec.w, "Evex"
			}
			src := "Y" + prefix[shape.source] + "m" + extra
			dst := "Y" + prefix[shape.destination] + "r" + extra
			src, dst = strings.ReplaceAll(src, "zmEvex", "zm"), strings.ReplaceAll(dst, "zrEvex", "zr")
			bits := shape.source * 8
			if spec.shape == "wide" {
				bits = shape.destination * 8
			}
			attributes := fmt.Sprintf("avxEscape | %s%d", encoding, bits)
			if spec.pp != "" {
				attributes += " | " + encoding + spec.pp
			}
			attributes += fmt.Sprintf(" | %s0F | %sW%d", encoding, encoding, word)
			opbytes = append(opbytes, attributes)
			if evex {
				attributes = fmt.Sprintf("evexN%d | evexBcstN%d", shape.lanes*spec.input/8, spec.input/8)
				if bits == 512 && spec.control != "" {
					attributes += map[string]string{"round": " | evexRoundingEnabled", "sae": " | evexSaeEnabled"}[spec.control]
				}
				opbytes = append(opbytes, attributes+" | evexZeroingEnabled")
				rows = append(rows, row{[]string{src, dst}, "Zevex_rm_v_r", 0}, row{[]string{src, "Yknot0", dst}, "Zevex_rm_k_r", 3})
			} else {
				rows = append(rows, row{[]string{src, dst}, "Zvex_rm_v_r", 2})
			}
			opbytes = append(opbytes, spec.opcode)
		}
		if spec.vex {
			for _, shape := range shapes {
				if shape.source < 64 && shape.destination < 64 {
					appendShape(shape, false)
				}
			}
		}
		if len(shapes) == 3 && spec.name != "VCVTUDQ2PD" {
			shapes = []x86PackedOracleShape{shapes[2], shapes[0], shapes[1]}
		}
		for _, shape := range shapes {
			appendShape(shape, true)
		}
		index, offset := 0, 0
		for _, actual := range rules {
			if actual.Opcode != spec.name {
				continue
			}
			if index >= len(rows) {
				t.Fatal("unexpected extra Go encoder row", spec.name)
			}
			want := rows[index]
			if actual.Ytab != table || actual.Prefix != "Pavx" || actual.RowIndex != index || actual.EncodingOffset != offset ||
				actual.ZCase != want.zcase || actual.ZOffset != want.offset || !reflect.DeepEqual(actual.Classes, want.classes) || !reflect.DeepEqual(actual.OpBytes, opbytes) {
				t.Fatalf("%s row%d changed: %+v\nwant %s %+v %v", spec.name, index, actual, table, want, opbytes)
			}
			index, offset, count = index+1, offset+want.offset, count+1
		}
		if index != len(rows) {
			t.Fatal("missing encoder rows", spec.name, index, len(rows))
		}
	}
	t.Logf("38 independent names, %d complete Go encoder rows", count)
}

func x86PackedConversionOracleRows(arch string) []string {
	var rows []string
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
	for _, spec := range x86PackedConversionOracleSpecs() {
		for _, shape := range spec.shapes() {
			destination := bank[shape.destination] + "7"
			for _, source := range []string{bank[shape.source] + "0", "(AX)", "3(BX)(CX*4)"} {
				rows = append(rows, spec.name+" "+source+","+destination)
				if !spec.legacy {
					rows = append(rows, spec.name+" "+source+",K1,"+destination, spec.name+".Z "+source+",K7,"+destination)
				}
			}
			if !spec.legacy {
				rows = append(rows, spec.name+".BCST (AX),"+destination, spec.name+".BCST.Z 3(BX)(CX*4),K7,"+destination)
				if arch == "amd64" {
					rows = append(rows, spec.name+" "+bank[shape.source]+"31,"+bank[shape.destination]+"31")
				}
			}
			if (shape.source == 64 || shape.destination == 64) && spec.control != "" {
				suffixes := []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}
				if spec.control == "sae" {
					suffixes = []string{"SAE"}
				}
				for _, suffix := range suffixes {
					rows = append(rows, spec.name+"."+suffix+" "+bank[shape.source]+"0,"+destination,
						spec.name+"."+suffix+".Z "+bank[shape.source]+"0,K7,"+destination)
				}
			}
		}
	}
	return rows
}

func TestX86PackedConversionFiveTargetsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86PackedConversionOracleRows(target.arch)
			seen := make(map[string]bool)
			const batchSize = 96
			for start := 0; start < len(rows); start += batchSize {
				end := start + batchSize
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
					var source strings.Builder
					for index, row := range rows[start:end] {
						if seen[row] {
							t.Fatal("duplicate matrix row", row)
						}
						seen[row] = true
						fmt.Fprintf(&source, "TEXT ·f%d(SB),4,$0-0\n%s\nRET\n", index, row)
					}
					goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
					file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
					ir := x86ScalarFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0)
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						compileLLVMToObject(t, llc, target.triple, "packed-conversion.ll", "packed-conversion.o", input)
					}
				})
			}
			if len(seen) != len(rows) {
				t.Fatal("incomplete batch union")
			}
			t.Logf("%d unchanged unique formats, <=96 functions/module, 3 public Context APIs and 2 emitter IR pipelines; initialized public objects are separate", len(rows))
		})
	}
}

func TestX86PackedConversionMMXAndTargetRemainContext(t *testing.T) {
	for _, spec := range x86PackedConversionOracleSpecs() {
		shape := spec.shapes()[0]
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
		row := spec.name + " " + bank[shape.source] + "0," + bank[shape.destination] + "1"
		for _, target := range []string{"", "aarch64-unknown-linux-gnu", "i386-unknown-linux-gnu"} {
			_, err := x86ScalarFPBitViewAPI(t, "TEXT ·f(SB),4,$0-0\nRET\n"+row+"\n", "func f()", "amd64", target, "text")
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("dead instruction acquired a foreign/missing target", row, target, err)
			}
		}
		if spec.legacy {
			for _, destination := range []string{"M0", "M7"} {
				row := spec.name + " X0," + destination
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
				_, err := x86ScalarFPBitViewAPI(t, "TEXT ·f(SB),4,$0-0\n"+row+"\nRET\n", "func f()", "amd64", "x86_64-unknown-linux-gnu", "text")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("virtual MMX destination granted physical x87 state", row, err)
				}
			}
		}
	}
}
