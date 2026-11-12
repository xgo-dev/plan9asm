package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawIntegerCompareLiteralCase struct {
	name, op           string
	width, tuple, mask int
	maskResult         bool
	code               []byte
}

// Independent _yvpcmpeqb witnesses include its two VEX and six EVEX rows,
// each opcode's full/broadcast tuple, and both VEX prefixes where encodable.
// The production opcode registry does not supply these bytes or cardinality.
func x86RawIntegerCompareLiteralCases() []x86RawIntegerCompareLiteralCase {
	var rows []x86RawIntegerCompareLiteralCase
	for _, operation := range []struct {
		name      string
		opcode    byte
		mapNumber byte
		laneBytes int
	}{
		{"VPCMPEQB", 0x74, 1, 1}, {"VPCMPEQW", 0x75, 1, 2},
		{"VPCMPEQD", 0x76, 1, 4}, {"VPCMPEQQ", 0x29, 2, 8},
		{"VPCMPGTB", 0x64, 1, 1}, {"VPCMPGTW", 0x65, 1, 2},
		{"VPCMPGTD", 0x66, 1, 4}, {"VPCMPGTQ", 0x37, 2, 8},
	} {
		for _, generation := range []string{"VEX2", "VEX3", "EVEX"} {
			if generation == "VEX2" && operation.mapNumber != 1 {
				continue
			}
			widths, masks := []int{16, 32}, []int{0}
			if generation == "EVEX" {
				widths, masks = []int{16, 32, 64}, []int{0, 3, 7}
			}
			for length, width := range widths {
				for _, mask := range masks {
					broadcasts := []bool{false}
					if generation == "EVEX" && operation.laneBytes >= 4 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						row := x86RawIntegerCompareLiteralCase{
							name: fmt.Sprintf("%s%s_%d_%d_%t", operation.name, generation, width, mask, broadcast),
							op:   operation.name, width: width, tuple: width, mask: mask, maskResult: generation == "EVEX",
						}
						switch generation {
						case "VEX2":
							row.code = []byte{0xc5, 0xf9 | byte(length<<2)}
						case "VEX3":
							row.code = []byte{0xc4, 0xe0 | operation.mapNumber, 0x79 | byte(length<<2)}
						case "EVEX":
							w := byte(0)
							if operation.laneBytes == 8 {
								w = 0x80
							}
							row.code = []byte{0x62, 0xf0 | operation.mapNumber, 0x7d | w, 0x08 | byte(length<<5) | byte(mask)}
							if broadcast {
								row.code[3] |= 0x10
								row.op += ".BCST"
								row.tuple = operation.laneBytes
							}
						}
						// RIP source, vector input 0, destination vector 2 or K2.
						row.code = append(row.code, operation.opcode, 0x15, 1, 0, 0, 0, 0xc3)
						for index := 0; index < row.tuple; index++ {
							row.code = append(row.code, byte(index*17+5))
						}
						rows = append(rows, row)
					}
				}
			}
		}
	}
	return rows
}

func x86RawIntegerCompareLiteralSource(row x86RawIntegerCompareLiteralCase) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", row.name)
	source.WriteString("VPXORD Z0,Z0,Z0\nMOVL $5,AX\nKMOVD AX,K3\nKMOVD AX,K7\n")
	for _, value := range row.code {
		fmt.Fprintf(&source, "BYTE $%#02x\n", value)
	}
	return source.String()
}

func x86RawIntegerCompareLiteralObjects(t *testing.T, triple string) {
	t.Helper()
	rows := x86RawIntegerCompareLiteralCases()
	if len(rows) != 136 {
		t.Fatal("incomplete independent integer compare literal directory", len(rows))
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for start := 0; start < len(rows); start += 64 {
		end := start + 64
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch%d", start/64), func(t *testing.T) {
			var source, declarations strings.Builder
			for _, row := range rows[start:end] {
				source.WriteString(x86RawIntegerCompareLiteralSource(row))
				fmt.Fprintf(&declarations, "func %s()\n", row.name)
			}
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil {
						t.Fatal("bound integer comparison lost its literal tuple", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86RawIntegerCompareLiteralLinuxObjects(t *testing.T) {
	x86RawIntegerCompareLiteralObjects(t, "x86_64-unknown-linux-gnu")
}

func TestX86RawIntegerCompareLiteralDarwinObjects(t *testing.T) {
	x86RawIntegerCompareLiteralObjects(t, "x86_64-apple-darwin")
}

func TestX86RawIntegerCompareLiteralWindowsObjects(t *testing.T) {
	x86RawIntegerCompareLiteralObjects(t, "x86_64-pc-windows-msvc")
}

func TestX86RawIntegerCompareLiteralEveryInputByteAndTuple(t *testing.T) {
	for _, row := range x86RawIntegerCompareLiteralCases() {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawIntegerCompareLiteralSource(row)), "amd64")
		if err != nil {
			t.Fatal(row.name, err)
		}
		for _, ins := range file.Funcs[0].Instrs {
			if !ins.x86RIPLiteral {
				continue
			}
			form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, "amd64")
			if !known || err != nil || string(ins.Op) != row.op || form.byteWidth != row.width ||
				form.memoryBytes != row.tuple || form.maskResult != row.maskResult ||
				!x86RawIntegerCompareLiteralForm(ins, "amd64") || x86RawIntegerCompareLiteralForm(ins, "386") {
				t.Fatal("original bytes changed their independent tuple/destination role", row.name, err)
			}
			address, valid := x86StaticSBReadAddress(form.source, "amd64")
			if !valid {
				t.Fatal("literal lost its DATA identity", row.name)
			}
			for missing := -1; missing < row.width; missing++ {
				state := x86ResultState{flags: 0x3f,
					loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(row.tuple)}}
				state.masks[3], state.masks[7] = true, true
				bytes := ^uint64(0)
				if missing >= 0 {
					bytes &^= uint64(1) << uint(missing)
				}
				state.writeVector(0, 64, bytes, false)
				accepted, known := x86ResultVectorCompareStep(ins, &state, nil, "amd64")
				if !known || accepted != (missing < 0) || state.flags != 0x3f {
					t.Fatal("comparison invented an input byte or changed FLAGS", row.name, missing)
				}
				if accepted && (row.maskResult && !state.masks[2] || !row.maskResult && state.vectorBytes(2) != ^uint64(0)) {
					t.Fatal("comparison lost its mask/vector destination", row.name)
				}
				state.loweredStaticReads[address]--
				if accepted, _ := x86ResultVectorCompareStep(ins, &state, nil, "amd64"); accepted {
					t.Fatal("comparison accepted an incomplete tuple", row.name)
				}
			}
		}
	}
}

func TestX86RawIntegerCompareLiteralKeepsMissingInputsAndSource(t *testing.T) {
	for _, row := range x86RawIntegerCompareLiteralCases() {
		source := x86RawIntegerCompareLiteralSource(row)
		changes := []string{
			strings.Replace(source, "VPXORD Z0,Z0,Z0\n", "", 1),
			strings.Replace(source, "$0-0", "$16-0", 1),
			strings.Replace(source, "BYTE ", "MOVQ $0,SP\nBYTE ", 1),
		}
		if row.mask != 0 {
			changes = append(changes, strings.Replace(source, fmt.Sprintf("KMOVD AX,K%d\n", row.mask), "", 1))
		}
		for _, changed := range changes {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, changed, "func "+row.name+"()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("literal waived an independent input/return obligation", row.name, api, err)
				}
			}
		}
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil || len(file.Data) != 1 {
			t.Fatal(row.name, err)
		}
		if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("standalone comparison query borrowed the DATA owner", row.name, err)
		}
		file.Data[0].Payload[0] ^= 1
		options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
			ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
		if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("comparison accepted changed original DATA", row.name, err)
		}
	}
}
