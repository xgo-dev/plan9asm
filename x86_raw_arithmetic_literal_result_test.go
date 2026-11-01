package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawArithmeticLiteralCase struct {
	x86RawVectorLiteralCase
	op                 string
	width, tuple, lane int
}

// Go's complete _yvandnpd rows have independent opcode-specific W and
// broadcast attributes. Keep wrapping and signed/unsigned saturation names
// explicit here rather than deriving witnesses from the production registry.
func x86RawArithmeticLiteralCases() []x86RawArithmeticLiteralCase {
	var rows []x86RawArithmeticLiteralCase
	for _, operation := range []struct {
		name   string
		opcode byte
		lane   int
	}{
		{"VPADDB", 0xfc, 1}, {"VPADDW", 0xfd, 2}, {"VPADDD", 0xfe, 4}, {"VPADDQ", 0xd4, 8},
		{"VPADDSB", 0xec, 1}, {"VPADDSW", 0xed, 2}, {"VPADDUSB", 0xdc, 1}, {"VPADDUSW", 0xdd, 2},
		{"VPSUBB", 0xf8, 1}, {"VPSUBW", 0xf9, 2}, {"VPSUBD", 0xfa, 4}, {"VPSUBQ", 0xfb, 8},
		{"VPSUBSB", 0xe8, 1}, {"VPSUBSW", 0xe9, 2}, {"VPSUBUSB", 0xd8, 1}, {"VPSUBUSW", 0xd9, 2},
	} {
		for _, generation := range []string{"VEX2", "VEX3", "EVEX"} {
			widths, masks := []int{16, 32}, []int{0}
			if generation == "EVEX" {
				widths, masks = []int{16, 32, 64}, []int{0, 3, 7}
			}
			for length, width := range widths {
				for _, mask := range masks {
					broadcasts := []bool{false}
					if generation == "EVEX" && operation.lane >= 4 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						row := x86RawArithmeticLiteralCase{op: operation.name, width: width, tuple: width, lane: operation.lane}
						row.name = fmt.Sprintf("%s%s_%d_%d_%t", operation.name, generation, width, mask, broadcast)
						row.mask = mask
						switch generation {
						case "VEX2":
							row.code = []byte{0xc5, 0xf9 | byte(length<<2)}
						case "VEX3":
							row.code = []byte{0xc4, 0xe1, 0x79 | byte(length<<2)}
						case "EVEX":
							w := byte(0)
							if operation.lane == 8 {
								w = 0x80
							}
							row.code = []byte{0x62, 0xf1, 0x7d | w, 0x08 | byte(length<<5) | byte(mask)}
							if broadcast {
								row.code[3] |= 0x10
								row.op += ".BCST"
								row.tuple = operation.lane
							}
							if mask == 7 {
								row.code[3] |= 0x80
								row.op += ".Z"
							}
						}
						row.code = append(row.code, operation.opcode, 0x15, 1, 0, 0, 0, 0xc3)
						for index := 0; index < row.tuple; index++ {
							row.code = append(row.code, byte(index*29+11))
						}
						rows = append(rows, row)
					}
				}
			}
		}
	}
	return rows
}

func x86RawArithmeticLiteralObjects(t *testing.T, triple string) {
	t.Helper()
	rows := x86RawArithmeticLiteralCases()
	if len(rows) != 244 {
		t.Fatal("incomplete independent add/sub literal directory", len(rows))
	}
	programs := make([]x86RawVectorLiteralCase, len(rows))
	for index, row := range rows {
		programs[index] = row.x86RawVectorLiteralCase
	}
	x86RawVectorLiteralObjects(t, triple, programs)
}

func TestX86RawArithmeticLiteralLinuxObjects(t *testing.T) {
	x86RawArithmeticLiteralObjects(t, "x86_64-unknown-linux-gnu")
}

func TestX86RawArithmeticLiteralDarwinObjects(t *testing.T) {
	x86RawArithmeticLiteralObjects(t, "x86_64-apple-darwin")
}

func TestX86RawArithmeticLiteralWindowsObjects(t *testing.T) {
	x86RawArithmeticLiteralObjects(t, "x86_64-pc-windows-msvc")
}

func TestX86RawArithmeticLiteralKeepsLaneAndTupleDependencies(t *testing.T) {
	for _, row := range x86RawArithmeticLiteralCases() {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawVectorLiteralSource(row.x86RawVectorLiteralCase)), "amd64")
		if err != nil {
			t.Fatal(row.name, err)
		}
		for _, ins := range file.Funcs[0].Instrs {
			if !ins.x86RIPLiteral {
				continue
			}
			if string(ins.Op) != row.op || !x86RawArithmeticLiteralForm(ins, "amd64") ||
				ins.x86RIPMemoryRead.source != 0 || ins.x86RIPMemoryRead.width != int64(row.tuple) {
				t.Fatal("arithmetic literal changed its independent opcode/tuple", row.name)
			}
			if x86RawArithmeticLiteralForm(ins, "386") {
				t.Fatal("mode32 borrowed an AMD64 RIP input", row.name)
			}
			address, valid := x86StaticSBReadAddress(ins.Args[0], "amd64")
			if !valid {
				t.Fatal("literal lost its DATA identity", row.name)
			}
			for _, input := range []int{0, 2} {
				for missing := -1; missing < row.width; missing++ {
					state := x86ResultState{flags: 0x3f,
						loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(row.tuple)}}
					state.masks[3], state.masks[7] = true, true
					state.writeVector(0, 64, ^uint64(0), false)
					state.writeVector(2, 64, ^uint64(0), false)
					want := ^uint64(0)
					if missing >= 0 {
						state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
						if input == 0 {
							for at := missing / row.lane * row.lane; at < (missing/row.lane+1)*row.lane; at++ {
								want &^= uint64(1) << uint(at)
							}
						} else if row.mask == 3 {
							want &^= uint64(1) << uint(missing)
						}
					}
					if accepted, known := x86ResultVectorArithmeticStep(ins, &state, nil, "amd64"); !accepted || !known ||
						state.vectorBytes(2) != want || state.flags != 0x3f {
						t.Fatal("arithmetic invented source/merge bytes or changed FLAGS", row.name, input, missing)
					}
					state.loweredStaticReads[address]--
					if accepted, _ := x86ResultVectorArithmeticStep(ins, &state, nil, "amd64"); accepted {
						t.Fatal("arithmetic accepted an incomplete tuple", row.name)
					}
				}
			}
		}
	}
}

func TestX86RawArithmeticLiteralKeepsMasksAndSourceBoundaries(t *testing.T) {
	for _, row := range x86RawArithmeticLiteralCases() {
		source := x86RawVectorLiteralSource(row.x86RawVectorLiteralCase)
		changes := []string{
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
					t.Fatal("literal waived an independent mask/return obligation", row.name, api, err)
				}
			}
		}
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil || len(file.Data) != 1 {
			t.Fatal(row.name, err)
		}
		if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("standalone query borrowed the arithmetic DATA owner", row.name, err)
		}
		file.Data[0].Payload[0] ^= 1
		options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
			ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
		if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("arithmetic accepted changed original DATA", row.name, err)
		}
	}
}
