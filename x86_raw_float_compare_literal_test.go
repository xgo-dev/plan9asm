package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86RawFloatCompareLiteralCase struct {
	x86RawVectorLiteralCase
	op                               string
	width, tuple, input, immediateAt int
	maskResult                       bool
}

// Independent _yvcmppd/_yvcmpsd memory witnesses. Register-only SAE is not a
// literal form; K-result comparisons never acquire vector merge/zero semantics.
func x86RawFloatCompareLiteralCases() []x86RawFloatCompareLiteralCase {
	var rows []x86RawFloatCompareLiteralCase
	for pp, operation := range []string{"VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		for _, generation := range []string{"VEX2", "VEX3", "EVEX"} {
			widths, masks := []int{16, 32}, []int{0}
			if generation == "EVEX" {
				widths, masks = []int{16, 32, 64}, []int{0, 3, 7}
			}
			if pp >= 2 {
				widths = []int{16}
			}
			for length, width := range widths {
				for _, mask := range masks {
					broadcasts := []bool{false}
					if generation == "EVEX" && pp < 2 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						row := x86RawFloatCompareLiteralCase{op: operation, width: width, tuple: width, input: width}
						row.name = fmt.Sprintf("%s%s_%d_%d_%t", operation, generation, width, mask, broadcast)
						row.mask, row.maskResult = mask, generation == "EVEX"
						if pp >= 2 || broadcast {
							row.tuple = 4
							if pp&1 != 0 {
								row.tuple = 8
							}
						}
						if pp >= 2 {
							row.input = row.tuple
						}
						switch generation {
						case "VEX2":
							row.code = []byte{0xc5, 0xf8 | byte(length<<2) | byte(pp)}
						case "VEX3":
							row.code = []byte{0xc4, 0xe1, 0x78 | byte(length<<2) | byte(pp)}
						case "EVEX":
							w := byte(0)
							if pp&1 != 0 {
								w = 0x80
							}
							row.code = []byte{0x62, 0xf1, 0x7c | w | byte(pp), 0x08 | byte(length<<5) | byte(mask)}
							if broadcast {
								row.code[3] |= 0x10
								row.op += ".BCST"
							}
						}
						row.code = append(row.code, 0xc2, 0x15, 1, 0, 0, 0, 12, 0xc3)
						row.immediateAt = len(row.code) - 2
						for index := 0; index < row.tuple; index++ {
							row.code = append(row.code, byte(index*41+15))
						}
						rows = append(rows, row)
					}
				}
			}
		}
	}
	return rows
}

func x86RawFloatCompareLiteralObjects(t *testing.T, triple string) {
	t.Helper()
	rows := x86RawFloatCompareLiteralCases()
	if len(rows) != 54 {
		t.Fatal("incomplete independent floating comparison literal directory", len(rows))
	}
	var programs []x86RawVectorLiteralCase
	for _, row := range rows {
		for _, selector := range []byte{0, 12, 255} {
			program := row.x86RawVectorLiteralCase
			program.name += fmt.Sprintf("_%d", selector)
			program.code = append([]byte(nil), program.code...)
			program.code[row.immediateAt] = selector
			programs = append(programs, program)
		}
	}
	x86RawVectorLiteralObjects(t, triple, programs)
}

func TestX86RawFloatCompareLiteralLinuxObjects(t *testing.T) {
	x86RawFloatCompareLiteralObjects(t, "x86_64-unknown-linux-gnu")
}

func TestX86RawFloatCompareLiteralDarwinObjects(t *testing.T) {
	x86RawFloatCompareLiteralObjects(t, "x86_64-apple-darwin")
}

func TestX86RawFloatCompareLiteralWindowsObjects(t *testing.T) {
	x86RawFloatCompareLiteralObjects(t, "x86_64-pc-windows-msvc")
}

func TestX86RawFloatCompareLiteralEverySelector(t *testing.T) {
	for _, row := range x86RawFloatCompareLiteralCases() {
		for selector := 0; selector < 256; selector++ {
			code := append([]byte(nil), row.code...)
			code[row.immediateAt] = byte(selector)
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, row.name, map[string]bool{})
			if err != nil || len(decoded) != 2 {
				t.Fatal(row.name, selector, err)
			}
			form, known, err := x86FloatCompareProperties(decoded[0], "amd64")
			if err != nil || !known || string(decoded[0].Op) != row.op ||
				int(form.immediate) != selector || form.byteWidth != row.width ||
				form.memoryBytes != row.tuple || form.maskResult != row.maskResult {
				t.Fatal("literal lost complete selector, generation or tuple", row.name, selector, err)
			}
		}
	}
}

func TestX86RawFloatCompareLiteralEveryInputByteAndTuple(t *testing.T) {
	for _, row := range x86RawFloatCompareLiteralCases() {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawVectorLiteralSource(row.x86RawVectorLiteralCase)), "amd64")
		if err != nil {
			t.Fatal(row.name, err)
		}
		for _, ins := range file.Funcs[0].Instrs {
			if !ins.x86RIPLiteral {
				continue
			}
			address, valid := x86StaticSBReadAddress(ins.Args[1], "amd64")
			if !valid || !x86RawFloatCompareLiteralForm(ins, "amd64") {
				t.Fatal("comparison lost decoder-bound DATA", row.name)
			}
			if x86RawFloatCompareLiteralForm(ins, "386") {
				t.Fatal("mode32 borrowed an AMD64 RIP input", row.name)
			}
			for missing := -1; missing < row.width; missing++ {
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
					loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(row.tuple)}}
				state.masks[3], state.masks[7] = true, true
				input := ^uint64(0)
				if missing >= 0 {
					input &^= uint64(1) << uint(missing)
				}
				state.writeVector(0, 64, input, false)
				// Compare inside this instruction-local DATA scope. The ordinary
				// CFG clone deliberately discards that transient read permission.
				before := state
				accepted, known := x86ResultFloatCompareStep(ins, &state, nil, "amd64", false)
				want := missing < 0 || missing >= row.input
				if !known || accepted != want {
					t.Fatal("raw comparison lost required or passthrough input", row.name, missing, accepted)
				}
				expected := before
				if want {
					if row.maskResult {
						expected.masks[2] = true
					} else {
						expected.writeVector(2, 64, input, false)
					}
				}
				if !reflect.DeepEqual(state, expected) {
					t.Fatal("comparison changed FLAGS, masks or source/result aliases", row.name, missing)
				}
				before.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(row.tuple - 1)}
				if accepted, _ := x86ResultFloatCompareStep(ins, &before, nil, "amd64", false); accepted {
					t.Fatal("comparison borrowed missing literal bytes", row.name)
				}
			}
		}
	}
}

func TestX86RawFloatCompareLiteralKeepsInputsAndSourceBoundaries(t *testing.T) {
	for _, row := range x86RawFloatCompareLiteralCases() {
		source := x86RawVectorLiteralSource(row.x86RawVectorLiteralCase)
		changes := []string{
			strings.Replace(source, "$0-0", "$16-0", 1),
			strings.Replace(source, "BYTE ", "MOVQ $0,SP\nBYTE ", 1),
			strings.Replace(source, "VPXORD Z0,Z0,Z0\n", "", 1),
		}
		if row.mask != 0 {
			changes = append(changes, strings.Replace(source, fmt.Sprintf("KMOVD AX,K%d\n", row.mask), "", 1))
		}
		for _, changed := range changes {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, changed, "func "+row.name+"()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("literal waived input or return contract", row.name, api, err)
				}
			}
		}
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil || len(file.Data) != 1 {
			t.Fatal(row.name, err)
		}
		if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("standalone query borrowed comparison DATA", row.name, err)
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
