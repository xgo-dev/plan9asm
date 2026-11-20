package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RawByteShiftLiteralBytes(left bool, width, destination, count int) []byte {
	code := encodeX86RawVectorByteShift(left, true, width, 0, destination, byte(count))
	code[len(code)-2] = code[len(code)-2]&0x38 | 0x05
	code = append(code[:len(code)-1], 1, 0, 0, 0, byte(count), 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*19+9))
	}
	return code
}

func x86RawByteShiftLiteralSource(name string, code []byte) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", name)
	for _, value := range code {
		fmt.Fprintf(&source, "BYTE $%#02x\n", value)
	}
	return source.String()
}

// Go's _yvpslldq has register-only VEX rows and three EVEX memory rows.
// These original mode64 bytes cover both directions, all memory tuple widths,
// low/high destinations and the lane/zero boundary counts. The full byte
// selector domain is independently checked below, without a giant LLVM module.
func TestX86RawByteShiftLiteralCompleteObjects(t *testing.T) {
	var source, declarations strings.Builder
	rows := 0
	for _, left := range []bool{false, true} {
		for _, width := range []int{16, 32, 64} {
			for _, destination := range []int{0, 31} {
				for _, count := range []int{0, 1, 7, 15, 16, 17, 255} {
					name := fmt.Sprintf("Shift%d", rows)
					rows++
					source.WriteString(x86RawByteShiftLiteralSource(name, x86RawByteShiftLiteralBytes(left, width, destination, count)))
					fmt.Fprintf(&declarations, "func %s()\n", name)
				}
			}
		}
	}
	if rows != 84 {
		t.Fatal("incomplete independent shift directory", rows)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil {
						t.Fatal("exact byte-shift literal tuple was lost", err)
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

func TestX86RawByteShiftLiteralEverySelectorAndExtent(t *testing.T) {
	for _, left := range []bool{false, true} {
		for _, width := range []int{16, 32, 64} {
			for count := 0; count < 256; count++ {
				code := x86RawByteShiftLiteralBytes(left, width, 31, count)
				decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "Shift", map[string]bool{})
				if err != nil || len(decoded) != 2 {
					t.Fatal("complete physical literal failed to decode", left, width, count, err)
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawByteShiftLiteralSource("Shift", code)), "amd64")
				if err != nil || len(file.Funcs[0].Instrs) != 3 || file.Funcs[0].Instrs[0].Op != OpTEXT ||
					file.Funcs[0].Instrs[2].Op != OpRET {
					t.Fatal("literal lost its complete source replay", left, width, count, err)
				}
				ins := file.Funcs[0].Instrs[1]
				form, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
				if !known || err != nil || form.memoryBytes != width || form.countOperand.Imm != int64(count) ||
					form.countMode != x86PackedShiftBytes || form.left != left || !x86RawByteShiftLiteralForm(ins, "amd64") ||
					x86RawByteShiftLiteralForm(ins, "386") {
					t.Fatal("literal/selector changed its typed identity", left, width, count, err)
				}
				address, valid := x86StaticSBReadAddress(ins.Args[1], "amd64")
				if !valid {
					t.Fatal("literal has no DATA address")
				}
				state := x86ResultState{flags: 0x3f, loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(width)}}
				if accepted, known := x86ResultPackedShiftStep(ins, &state, nil, "amd64"); !accepted || !known ||
					state.vectorBytes(31) != ^uint64(0) || state.flags != 0x3f {
					t.Fatal("exact constant did not define output bytes", left, width, count)
				}
				state.loweredStaticReads[address]--
				if accepted, _ := x86ResultPackedShiftStep(ins, &state, nil, "amd64"); accepted {
					t.Fatal("even a saturating count requires the entire memory tuple", left, width, count)
				}
			}
		}
	}
}

func TestX86RawByteShiftLiteralKeepsSourceAndReturnBoundaries(t *testing.T) {
	for _, left := range []bool{false, true} {
		for _, width := range []int{16, 32, 64} {
			source := x86RawByteShiftLiteralSource("Shift", x86RawByteShiftLiteralBytes(left, width, 0, 255))
			for _, changed := range []string{
				strings.Replace(source, "$0-0", "$16-0", 1),
				strings.Replace(source, "BYTE ", "MOVQ $0,SP\nBYTE ", 1),
			} {
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, changed, "func Shift()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("constant-zero result waived a raw-return frame", left, width, api, err)
					}
				}
			}
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
			if err != nil || len(file.Data) != 1 {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: "Shift", Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone query borrowed the lowering-only DATA owner", left, width, err)
			}
			file.Data[0].Payload[0] ^= 1
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:       map[string]FuncSig{"Shift": {Name: "Shift", Ret: Void}},
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("constant-zero result waived changed original DATA", left, width, err)
			}
		}
	}
}
