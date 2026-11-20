package plan9asm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestX86X87CompareNativeReadsDoNotGrantBacking(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		state := x86ResultState{x87: &x86ResultX87State{depth: 1, slots: 1}}
		state.pointerGP[0] = true
		instruction := x86X87ValueInstruction(t, "FCOMD 7(AX),F0")
		consumer := &amd64Ctx{goarch: arch, x87Mode: X87Software}
		if accepted, known := consumer.x87NativeMemoryValueResultStep(instruction, &state, nil, 0, arch); !known || !accepted {
			t.Fatal("paired conditional read rejected its defined operands")
		}
		if x86ResultRead(instruction.Args[0], 8, &state, nil, arch) || state.literalMemoryOperand != nil {
			t.Fatal("compare published a reusable pointee/backing fact")
		}
		arithmetic := x86X87ValueInstruction(t, "FADDD 7(AX),F0")
		if _, known := consumer.x87NativeMemoryValueResultStep(arithmetic, &state, nil, 0, arch); known {
			t.Fatal("compare contract expanded to arithmetic")
		}
	}
}

func TestX86X87CompareDeadVoidNeedsValuesAndPointer(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, raw := range []bool{false, true} {
			compare := "FCOMD (AX),F0\n"
			if raw {
				compare = x86RawDisplacementDirectives([]byte{0xdc, 0x10})
			}
			for _, test := range []struct {
				name, typ, push string
				valid           bool
			}{
				{"complete", "*byte", "FLD1\n", true},
				{"missing-F0", "*byte", "", false},
				{"complete-uintptr", "uintptr", "FLD1\n", true},
			} {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s input+0(FP),AX\nFINIT\n%s%sFINIT\nRET\n", word, move, test.push, compare)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/raw%t/%s/%s", arch, raw, test.name, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, "func Value(input "+test.typ+")", arch, triple, api, X87Software)
						if test.valid {
							if err != nil || ir == "" {
								t.Fatal("complete dead compare rejected", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("dead/Void bypassed compare inputs", err)
						}
					})
				}
			}
		}
	}
}

func TestX86X87CompareNativeDeadReadWidthsAndFaults(t *testing.T) {
	x86X87CompareDeadReadWidthsAndFaults(t, false)
}

func x86X87CompareDeadReadWidthsAndFaults(t *testing.T, numericAddress bool) {
	t.Helper()
	execution := x86ScalarCountHostExecution(t)
	arch, word, move := "amd64", 8, "MOVQ"
	if strconv.IntSize == 32 {
		arch, word, move = "386", 4, "MOVL"
	}
	inputType, cInputType := "*byte", "const uint8_t*"
	if numericAddress {
		inputType, cInputType = "uintptr", "uintptr_t"
	}
	var source, declarations, prototypes, callbacks, rows strings.Builder
	for _, raw := range []bool{false, true} {
		for _, suffix := range []string{"W", "WP", "L", "LP", "F", "FP", "D", "DP"} {
			width, opcode, digit := 4, byte(0xd8), byte(2)
			switch suffix[0] {
			case 'W':
				width, opcode = 2, 0xde
			case 'L':
				opcode = 0xda
			case 'D':
				width, opcode = 8, 0xdc
			}
			if strings.HasSuffix(suffix, "P") {
				digit = 3
			}
			for _, displacement := range []int{0, 7} {
				name := fmt.Sprint("DeadCompare", strings.Count(declarations.String(), "func "))
				instruction := fmt.Sprintf("FCOM%s (AX),F0\n", suffix)
				code := []byte{opcode, digit << 3}
				if displacement != 0 {
					instruction = fmt.Sprintf("FCOM%s 7(AX),F0\n", suffix)
					code = []byte{opcode, 0x40 | digit<<3, 7}
				}
				if raw {
					instruction = x86RawDisplacementDirectives(code)
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),AX\nFINIT\nFLD1\n%sFINIT\nMOVL $7,ret+%d(FP)\nRET\n", name, word+4, move, instruction, word)
				fmt.Fprintf(&declarations, "func %s(input %s) uint32\n", name, inputType)
				fmt.Fprintf(&prototypes, "extern uint32_t %s(%s);\n", name, cInputType)
				address := fmt.Sprintf("(uintptr_t)p-%d", displacement)
				if !numericAddress {
					address = "(const uint8_t*)(" + address + ")"
				}
				fmt.Fprintf(&callbacks, "static int run%s(const uint8_t*p){return %s(%s)==7?0:91;}\n", name, name, address)
				fmt.Fprintf(&rows, "{run%s,%d,%d},\n", name, width, width-1)
			}
		}
	}
	if strings.Count(declarations.String(), "func ") != 32 {
		t.Fatal("incomplete compare native-read matrix")
	}
	ir, err := x86X87InitializedWordAPI(t, source.String(), declarations.String(), arch, execution.triple, "Go", X87Software)
	if err != nil {
		t.Fatal("complete dead-read sources did not translate", err)
	}
	for _, width := range []struct {
		typ   string
		count int
	}{{"i16", 8}, {"i32", 8}, {"float", 8}, {"double", 8}} {
		if strings.Count(ir, "load volatile "+width.typ+",") != width.count {
			t.Fatal("wrong exact volatile compare read width", width, ir)
		}
	}
	driver := x86MemoryFaultDriver(prototypes.String()+callbacks.String(), rows.String())
	for _, optimized := range []bool{false, true} {
		input := ir
		if optimized {
			input = x86MulDivRoundOptimize(t, input)
		}
		for _, backend := range []string{"-O0", "-O2"} {
			t.Run(fmt.Sprintf("IR-O2-%t/%s", optimized, backend), func(t *testing.T) {
				executable := execution.compileLLVM(t, "compare-dead-read-widths", input, driver, backend)
				x86CheckMemoryFaultMatrix(t, execution, executable, 32)
			})
		}
	}
}
