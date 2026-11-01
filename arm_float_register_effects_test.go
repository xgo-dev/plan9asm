package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Each fixture initializes and observes whole D registers. In particular the
// other half of an S write is a known canary, not an unspecified native value.
type armFloatEffectCase struct {
	instruction string
	input       [4]uint64 // D0, D1, D15, R2 (low word)
	want        [4]uint64
}

func armFloatEffectSeed() [4]uint64 {
	return [4]uint64{0x4312345640000000, 0x4423456740800000, 0x4534567840e00000, 0xabcdef0100000003}
}

func armFloatEffectLow(old uint64, low uint32) uint64 {
	return old&0xffffffff00000000 | uint64(low)
}

func armFloatConversionEffectCases() []armFloatEffectCase {
	var cases []armFloatEffectCase
	// Go asm5 rows 84/85 have no hidden destination. Rows 86/87 use S30
	// (the low half of F15), including when an explicit operand aliases F15.
	for _, op := range []string{"MOVWF", "MOVWD", "MOVFW", "MOVDW"} {
		toFloat := strings.HasPrefix(op, "MOVW")
		double := strings.Contains(op, "D")
		for _, unsigned := range []bool{false, true} {
			for _, pair := range [][2]string{
				{"F0", "F1"}, {"F0", "F0"}, {"F15", "F0"},
				{"F0", "F15"}, {"F15", "F15"}, {"R2", "F0"}, {"R2", "F15"},
			} {
				if !toFloat && pair[0] == "R2" {
					pair[0], pair[1] = pair[1], pair[0]
				}
				for _, condition := range []string{"", ".EQ", ".NE"} {
					index := func(reg string) int {
						switch reg {
						case "F0":
							return 0
						case "F1":
							return 1
						case "F15":
							return 2
						default:
							return 3
						}
					}
					src, dst := index(pair[0]), index(pair[1])
					input := armFloatEffectSeed()
					integer := uint32(0xfffffff9) // -7; exact at either precision.
					floating := -7.75
					if unsigned {
						integer = 0x80000000
						floating = 3221225472 // exact, above the signed boundary.
					}
					if toFloat {
						input[src] = armFloatEffectLow(input[src], integer)
					} else if double {
						input[src] = math.Float64bits(floating)
					} else {
						input[src] = armFloatEffectLow(input[src], math.Float32bits(float32(floating)))
					}
					want := input
					if condition != ".NE" {
						if toFloat {
							value := float64(int32(integer))
							if unsigned {
								value = float64(integer)
							}
							if src == 3 {
								want[2] = armFloatEffectLow(want[2], integer)
							}
							if double {
								want[dst] = math.Float64bits(value)
							} else {
								want[dst] = armFloatEffectLow(want[dst], math.Float32bits(float32(value)))
							}
						} else {
							value := uint32(int32(floating))
							if unsigned {
								value = uint32(floating)
							}
							if dst == 3 {
								want[2] = armFloatEffectLow(want[2], value)
							}
							want[dst] = armFloatEffectLow(want[dst], value)
						}
					}
					suffix := condition
					if unsigned {
						suffix = ".U" + suffix
					}
					cases = append(cases, armFloatEffectCase{
						instruction: fmt.Sprintf("%s%s %s,%s", op, suffix, pair[0], pair[1]),
						input:       input, want: want,
					})
				}
			}
		}
	}
	return cases
}

func armFloatHalfWriteEffectCases() []armFloatEffectCase {
	var cases []armFloatEffectCase
	// Cover every named producer using the common single-register writer,
	// including all arithmetic aliases, two/three operands, and full-D controls.
	for _, operation := range []struct {
		op, operands string
		value        float32
	}{
		{"MOVF", "$2.0,F1", 2}, {"MOVF", "F0,F1", 2}, {"MOVF", "F1,F1", 4},
		{"MOVF", "0(R0),F1", 2}, {"MOVW", "R2,F1", math.Float32frombits(3)},
		{"ADDF", "F0,F1", 6}, {"ADDF", "F0,F1,F1", 6},
		{"SUBF", "F0,F1", 2}, {"SUBF", "F0,F1,F1", 2},
		{"MULF", "F0,F1", 8}, {"MULF", "F0,F1,F1", 8},
		{"NMULF", "F0,F1", -8}, {"NMULF", "F0,F1,F1", -8},
		{"DIVF", "F0,F1", 2}, {"DIVF", "F0,F1,F1", 2},
		{"MULAF", "F0,F1,F1", 12}, {"FMULAF", "F0,F1,F1", 12},
		{"MULSF", "F0,F1,F1", -4}, {"FMULSF", "F0,F1,F1", -4},
		{"NMULAF", "F0,F1,F1", -12}, {"FNMULAF", "F0,F1,F1", -12},
		{"NMULSF", "F0,F1,F1", 4}, {"FNMULSF", "F0,F1,F1", 4},
		{"NEGF", "F1,F1", -4}, {"ABSF", "F1,F1", 4}, {"SQRTF", "F1,F1", 2},
		{"MOVDF", "F0,F1", 2}, {"MOVD", "F0,F1", 2}, {"MOVFD", "F0,F1", 2},
	} {
		for _, condition := range []string{"", ".EQ", ".NE"} {
			input := armFloatEffectSeed()
			if operation.op == "MOVDF" || operation.op == "MOVD" {
				input[0] = math.Float64bits(2)
			}
			want := input
			if condition != ".NE" {
				if operation.op == "MOVD" || operation.op == "MOVFD" {
					want[1] = math.Float64bits(float64(operation.value))
				} else {
					want[1] = armFloatEffectLow(want[1], math.Float32bits(operation.value))
				}
			}
			cases = append(cases, armFloatEffectCase{
				instruction: operation.op + condition + " " + operation.operands,
				input:       input, want: want,
			})
		}
	}
	return cases
}

func armFloatEffectSource(cases []armFloatEffectCase) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig, len(cases))
	for i, fixture := range cases {
		name := fmt.Sprintf("effect%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-8
MOVW input+0(FP),R0
MOVW output+4(FP),R1
MOVD 0(R0),F0
MOVD 8(R0),F1
MOVD 16(R0),F15
MOVW 24(R0),R2
MOVW $0,R3
CMP $0,R3
%s
MOVD F0,0(R1)
MOVD F1,8(R1)
MOVD F15,16(R1)
MOVW R2,24(R1)
RET
`, name, fixture.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	return source.String(), sigs
}

func TestARMFloatRegisterEffectMatrixCoverage(t *testing.T) {
	conversions := armFloatConversionEffectCases()
	writers := armFloatHalfWriteEffectCases()
	if len(conversions) != 168 || len(writers) != 87 {
		t.Fatalf("incomplete effect matrix: conversions=%d writers=%d", len(conversions), len(writers))
	}
	source, sigs := armFloatEffectSource(append(conversions, writers...))
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm-float-effects.ll", "arm-float-effects.o", ir)
		})
	}
}

func armFloatEffectOptimizedIR(t *testing.T, ir string) string {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	return module.String()
}
