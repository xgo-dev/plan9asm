//go:build linux && amd64 && go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalFramedLeaf(t *testing.T) {
	cases := fixedLocalFramedLeafCases()
	var assembly, declarations strings.Builder
	for index, row := range cases {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		source := strings.NewReplacer("·Value(", "·"+name+"(", "leaf<>", fmt.Sprintf("leaf%d<>", index)).Replace(
			fixedLocalFramedLeafSource(row))
		assembly.WriteString(source)
	}
	inputs := []uint64{0, 1, 6, 7, 8, 0xffffffff, 0x100000000, ^uint64(0)}
	expected := make([][]string, len(inputs))
	for index, input := range inputs {
		for _, row := range cases {
			var result uint64
			switch row.name {
			case "numeric_bp", "partial_bp":
				result = input + 18
			case "private_address_bp":
				result = input*2 + 7
			case "unknown_bp", "untouched_bp":
				result = input + 7
			case "two_call_sites":
				result = input + 20
			case "loop_reentry":
				result = input + 54
			case "two_returns":
				result = input*2 + 7
				if input < 7 {
					result = input*2 - 7
				}
			default:
				t.Fatal("missing independent original-frame oracle", row.name)
			}
			expected[index] = append(expected[index], fmt.Sprintf("%016x", result))
		}
	}
	fixedLocalResultsRuntime(t, assembly.String(), declarations.String(), inputs, expected)
	if !t.Failed() {
		t.Logf("FRAMED_LEAF_NATIVE_COMPLETE functions=%d inputs_per_function=%d APIs=3 LLVM_levels=O0,O2 original_observations=%d LLVM_comparisons=%d",
			len(cases), len(inputs), len(cases)*len(inputs), len(cases)*len(inputs)*3*2)
	}
}

func TestCrossLinuxRuntimeMatrixGoAMD64FramedLeafIncomingAddress(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	inputs := []uint64{0, 1, 0xffffffff, 0x100000000, ^uint64(0)}
	var goCalls, cCalls strings.Builder
	var expected []string
	for _, input := range inputs {
		fmt.Fprintf(&goCalls, "{ a := uint64(0x%x); fmt.Printf(\"%%016x\\n\",Value(&a)) }\n", input)
		fmt.Fprintf(&cCalls, "{ uint64_t a = UINT64_C(0x%x); printf(\"%%016llx\\n\",(unsigned long long)value(&a)); }\n", input)
		expected = append(expected, fmt.Sprintf("%016x", input*2+7))
	}
	const declaration = "func Value(a *uint64) uint64"
	original := "package main\nimport \"fmt\"\n" + declaration + "\nfunc main() {\n" + goCalls.String() + "}\n"
	want := strings.Fields(string(x86ScalarFloatIntegerOriginalOutput(t, execution, fixedLocalFramedLeafIncomingAddress, original)))
	if strings.Join(want, " ") != strings.Join(expected, " ") {
		t.Fatal("original helper did not restore its caller's input address", want, expected)
	}
	label := runtimeCAsmLabel("example.invalid/framefixture.Value")
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + runtimeCAsmLabelPreamble +
		"extern uint64_t value(uint64_t *) __asm__(" + label + ");\nint main(void) {\n" + cCalls.String() + "return 0;\n}\n"
	pkg, request, options := fixedLocalPrivateLeafFixture(t, fixedLocalFramedLeafIncomingAddress, declaration)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					got := strings.Fields(string(execution.compileAndRunLLVM(t, "framed-leaf-input-address", input, driver, level)))
					if strings.Join(got, " ") != strings.Join(want, " ") {
						t.Fatal("translated helper changed caller input-address semantics", got, want)
					}
				})
			}
		})
	if !t.Failed() {
		t.Logf("FRAMED_LEAF_NATIVE_ADDRESS functions=1 inputs_per_function=%d APIs=3 LLVM_levels=O0,O2 original_observations=%d LLVM_comparisons=%d",
			len(inputs), len(inputs), len(inputs)*3*2)
	}
}

// These accepted original Go programs observe the automatic physical frame.
// Their framed variants deliberately remain translation counterexamples:
// arithmetic FLAGS do not retain their caller/body value across ADD/SUB SP.
func TestCrossLinuxRuntimeMatrixGoAMD64FramedLeafPhysicalFlags(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var assembly, declarations, calls strings.Builder
	var frames []int
	for _, frame := range []int{0, 8, 128} {
		for _, incoming := range []bool{true, false} {
			row := fixedLocalFramedLeafCase{
				caller: "CALL leaf<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
				helper: "CMPQ AX,BX",
				frame:  frame,
			}
			if incoming {
				row.caller = "CMPQ AX,BX\n CALL leaf<>(SB)"
				row.helper = "SETCS CL\n MOVBLZX CL,AX"
			}
			index := len(frames)
			name := fmt.Sprintf("Value%d", index)
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			fmt.Fprintf(&calls, "fmt.Println(%s(0))\nfmt.Println(%s(8))\n", name, name)
			assembly.WriteString(strings.NewReplacer("·Value(", "·"+name+"(",
				"leaf<>", fmt.Sprintf("leaf%d<>", index)).Replace(fixedLocalFramedLeafSource(row)))
			frames = append(frames, frame)
		}
	}
	original := "package main\nimport \"fmt\"\n" + declarations.String() + "func main() {\n" + calls.String() + "}\n"
	got := strings.Fields(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly.String(), original)))
	if len(got) != 2*len(frames) {
		t.Fatal("original physical-FLAGS observation inventory changed", len(got))
	}
	for index, frame := range frames {
		first, second := got[2*index], got[2*index+1]
		if frame == 0 {
			if first != "1" || second != "0" {
				t.Fatal("original zero-frame CALL/RET did not preserve both carry values", first, second)
			}
			continue
		}
		// Go can encode a 128-byte adjustment using the opposite operation
		// and a negative imm8. Do not assume every physical frame clears CF;
		// neither encoding preserves the preceding arithmetic input's CF.
		if first != second || first != "0" && first != "1" {
			t.Fatal("original automatic frame unexpectedly preserved arithmetic CF", frame, first, second)
		}
	}
	t.Logf("FRAMED_LEAF_PHYSICAL_FLAGS original_only=true functions=%d inputs_per_function=2 original_observations=%d LLVM_comparisons=0",
		len(frames), len(frames)*2)
}
