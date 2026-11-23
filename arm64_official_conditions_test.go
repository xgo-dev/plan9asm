package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func arm64OfficialConditionalSource(t *testing.T) (string, []string, map[string]FuncSig) {
	t.Helper()
	corpus := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata")
	var source strings.Builder
	var instructions []string
	sigs := make(map[string]FuncSig)
	for _, name := range []string{"arm64.s", "arm64enc.s"} {
		data, err := os.ReadFile(filepath.Join(corpus, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			text, _, _ := strings.Cut(line, "//")
			instruction := strings.TrimSpace(text)
			op, operands, _ := strings.Cut(strings.ReplaceAll(instruction, "\t", " "), " ")
			switch op {
			case "CCMN", "CCMNW", "CCMP", "CCMPW", "CINC", "CINCW", "CINV", "CINVW",
				"CNEG", "CNEGW", "CSEL", "CSELW", "CSET", "CSETW", "CSETM", "CSETMW",
				"CSINC", "CSINCW", "CSINV", "CSINVW", "CSNEG", "CSNEGW",
				"FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED", "FCSELS", "FCSELD":
			default:
				continue
			}
			args := strings.Split(operands, ",")
			for index := range args {
				args[index] = strings.TrimSpace(args[index])
			}
			if args[0] == "AL" || args[0] == "NV" {
				continue
			}

			name := fmt.Sprintf("compareOfficialCondition%d", len(instructions))
			writeARM64OfficialConditionalBody(&source, name, op, instruction, args[1:])
			instructions = append(instructions, instruction)
			sigs[name] = FuncSig{
				Name: name, Args: []LLVMType{Ptr}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			}
		}
	}
	if len(instructions) != 56 {
		t.Fatalf("found %d original conditional operations requiring NZCV, want 56", len(instructions))
	}
	return source.String(), instructions, sigs
}

func writeARM64OfficialConditionalBody(source *strings.Builder, name, op, instruction string, args []string) {
	var registers []string
	used := make(map[string]bool)
	for _, operand := range args {
		if (strings.HasPrefix(operand, "R") || strings.HasPrefix(operand, "F")) && !used[operand] {
			registers = append(registers, operand)
			used[operand] = true
		}
	}
	var scratch []string
	for index := 9; len(scratch) < 4; index++ {
		register := fmt.Sprintf("R%d", index)
		if index != 18 && !used[register] {
			scratch = append(scratch, register)
		}
	}
	base, value := scratch[0], scratch[1]
	saved := []struct {
		register string
		scratch  string
	}{{"R29", scratch[2]}, {"R30", scratch[3]}}

	fmt.Fprintf(source, "TEXT %s(SB),516,$0-16\nMOVD data+0(FP),%s\n", name, base)
	for _, save := range saved {
		if used[save.register] {
			fmt.Fprintf(source, "MOVD %s,%s\n", save.register, save.scratch)
		}
	}
	floatMove := "FMOVD"
	if strings.HasSuffix(op, "S") {
		floatMove = "FMOVS"
	}
	for index, register := range registers {
		move := "MOVD"
		if strings.HasPrefix(register, "F") {
			move = floatMove
		}
		fmt.Fprintf(source, "%s %d(%s),%s\n", move, 8*index, base, register)
	}
	fmt.Fprintf(source, "MOVD 24(%s),%s\nMSR %s,NZCV\n%s\n", base, value, value, instruction)
	result := args[len(args)-1]
	switch {
	case strings.HasPrefix(op, "CC"), strings.HasPrefix(op, "FCC"):
		fmt.Fprintf(source, "MRS NZCV,%s\n", value)
	case strings.HasPrefix(result, "F"):
		fmt.Fprintf(source, "%s %s,%s\n", floatMove, result, value)
	default:
		fmt.Fprintf(source, "MOVD %s,%s\n", result, value)
	}
	for _, save := range saved {
		if used[save.register] {
			fmt.Fprintf(source, "MOVD %s,%s\n", save.scratch, save.register)
		}
	}
	fmt.Fprintf(source, "MOVD %s,ret+8(FP)\nRET\n", value)
}

func TestCrossLinuxRuntimeMatrixARM64OfficialConditions(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, instructions, sigs := arm64OfficialConditionalSource(t)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}

	inputs := [][3]uint64{
		{0x3ff000003f800000, 0xc0000000c0000000, 0x4010000040800000},
		{0x8000000000000000, 0x7f8000007f800000, 0xfff80000ffc00000},
		{^uint64(0), 0, 0x8000000000000001},
	}
	var original, calls, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <inttypes.h>\n#include <stdio.h>\n")
	for index := range instructions {
		fmt.Fprintf(&original, "func compareOfficialCondition%d(*[4]uint64) uint64\n", index)
		fmt.Fprintf(&calls, "fmt.Printf(\"%%016x\\n\", compareOfficialCondition%d(&input))\n", index)
		fmt.Fprintf(&driver, "extern uint64_t compareOfficialCondition%d(const uint64_t *);\n", index)
	}
	original.WriteString("func main() {\nfor _, values := range [][3]uint64{\n")
	driver.WriteString("static const uint64_t inputs[][3] = {\n")
	for _, input := range inputs {
		fmt.Fprintf(&original, "{%#x,%#x,%#x},\n", input[0], input[1], input[2])
		fmt.Fprintf(&driver, "{UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x)},\n", input[0], input[1], input[2])
	}
	original.WriteString("} {\nfor flags := uint64(0); flags < 16; flags++ {\n")
	original.WriteString("input := [4]uint64{values[0],values[1],values[2],flags << 28}\n")
	original.WriteString(calls.String() + "}\n}\n}\n")
	driver.WriteString("};\nstatic const uint64_t expected[] = {\n")
	goos := runtime.GOOS
	if len(runner) != 0 {
		goos = "linux"
	}
	values := strings.Fields(string(arm64BinaryOriginalOutput(t, source, original.String(), goos, runner)))
	if want := len(inputs) * 16 * len(instructions); len(values) != want {
		t.Fatalf("original Go produced %d conditional results, want %d", len(values), want)
	}
	for _, value := range values {
		word, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			t.Fatalf("invalid original Go conditional result %q: %v", value, err)
		}
		fmt.Fprintf(&driver, "UINT64_C(%#x),\n", word)
	}
	driver.WriteString("};\nint main(void) {\nunsigned index = 0;\n")
	driver.WriteString("for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {\n")
	driver.WriteString("for (uint64_t flags = 0; flags < 16; flags++) {\n")
	driver.WriteString("const uint64_t input[] = {inputs[i][0], inputs[i][1], inputs[i][2], flags << 28};\n")
	for index, instruction := range instructions {
		fmt.Fprintf(&driver, "{uint64_t got = compareOfficialCondition%d(input);\n", index)
		fmt.Fprintf(&driver, "if (got != expected[index]) {\nfprintf(stderr, \"%%s input %%u NZCV %%\" PRIx64 \" got %%\" PRIx64 \" want %%\" PRIx64 \"\\n\", %q, i, flags, got, expected[index]);\nreturn 1;\n}\nindex++;\n}\n",
			strings.Join(strings.Fields(instruction), " "))
	}
	driver.WriteString("}\n}\nreturn 0;\n}\n")
	for index, variant := range []string{ir, armFloatEffectOptimizedIR(t, ir)} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR%d/backend-O%d", index, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "official_arm64_conditions", triple,
					variant, driver.String(), runner, level)
				t.Logf("%d original Go conditional observations", len(values))
			})
		}
	}
}
