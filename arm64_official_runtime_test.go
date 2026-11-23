package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func arm64OfficialSourceRows(t *testing.T) []string {
	t.Helper()
	corpus := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata")
	var rows []string
	for _, name := range []string{"arm64.s", "arm64enc.s"} {
		data, err := os.ReadFile(filepath.Join(corpus, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			text, _, _ := strings.Cut(line, "//")
			if instruction := strings.TrimSpace(text); instruction != "" {
				rows = append(rows, instruction)
			}
		}
	}
	return rows
}

func arm64OfficialRuntimeSymbol(index int) string {
	return fmt.Sprintf("compareOfficial%d", index)
}

func runARM64OfficialResultRuntime(t *testing.T, fixture, source string, instructions []string, inputs [][4]uint64) {
	t.Helper()
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}

	var original, driver strings.Builder
	original.WriteString("package main\nimport (\"encoding/binary\"; \"os\")\n")
	driver.WriteString("#include <stdint.h>\n#include <inttypes.h>\n#include <stdio.h>\n")
	sigs := make(map[string]FuncSig, len(instructions))
	for index := range instructions {
		name := arm64OfficialRuntimeSymbol(index)
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr}, Ret: I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		}
		fmt.Fprintf(&original, "func %s(*[4]uint64) uint64\n", name)
		fmt.Fprintf(&driver, "extern uint64_t %s(const uint64_t *);\n", name)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}

	original.WriteString("var cases = [...]func(*[4]uint64) uint64{\n")
	driver.WriteString("static uint64_t (*const cases[])(const uint64_t *) = {\n")
	for index := range instructions {
		name := arm64OfficialRuntimeSymbol(index)
		fmt.Fprintf(&original, "%s,\n", name)
		fmt.Fprintf(&driver, "%s,\n", name)
	}
	original.WriteString("}\nvar inputs = [...][4]uint64{\n")
	driver.WriteString("};\nstatic const uint64_t inputs[][4] = {\n")
	for _, input := range inputs {
		fmt.Fprintf(&original, "{%#x,%#x,%#x,%#x},\n", input[0], input[1], input[2], input[3])
		fmt.Fprintf(&driver, "{UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x),UINT64_C(%#x)},\n",
			input[0], input[1], input[2], input[3])
	}
	original.WriteString(`}
func main() {
	results := make([]uint64, 0, len(inputs)*len(cases))
	for _, input := range inputs {
		for _, run := range cases {
			results = append(results, run(&input))
		}
	}
	if err := binary.Write(os.Stdout, binary.LittleEndian, results); err != nil {
		panic(err)
	}
}
`)
	goos := runtime.GOOS
	if len(runner) != 0 {
		goos = "linux"
	}
	results := arm64BinaryOriginalOutput(t, source, original.String(), goos, runner)
	if want := 8 * len(inputs) * len(instructions); len(results) != want {
		t.Fatalf("original Go produced %d result bytes, want %d", len(results), want)
	}
	driver.WriteString("};\nstatic const uint64_t expected[] = {\n")
	for index := 0; index < len(results); index += 8 {
		fmt.Fprintf(&driver, "UINT64_C(%#x),\n", binary.LittleEndian.Uint64(results[index:]))
	}
	driver.WriteString("};\nstatic const char *const instructions[] = {\n")
	for _, instruction := range instructions {
		fmt.Fprintf(&driver, "%q,\n", strings.Join(strings.Fields(instruction), " "))
	}
	driver.WriteString(`};
int main(void) {
	unsigned index = 0;
	for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
		for (unsigned row = 0; row < sizeof(cases)/sizeof(cases[0]); row++) {
			uint64_t got = cases[row](inputs[i]);
			if (got != expected[index]) {
				fprintf(stderr, "%s input %u got %" PRIx64 " want %" PRIx64 "\n",
					instructions[row], i, got, expected[index]);
				return 1;
			}
			index++;
		}
	}
	return 0;
}
`)
	for index, variant := range []string{ir, armFloatEffectOptimizedIR(t, ir)} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR%d/backend-O%d", index, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fixture, triple,
					variant, driver.String(), runner, level)
				t.Logf("%d original Go observations", len(results)/8)
			})
		}
	}
}
