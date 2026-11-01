package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type x86LegacyScalarMoveUpperForm struct {
	name, move string
	width      int
	register   bool
}

func x86LegacyScalarMoveUpperForms() []x86LegacyScalarMoveUpperForm {
	return []x86LegacyScalarMoveUpperForm{
		{name: "loadSS", move: "MOVSS", width: 4},
		{name: "copySS", move: "MOVSS", width: 4, register: true},
		{name: "loadSD", move: "MOVSD", width: 8},
		{name: "copySD", move: "MOVSD", width: 8, register: true},
	}
}

func x86LegacyScalarMoveUpperAssembly(goarch string) string {
	word, pointerMove := 8, "MOVQ"
	if goarch == "386" {
		word, pointerMove = 4, "MOVL"
	}
	var source strings.Builder
	for _, form := range x86LegacyScalarMoveUpperForms() {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),AX\n%s output+%d(FP),BX\nMOVUPS (AX),X0\n",
			form.name, word*2, pointerMove, pointerMove, word)
		if form.register {
			fmt.Fprintf(&source, "%s 16(AX),X1\n%s X1,X0\n", form.move, form.move)
		} else {
			fmt.Fprintf(&source, "%s 16(AX),X0\n", form.move)
		}
		source.WriteString("MOVUPS X0,(BX)\nRET\n")
	}
	return source.String()
}

func x86LegacyScalarMoveUpperIR(t *testing.T, goarch, triple string) string {
	t.Helper()
	assembly := x86LegacyScalarMoveUpperAssembly(goarch)
	requireX86GoAssemblerResult(t, goarch, assembly, true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	word := int64(8)
	if goarch == "386" {
		word = 4
	}
	sigs := make(map[string]FuncSig)
	for _, form := range x86LegacyScalarMoveUpperForms() {
		symbol := "scalar." + form.name
		sigs[symbol] = FuncSig{
			Name: symbol, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: word, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	ir, err := Translate(file, Options{
		Goarch: goarch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "scalar.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestX86LegacyScalarMoveUpperFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ goarch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i386-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			ir := x86LegacyScalarMoveUpperIR(t, target.goarch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "scalar-upper.ll", "scalar-upper.o", ir)
		})
	}
}

func x86LegacyScalarMoveActualGoUpperOracle(t *testing.T) {
	t.Helper()
	var declarations, tests strings.Builder
	declarations.WriteString("package scalar\nimport \"unsafe\"\n")
	tests.WriteString("package scalar\nimport (\"testing\"; \"unsafe\")\nfunc TestFullBytes(t *testing.T) {\n")
	for _, form := range x86LegacyScalarMoveUpperForms() {
		fmt.Fprintf(&declarations, "func %s(input, output unsafe.Pointer)\n", form.name)
		fmt.Fprintf(&tests, `
	for iteration := 0; iteration < 128; iteration++ {
		var input [32]byte
		var output [48]byte
		for index := range input {
			input[index] = byte(index*17 + iteration)
		}
		for index := range output {
			output[index] = byte(index*7 + iteration)
		}
		beforeInput, beforeOutput := input, output
		%[1]s(unsafe.Pointer(&input[0]), unsafe.Pointer(&output[16]))
		for index := range output {
			want := beforeOutput[index]
			if index >= 16 && index < 32 {
				lane := index - 16
				want = 0
				if lane < %[2]d {
					want = input[16+lane]
				} else if %[3]t {
					want = input[lane]
				}
			}
			if output[index] != want {
				t.Fatalf("%[1]s iteration=%%d byte=%%d got=%%#x want=%%#x", iteration, index, output[index], want)
			}
		}
		if input != beforeInput {
			t.Fatal("%[1]s changed input")
		}
	}
`, form.name, form.width, form.register)
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module scalar\n\ngo 1.20\n", "scalar.go": declarations.String(),
		"scalar_amd64.s": x86LegacyScalarMoveUpperAssembly("amd64"), "scalar_test.go": tests.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	command.WaitDelay = 2 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual Go full-byte scalar move oracle: %v\n%s", err, output)
	}
}

func TestCrossLinuxRuntimeMatrixX86LegacyScalarMoveUpperBytes(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	x86LegacyScalarMoveActualGoUpperOracle(t)
	var source strings.Builder
	source.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for _, form := range x86LegacyScalarMoveUpperForms() {
		fmt.Fprintf(&source, "extern void %s(void*,void*) __asm__(LABEL(\"scalar.%s\"));\n", form.name, form.name)
	}
	source.WriteString("int main(void) {\n")
	for _, form := range x86LegacyScalarMoveUpperForms() {
		register := 0
		if form.register {
			register = 1
		}
		fmt.Fprintf(&source, `
	for (unsigned iteration = 0; iteration < 128; iteration++) {
		uint8_t input[32], output[48], before_input[32], before_output[48];
		for (unsigned index = 0; index < sizeof(input); index++) {
			input[index] = index*17 + iteration;
		}
		for (unsigned index = 0; index < sizeof(output); index++) {
			output[index] = index*7 + iteration;
		}
		memcpy(before_input, input, sizeof(input));
		memcpy(before_output, output, sizeof(output));
		%[1]s(input, output + 16);
		for (unsigned index = 0; index < sizeof(output); index++) {
			uint8_t want = before_output[index];
			if (index >= 16 && index < 32) {
				unsigned lane = index - 16;
				want = lane < %[2]d ? input[16+lane] : (%[3]d ? input[lane] : 0);
			}
			if (output[index] != want) {
				fprintf(stderr, "%[1]s iteration=%%u byte=%%u got=%%02x want=%%02x\n", iteration, index, output[index], want);
				return 1;
			}
		}
		if (memcmp(input, before_input, sizeof(input))) {
			return 2;
		}
	}
`, form.name, form.width, register)
	}
	source.WriteString("\treturn 0;\n}\n")
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_upper_bytes", triple,
		x86LegacyScalarMoveUpperIR(t, "amd64", triple), source.String(), runner)
}
