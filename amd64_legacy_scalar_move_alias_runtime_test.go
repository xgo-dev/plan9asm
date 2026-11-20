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

type x86LegacyScalarAliasForm struct {
	name, move string
	width      int
	register   bool
	self       bool
}

func x86LegacyScalarAliasForms() []x86LegacyScalarAliasForm {
	return []x86LegacyScalarAliasForm{
		{name: "loadSS", move: "MOVSS", width: 4},
		{name: "copySS", move: "MOVSS", width: 4, register: true},
		{name: "selfSS", move: "MOVSS", width: 4, register: true, self: true},
		{name: "loadSD", move: "MOVSD", width: 8},
		{name: "copySD", move: "MOVSD", width: 8, register: true},
		{name: "selfSD", move: "MOVSD", width: 8, register: true, self: true},
	}
}

func x86LegacyScalarAliasAssembly(wide int, goarch string) string {
	var source strings.Builder
	word, pointerMove := 8, "MOVQ"
	if goarch == "386" {
		word, pointerMove = 4, "MOVL"
	}
	register := "Y0"
	if wide == 64 {
		register = "Z0"
	}
	for _, form := range x86LegacyScalarAliasForms() {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),AX\n%s output+%d(FP),BX\nVMOVUPS (AX),%s\n",
			form.name, word*2, pointerMove, pointerMove, word, register)
		switch {
		case form.self:
			fmt.Fprintf(&source, "%s X0,X0\n", form.move)
		case form.register:
			fmt.Fprintf(&source, "%s 64(AX),X1\n%s X1,X0\n", form.move, form.move)
		default:
			fmt.Fprintf(&source, "%s 64(AX),X0\n", form.move)
		}
		// A store must not alter the register or any overlapping view.
		fmt.Fprintf(&source, "%s X0,128(BX)\nMOVUPS X0,(BX)\nVMOVUPS Y0,16(BX)\n", form.move)
		if wide == 64 {
			source.WriteString("VMOVUPS Z0,48(BX)\n")
		}
		source.WriteString("RET\n")
	}
	return source.String()
}

func x86LegacyScalarAliasIR(t *testing.T, wide int, goarch, triple string) string {
	t.Helper()
	assembly := x86LegacyScalarAliasAssembly(wide, goarch)
	requireX86GoAssemblerResult(t, goarch, assembly, true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	word := int64(8)
	if goarch == "386" {
		word = 4
	}
	for _, form := range x86LegacyScalarAliasForms() {
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

func TestX86LegacyScalarMoveAliasFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, wide := range []int{32, 64} {
		for _, target := range []struct{ goarch, triple string }{
			{"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-apple-darwin"},
			{"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"},
			{"386", "i386-pc-windows-msvc"},
		} {
			t.Run(fmt.Sprintf("%d/%s", wide, target.triple), func(t *testing.T) {
				ir := x86LegacyScalarAliasIR(t, wide, target.goarch, target.triple)
				compileLLVMToObject(t, llc, target.triple, "legacy-alias.ll", "legacy-alias.o", ir)
			})
		}
	}
}

func x86LegacyScalarAliasActualGoOracle(t *testing.T, wide int) {
	t.Helper()
	var declarations, tests strings.Builder
	declarations.WriteString("package scalar\nimport \"unsafe\"\n")
	tests.WriteString("package scalar\nimport (\"testing\"; \"unsafe\")\nfunc TestFullViews(t *testing.T) {\n")
	for _, form := range x86LegacyScalarAliasForms() {
		fmt.Fprintf(&declarations, "func %s(input, output unsafe.Pointer)\n", form.name)
		fmt.Fprintf(&tests, `
	for iteration := 0; iteration < 64; iteration++ {
		var input [80]byte
		var output [160]byte
		for index := range input {
			input[index] = byte(index*17 + iteration)
		}
		for index := range output {
			output[index] = byte(index*7 + iteration)
		}
		beforeInput, want := input, output
		for _, view := range [][2]int{{0,16},{16,32},{48,%[4]d}} {
			if view[0] == 48 && %[4]d != 64 {
				continue
			}
			for lane := 0; lane < view[1]; lane++ {
				value := input[lane]
				if !%[3]t && lane < %[2]d {
					value = input[64+lane]
				} else if !%[3]t && !%[5]t && lane < 16 {
					value = 0
				}
				want[16+view[0]+lane] = value
			}
		}
		for lane := 0; lane < %[2]d; lane++ {
			value := input[64+lane]
			if %[3]t {
				value = input[lane]
			}
			want[144+lane] = value
		}
		%[1]s(unsafe.Pointer(&input[0]), unsafe.Pointer(&output[16]))
		if output != want || input != beforeInput {
			t.Fatalf("%[1]s iteration=%%d got=%%x want=%%x inputChanged=%%t", iteration, output, want, input != beforeInput)
		}
	}
`, form.name, form.width, form.self, wide, form.register)
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module scalar\n\ngo 1.20\n", "scalar.go": declarations.String(),
		"scalar_amd64.s": x86LegacyScalarAliasAssembly(wide, "amd64"), "scalar_test.go": tests.String(),
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
		t.Fatalf("actual Go %d-byte legacy alias oracle: %v\n%s", wide, err, output)
	}
}

func TestCrossLinuxRuntimeMatrixX86LegacyScalarMoveAliasViews(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	// This original Go counterpart requires AVX, not AVX512. ZMM encodings
	// below are independently Go-assembled and portable LLVM/C checked; that
	// does not claim that the host executes those original AVX512 instructions.
	x86LegacyScalarAliasActualGoOracle(t, 32)
	for _, wide := range []int{32, 64} {
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
		for _, form := range x86LegacyScalarAliasForms() {
			fmt.Fprintf(&source, "extern void %s(void*,void*) __asm__(LABEL(\"scalar.%s\"));\n", form.name, form.name)
		}
		source.WriteString("int main(void) {\n")
		for _, form := range x86LegacyScalarAliasForms() {
			register, self := 0, 0
			if form.register {
				register = 1
			}
			if form.self {
				self = 1
			}
			fmt.Fprintf(&source, `
	for (unsigned iteration = 0; iteration < 64; iteration++) {
		uint8_t input[80], output[160], before_input[80], want[160];
		for (unsigned index = 0; index < sizeof(input); index++) {
			input[index] = index*17 + iteration;
		}
		for (unsigned index = 0; index < sizeof(output); index++) {
			output[index] = index*7 + iteration;
		}
		memcpy(before_input, input, sizeof(input));
		memcpy(want, output, sizeof(output));
		const unsigned offsets[] = {0,16,48}, widths[] = {16,32,%[4]d};
		for (unsigned view = 0; view < (%[4]d == 64 ? 3 : 2); view++) {
			for (unsigned lane = 0; lane < widths[view]; lane++) {
				uint8_t value = input[lane];
				if (!%[3]d && lane < %[2]d) {
					value = input[64+lane];
				} else if (!%[3]d && !%[5]d && lane < 16) {
					value = 0;
				}
				want[16+offsets[view]+lane] = value;
			}
		}
		for (unsigned lane = 0; lane < %[2]d; lane++) {
			want[144+lane] = input[(%[3]d ? 0 : 64)+lane];
		}
		%[1]s(input, output + 16);
		for (unsigned index = 0; index < sizeof(output); index++) {
			if (output[index] != want[index]) {
				fprintf(stderr, "%[1]s wide=%[4]d iteration=%%u byte=%%u got=%%02x want=%%02x\n", iteration, index, output[index], want[index]);
				return 1;
			}
		}
		if (memcmp(input, before_input, sizeof(input))) {
			return 2;
		}
	}
`, form.name, form.width, self, wide, register)
		}
		source.WriteString("\treturn 0;\n}\n")
		triple := testTargetTriple(runtime.GOOS, "amd64")
		var runner []string
		if crossRosetta {
			runner = []string{"/usr/bin/arch", "-x86_64"}
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, fmt.Sprintf("legacy_alias_%d", wide), triple,
			x86LegacyScalarAliasIR(t, wide, "amd64", triple), source.String(), runner)
	}
}
