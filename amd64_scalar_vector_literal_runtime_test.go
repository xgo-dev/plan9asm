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

type x86ScalarLiteralForm struct {
	name, op string
	value    x86ScalarLiteralValue
	width    int
	register int
	masked   bool
	active   bool
	zeroing  bool
}

func x86ScalarLiteralForms(extended bool) []x86ScalarLiteralForm {
	var forms []x86ScalarLiteralForm
	for _, op := range []string{"MOVSS", "MOVSD", "VMOVSS", "VMOVSD"} {
		width := 4
		if strings.HasSuffix(op, "SD") {
			width = 8
		}
		for _, value := range x86ScalarLiteralValues {
			forms = append(forms, x86ScalarLiteralForm{name: op + value.name, op: op, value: value, width: width})
		}
		if extended && strings.HasPrefix(op, "V") {
			for _, value := range x86ScalarLiteralValues[:3] {
				for _, mask := range []struct {
					name                 string
					masked, active, zero bool
				}{
					{name: "plain"},
					{name: "mergeOff", masked: true},
					{name: "mergeOn", masked: true, active: true},
					{name: "zeroOff", masked: true, zero: true},
				} {
					forms = append(forms, x86ScalarLiteralForm{
						name: op + value.name + mask.name, op: op, value: value, width: width,
						register: 31, masked: mask.masked, active: mask.active, zeroing: mask.zero,
					})
				}
			}
		}
	}
	return forms
}

func (form x86ScalarLiteralForm) legacyEncoding() bool {
	return !strings.HasPrefix(form.op, "V") || form.value.zero && form.register < 16
}

func (form x86ScalarLiteralForm) bits() uint64 {
	if form.width == 4 {
		return uint64(form.value.bits32)
	}
	return form.value.bits64
}

func x86ScalarLiteralTargetForms(wide int, arch string) []x86ScalarLiteralForm {
	forms := x86ScalarLiteralForms(wide == 64)
	if arch != "386" {
		return forms
	}
	var physical []x86ScalarLiteralForm
	for _, form := range forms {
		if form.register >= 8 {
			// These are low physical-bank object controls, not a binding for
			// Go-accepted high-bank encodings. Keep the original high forms in
			// the separate actual-source/Context regression.
			form.register = 7
			if form.value.zero && form.masked {
				// The frontend rewrites positive zero in X0-X15 to XORPS,
				// whose retained mask makes this original source Go-invalid.
				continue
			}
		}
		physical = append(physical, form)
	}
	return physical
}

func x86ScalarLiteralAssembly(wide int, arch string) string {
	return x86ScalarLiteralAssemblyForForms(wide, arch, x86ScalarLiteralTargetForms(wide, arch))
}

func x86ScalarLiteralAssemblyForForms(wide int, arch string, forms []x86ScalarLiteralForm) string {
	var source strings.Builder
	word, pointerMove := 8, "MOVQ"
	if arch == "386" {
		word, pointerMove = 4, "MOVL"
	}
	for _, form := range forms {
		view := fmt.Sprintf("Y%d", form.register)
		// Retain the original high-bank source shape in its negative test;
		// ordinary object controls use physical low banks on mode32.
		zView := wide == 64 && (arch != "386" || form.register < 16)
		if zView {
			view = fmt.Sprintf("Z%d", form.register)
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),AX\n%s output+%d(FP),BX\nVMOVUPS (AX),%s\n",
			form.name, word*2, pointerMove, pointerMove, word, view)
		suffix, mask := "", ""
		if form.masked {
			active := 0
			if form.active {
				active = 1
			}
			fmt.Fprintf(&source, "MOVL $%d,CX\nKMOVW CX,K1\n", active)
			mask = "K1,"
		}
		if form.zeroing {
			suffix = ".Z"
		}
		xStore := "MOVUPS"
		if form.register >= 16 {
			xStore = "VMOVUPS"
		}
		fmt.Fprintf(&source, "%s%s $%s,%sX%d\n%s X%d,(BX)\nVMOVUPS Y%d,16(BX)\n",
			form.op, suffix, form.value.text, mask, form.register, xStore, form.register, form.register)
		if zView {
			fmt.Fprintf(&source, "VMOVUPS Z%d,48(BX)\n", form.register)
		}
		source.WriteString("RET\n")
	}
	return source.String()
}

func x86ScalarLiteralIR(t *testing.T, wide int, arch, triple string) string {
	t.Helper()
	assembly := x86ScalarLiteralAssembly(wide, arch)
	requireX86GoAssemblerResult(t, arch, assembly, true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	word := int64(8)
	if arch == "386" {
		word = 4
	}
	sigs := make(map[string]FuncSig)
	for _, form := range x86ScalarLiteralTargetForms(wide, arch) {
		symbol := "literal." + form.name
		sigs[symbol] = FuncSig{
			Name: symbol, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: word, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	ir, err := Translate(file, Options{
		Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestX86ScalarLiteralFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, wide := range []int{32, 64} {
		for _, target := range []struct{ arch, triple string }{
			{arch: "amd64", triple: "x86_64-unknown-linux-gnu"},
			{arch: "amd64", triple: "x86_64-apple-darwin"},
			{arch: "amd64", triple: "x86_64-pc-windows-msvc"},
			{arch: "386", triple: "i386-unknown-linux-gnu"},
			{arch: "386", triple: "i386-pc-windows-msvc"},
		} {
			t.Run(fmt.Sprintf("%d/%s", wide, target.triple), func(t *testing.T) {
				ir := x86ScalarLiteralIR(t, wide, target.arch, target.triple)
				compileLLVMToObject(t, llc, target.triple, "scalar-literals.ll", "scalar-literals.o", ir)
			})
		}
	}
}

func x86ScalarLiteralActualGoOracle(t *testing.T) {
	t.Helper()
	var declarations, tests strings.Builder
	declarations.WriteString("package literal\nimport \"unsafe\"\n")
	tests.WriteString("package literal\nimport (\"testing\"; \"unsafe\")\nfunc TestLiteralBytes(t *testing.T) {\n")
	for _, form := range x86ScalarLiteralForms(false) {
		fmt.Fprintf(&declarations, "func %s(input, output unsafe.Pointer)\n", form.name)
		fmt.Fprintf(&tests, `
	for iteration := 0; iteration < 32; iteration++ {
		var input [80]byte
		var output [160]byte
		for index := range input {
			input[index] = byte(index*17 + iteration)
		}
		for index := range output {
			output[index] = byte(index*7 + iteration)
		}
		beforeInput, want := input, output
		const bits uint64 = %[2]d
		for _, view := range [][2]int{{0,16},{16,32}} {
			for lane := 0; lane < view[1]; lane++ {
				value := byte(0)
				if lane < %[3]d {
					value = byte(bits >> (8*lane))
				} else if %[4]t && lane >= 16 {
					value = input[lane]
				}
				want[16+view[0]+lane] = value
			}
		}
		%[1]s(unsafe.Pointer(&input[0]), unsafe.Pointer(&output[16]))
		if output != want || input != beforeInput {
			t.Fatalf("%[1]s iteration=%%d got=%%x want=%%x inputChanged=%%t", iteration, output, want, input != beforeInput)
		}
	}
`, form.name, form.bits(), form.width, form.legacyEncoding())
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module literal\n\ngo 1.20\n", "literal.go": declarations.String(),
		"literal_amd64.s": x86ScalarLiteralAssembly(32, "amd64"), "literal_test.go": tests.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go floating-literal full-byte oracle: %v\n%s", err, output)
	}
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatingLiteralBytes(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	// This original Go oracle executes low-register AVX forms. Extended and
	// masked AVX512 forms below have Go objects and a portable LLVM/C oracle;
	// those are not a claim that this host executes original AVX512 bytes.
	if goToolchainAtLeast(runtime.Version(), 1, 27) {
		x86ScalarLiteralActualGoOracle(t)
	}
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
		for _, form := range x86ScalarLiteralForms(wide == 64) {
			fmt.Fprintf(&source, "extern void %s(void*,void*) __asm__(LABEL(\"literal.%s\"));\n", form.name, form.name)
		}
		source.WriteString("int main(void) {\n")
		for _, form := range x86ScalarLiteralForms(wide == 64) {
			mergeOff, legacy := 0, 0
			if form.masked && !form.active && !form.zeroing {
				mergeOff = 1
			}
			if form.legacyEncoding() {
				legacy = 1
			}
			bits := form.bits()
			if form.masked && !form.active && form.zeroing {
				bits = 0
			}
			fmt.Fprintf(&source, `
	for (unsigned iteration = 0; iteration < 32; iteration++) {
		uint8_t input[80], output[160], before_input[80], want[160];
		for (unsigned index = 0; index < sizeof(input); index++) {
			input[index] = index*17 + iteration;
		}
		for (unsigned index = 0; index < sizeof(output); index++) {
			output[index] = index*7 + iteration;
		}
		memcpy(before_input, input, sizeof(input));
		memcpy(want, output, sizeof(output));
		const uint64_t bits = UINT64_C(%[2]d);
		const unsigned offsets[] = {0,16,48}, widths[] = {16,32,%[6]d};
		for (unsigned view = 0; view < (%[6]d == 64 ? 3 : 2); view++) {
			for (unsigned lane = 0; lane < widths[view]; lane++) {
				uint8_t value = 0;
				if (lane < %[3]d) {
					value = %[5]d ? input[lane] : bits >> (8*lane);
				} else if (%[4]d && lane >= 16) {
					value = input[lane];
				}
				want[16+offsets[view]+lane] = value;
			}
		}
		%[1]s(input, output + 16);
		for (unsigned index = 0; index < sizeof(output); index++) {
			if (output[index] != want[index]) {
				fprintf(stderr, "%[1]s wide=%[6]d iteration=%%u byte=%%u got=%%02x want=%%02x\n", iteration, index, output[index], want[index]);
				return 1;
			}
		}
		if (memcmp(input, before_input, sizeof(input))) {
			return 2;
		}
	}
`, form.name, bits, form.width, legacy, mergeOff, wide)
		}
		source.WriteString("\treturn 0;\n}\n")
		triple := testTargetTriple(runtime.GOOS, "amd64")
		var runner []string
		if crossRosetta {
			runner = []string{"/usr/bin/arch", "-x86_64"}
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, fmt.Sprintf("scalar_literals_%d", wide), triple,
			x86ScalarLiteralIR(t, wide, "amd64", triple), source.String(), runner)
	}
}

func TestCrossLinuxRuntimeMatrixX86ScalarLiteralFloat32Rounding(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	assembly := "TEXT rounding(SB),4,$0-8\nMOVQ output+0(FP),AX\nMOVSS $1.25,X0\nMOVSS X0,(AX)\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
		"rounding": {
			Name: "rounding", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	source := `#include <stdint.h>
#include <stdio.h>
#if defined(__APPLE__)
extern void rounding(void*) __asm__("_rounding");
#else
extern void rounding(void*);
#endif
int main(void) {
	uint32_t output = 0xdeadbeef;
	rounding(&output);
	if (output != UINT32_C(0x3fa00000)) {
		fprintf(stderr, "MOVSS $1.25 got=%08x want=3fa00000\n", output);
		return 1;
	}
	return 0;
}
`
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_literal_rounding", triple, ir, source, runner)
}
