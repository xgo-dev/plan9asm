package plan9asm

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

type x86CallerRuntimeForm struct {
	name  string
	bits  int
	move  string
	stack string
}

func x86CallerRuntimeForms() []x86CallerRuntimeForm {
	var forms []x86CallerRuntimeForm
	for _, width := range []struct {
		bits int
		move string
	}{{8, "MOVB"}, {16, "MOVW"}, {32, "MOVL"}, {64, "MOVQ"}} {
		for _, stack := range []string{"Leaf", "Balanced", "SavedPointer"} {
			forms = append(forms, x86CallerRuntimeForm{
				name: fmt.Sprintf("kernel%d%s", width.bits, stack),
				bits: width.bits, move: width.move, stack: stack,
			})
		}
	}
	return forms
}

func x86CallerRuntimeSource() (goSource, assembly string) {
	var declarations, machine strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	for _, form := range x86CallerRuntimeForms() {
		fmt.Fprintf(&declarations, `
//go:noescape
func %[1]s(a, b, res, length unsafe.Pointer)

func Call%[1]s(x, y []uint64) uint%[2]d {
	var res uint%[2]d
	length := len(x)
	%[1]s(
		unsafe.Pointer(unsafe.SliceData(x)),
		unsafe.Pointer(unsafe.SliceData(y)),
		unsafe.Pointer(&res),
		unsafe.Pointer(&length))
	return res
}
`, form.name, form.bits)
		fmt.Fprintf(&machine, "TEXT ·%s(SB),4,$0-32\n", form.name)
		machine.WriteString("MOVQ a+0(FP),DI\nMOVQ b+8(FP),SI\nMOVQ res+16(FP),DX\nMOVQ length+24(FP),CX\n")
		if form.stack != "Leaf" {
			machine.WriteString("BYTE $0x55\nWORD $0x8948\nBYTE $0xe5\nLONG $0xf8e48348\n")
		}
		if form.stack == "SavedPointer" {
			machine.WriteString("PUSHQ DX\nMOVQ DI,DX\nPOPQ DX\n")
		}
		suffix := strings.TrimPrefix(form.move, "MOV")
		fmt.Fprintf(&machine, "%s (DI),AX\n%s 8(SI),BX\nADD%s BX,AX\nMOVQ (CX),BX\nADD%s BX,AX\nADD%s $7,AX\n%s AX,(DX)\n",
			form.move, form.move, suffix, suffix, suffix, form.move)
		if form.stack != "Leaf" {
			machine.WriteString("WORD $0x8948\nBYTE $0xec\nBYTE $0x5d\n")
		}
		machine.WriteString("BYTE $0xc3\n")
	}
	return declarations.String(), machine.String()
}

func x86CallerRuntimePackage(t *testing.T, goSource, assembly string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "value.go", goSource, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	typed, err := (&types.Config{
		Importer: x86CallerTestImporter{}, Sizes: types.SizesFor("gc", "amd64"),
	}).Check("caller", fset, []*ast.File{syntax}, info)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{
		Path: "caller", Types: typed, Syntax: []*ast.File{syntax},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: types.SizesFor("gc", "amd64"),
			SelectedGoFiles: []string{"value.go"}, GoSources: map[string][]byte{"value.go": []byte(goSource)},
			SelectedAssemblyFiles: []string{"value_amd64.s"}, Assembly: map[string]*File{"value_amd64.s": file},
		},
	}
}

func x86CallerActualGoOracle(t *testing.T, goSource, assembly string) {
	t.Helper()
	var tests strings.Builder
	tests.WriteString("package caller\nimport \"testing\"\nfunc TestActualCallers(t *testing.T) {\n")
	for _, form := range x86CallerRuntimeForms() {
		fmt.Fprintf(&tests, `
	for iteration := 0; iteration < 64; iteration++ {
		for _, input := range []uint64{0, 1, 127, 255, 65535, 1<<31, 1<<63, ^uint64(0)} {
			x := []uint64{input, 0x1122334455667788}
			y := []uint64{0x8877665544332211, input ^ 0x9876543210abcdef}
			originalX := [2]uint64{x[0], x[1]}
			originalY := [2]uint64{y[0], y[1]}
			canary := [4]uint64{11, 23, 37, 41}
			want := uint%[1]d(x[0]) + uint%[1]d(y[1]) + uint%[1]d(len(x)) + 7
			got := Call%[2]s(x, y)
			if got != want || x[0] != originalX[0] || x[1] != originalX[1] ||
				y[0] != originalY[0] || y[1] != originalY[1] || canary != [4]uint64{11, 23, 37, 41} {
				t.Fatalf("%[2]s got=%%#x want=%%#x x=%%#v y=%%#v canary=%%#v", got, want, x, y, canary)
			}
		}
	}
`, form.bits, form.name)
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": goSource,
		"value_amd64.s": assembly, "value_test.go": tests.String(),
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
		t.Fatalf("actual Go original caller-region oracle: %v\n%s", err, output)
	}
}

func x86CallerCOracle() string {
	var source strings.Builder
	source.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for _, form := range x86CallerRuntimeForms() {
		fmt.Fprintf(&source, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", form.name, form.name)
	}
	source.WriteString("int main(void) {\n")
	for _, form := range x86CallerRuntimeForms() {
		fmt.Fprintf(&source, `
	for (unsigned iteration = 0; iteration < 64; iteration++) {
		const uint64_t inputs[] = {0, 1, 127, 255, 65535, UINT64_C(1)<<31, UINT64_C(1)<<63, UINT64_MAX};
		for (unsigned index = 0; index < sizeof(inputs)/sizeof(inputs[0]); index++) {
			uint64_t x[] = {inputs[index], UINT64_C(0x1122334455667788)};
			uint64_t y[] = {UINT64_C(0x8877665544332211), inputs[index] ^ UINT64_C(0x9876543210abcdef)};
			uint64_t original_x[2], original_y[2], length = 2;
			unsigned char output[48], before[48];
			memcpy(original_x, x, sizeof(x));
			memcpy(original_y, y, sizeof(y));
			for (unsigned byte = 0; byte < sizeof(output); byte++) {
				output[byte] = byte + iteration;
			}
			memset(output + 16, 0, %[1]d);
			memcpy(before, output, sizeof(output));
			const uint64_t want = (x[0] + y[1] + length + 7) & UINT%[2]d_MAX;
			%[3]s(x, y, output + 16, &length);
			for (unsigned byte = 0; byte < sizeof(output); byte++) {
				unsigned char expected = before[byte];
				if (byte >= 16 && byte < 16 + %[1]d) {
					expected = want >> (8*(byte-16));
				}
				if (output[byte] != expected) {
					return 1;
				}
			}
			if (memcmp(x, original_x, sizeof(x)) || memcmp(y, original_y, sizeof(y)) || length != 2) {
				return 2;
			}
		}
	}
`, form.bits/8, form.bits, form.name)
	}
	source.WriteString("\treturn 0;\n}\n")
	return source.String()
}

func TestCrossLinuxRuntimeMatrixX86GoCallerRegions(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("caller-region execution requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	goSource, assembly := x86CallerRuntimeSource()
	x86CallerActualGoOracle(t, goSource, assembly)
	pkg := x86CallerRuntimePackage(t, goSource, assembly)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "caller_regions", triple,
		translation.Module.String(), x86CallerCOracle(), runner)
}
