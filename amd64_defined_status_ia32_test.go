//go:build unix

package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// IA32 has no Q-width POPCNT. This retains all seven physical baseline kernels
// without granting an IA32 encoding or runtime role to VEX/mask instructions.
func x86DefinedStatusIA32Kernels() []x86DefinedStatusKernel {
	var result []x86DefinedStatusKernel
	for _, kernel := range x86DefinedStatusKernels()[:8] {
		if kernel.kind == 0 && kernel.bits == 64 {
			continue
		}
		result = append(result, kernel)
	}
	return result
}

func x86DefinedStatusIA32Fixture(arch string) (declarations, source string) {
	word, pointerBytes := "L", 4
	if arch == "amd64" {
		word, pointerBytes = "Q", 8
	}
	var decl, assembly strings.Builder
	for _, kernel := range x86DefinedStatusIA32Kernels() {
		fmt.Fprintf(&decl, "func %s(out *[8]uint32, left, right, seed uint32)\n", kernel.name)
		fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-%d
MOV%s out+0(FP),DI
MOVL left+%d(FP),AX
MOVL right+%d(FP),BX
MOVL seed+%d(FP),SI
MOVL BX,DX
MOVL AX,X0
MOVL BX,X1
PUSH%s SI
POPF%s
%s
PUSHF%s
POP%s SI
MOVL SI,0(DI)
LAHF
MOVB AH,4(DI)
RET
`, kernel.name, pointerBytes+12, word, pointerBytes, pointerBytes+4,
			pointerBytes+8, word, word, kernel.instruction, word, word)
	}
	return decl.String(), assembly.String()
}

// Reuse the independent mathematical model and all 8x8x2 input axes. Only the
// transport width changes. Signed length is widened before abs so MinInt32 is
// not negated in a 32-bit int; Go's vector-fill shifts otherwise remain defined.
func x86DefinedStatusIA32GoDriver(t *testing.T) string {
	t.Helper()
	var names, kinds, widths strings.Builder
	for _, kernel := range x86DefinedStatusIA32Kernels() {
		fmt.Fprintf(&names, "%s,\n", kernel.name)
		fmt.Fprintf(&kinds, "%d,", kernel.kind)
		fmt.Fprintf(&widths, "%d,", kernel.bits)
	}
	source := strings.NewReplacer(
		"KERNEL_NAMES", names.String(), "KERNEL_KINDS", kinds.String(),
		"KERNEL_WIDTHS", widths.String(), "ACTUAL_OBSERVATIONS", "false",
		"uint64", "uint32", "0xa7a7a7a7a7a7a7a7", "0xa7a7a7a7",
		"if bits == 64", "if bits == 32",
		"int(int32(left)), int(int32(right))", "int64(int32(left)), int64(int32(right))",
		"la, lb := 16, 16", "la, lb := int64(16), int64(16)",
		"if i >= la && i >= lb || i < la && i < lb", "if int64(i) >= la && int64(i) >= lb || int64(i) < la && int64(i) < lb",
	).Replace(x86DefinedStatusGoDriver)
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return string(formatted)
}

func x86DefinedStatusIA32CDriver() string {
	var prototypes, kernels strings.Builder
	for _, kernel := range x86DefinedStatusIA32Kernels() {
		fmt.Fprintf(&prototypes, "extern void %s(uint32_t *, uint32_t, uint32_t, uint32_t);\n", kernel.name)
		fmt.Fprintf(&kernels, "{%s,%d,%d,\"%s\"},\n", kernel.name, kernel.kind, kernel.bits, kernel.instruction)
	}
	source := strings.NewReplacer(
		"KERNEL_PROTOTYPES", prototypes.String(), "KERNELS", kernels.String(),
		"uint64_t", "uint32_t", "UINT64_MAX", "UINT32_MAX", "UINT64_C", "UINT32_C",
		"0xa7a7a7a7a7a7a7a7", "0xa7a7a7a7",
		"bits == 64 ?", "bits == 32 ?",
		"a[i] = right>>(8*i);", "a[i] = ((uint64_t)right)>>(8*i);",
		"b[i] = left>>(8*i);", "b[i] = ((uint64_t)left)>>(8*i);",
	).Replace(x86DefinedStatusCDriver)
	return source
}

func x86DefinedStatusIA32BuildOriginal(t *testing.T) x87IA32Executable {
	t.Helper()
	dir := t.TempDir()
	declarations, assembly := x86DefinedStatusIA32Fixture("386")
	inputs := map[string]string{
		"go.mod":       "module definedstatus386\n\ngo 1.20\n",
		"main.go":      x86DefinedStatusIA32GoDriver(t),
		"decl.go":      "package main\n" + declarations,
		"status_386.s": assembly,
	}
	for name, contents := range inputs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("original IA32 input=%s bytes=%d sha256=%x", name, len(contents), sha256.Sum256([]byte(contents)))
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	env := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOROOT="+runtime.GOROOT(), "GOFLAGS=", "GOEXPERIMENT=", "GOOS=linux",
		"GOARCH=386", "CGO_ENABLED=0", "GOMAXPROCS=2")
	version, err := x87IA32Capture(t, goBinary, []string{"version"}, dir, env)
	if err != nil || !strings.HasPrefix(string(version), "go version "+runtime.Version()+" ") {
		t.Fatalf("original IA32 SDK identity mismatch: %v\n%s", err, version)
	}
	executable := filepath.Join(dir, "original-go")
	output, err := x87IA32Capture(t, goBinary,
		[]string{"build", "-p=2", "-o", executable, "."}, dir, env)
	if err != nil || len(output) != 0 {
		t.Fatalf("original IA32 Go build failed: %v\n%s", err, output)
	}
	sealed, err := x87IA32StaticExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("original Go %s static IA32 ELF bytes=%d sha256=%x; compile-only receipt",
		runtime.Version(), sealed.size, sealed.hash)
	return sealed
}

func TestX86DefinedStatusIA32OriginalGoStaticELFActualCompile(t *testing.T) {
	executable := x86DefinedStatusIA32BuildOriginal(t)
	if err := executable.verify(); err != nil {
		t.Fatal(err)
	}
	t.Log("seven kernels and 896 mathematical observations built; native execution is a separate required root")
}

func TestX86DefinedStatusIA32RequiredNativeCounterpartSource(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_defined_status_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var counterpart *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "TestCrossLinuxRuntimeMatrixX86DefinedStatusNative386" {
			counterpart = function
		}
	}
	if counterpart == nil {
		t.Fatal("required original-Go/LLVM O0/O2 native IA32 defined-status counterpart is missing")
	}
	want := map[string]bool{
		"x87IA32RequireNativeHost":          false,
		"x86DefinedStatusIA32BuildOriginal": false,
		"x87IA32RunDirect":                  false,
		"x86DefinedStatusIA32CompileAndRun": false,
	}
	levels := map[string]bool{"-O0": false, "-O2": false}
	ast.Inspect(counterpart.Body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if _, required := levels[value]; required {
				levels[value] = true
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok {
			if _, required := want[function.Name]; required {
				want[function.Name] = true
			}
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(selector.Sel.Name, "Skip") {
			t.Error("required native IA32 counterpart cannot skip failed tools or execution")
		}
		return true
	})
	for function, found := range want {
		if !found {
			t.Errorf("required native IA32 counterpart lacks %s", function)
		}
	}
	for level, found := range levels {
		if !found {
			t.Errorf("required native IA32 counterpart lacks %s", level)
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if ok && literal.Kind == token.STRING {
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if value == "qemu-i386" || value == "-exec" {
				t.Error("required native IA32 counterpart cannot substitute a guest executor")
			}
		}
		return true
	})
}

func x86DefinedStatusIA32Capabilities(cpuinfo string) error {
	flags := make(map[string]bool)
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "flags" {
			for _, flag := range strings.Fields(value) {
				flags[flag] = true
			}
		}
	}
	for _, required := range []string{"sse4_1", "sse4_2", "popcnt"} {
		if !flags[required] {
			return fmt.Errorf("required native IA32 capability missing: %s", required)
		}
	}
	return nil
}

func x86DefinedStatusIA32RequireCapabilities(t *testing.T) {
	t.Helper()
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(contents) > 4<<20 {
		t.Fatal("unbound native IA32 capability observation", err)
	}
	if err := x86DefinedStatusIA32Capabilities(string(contents)); err != nil {
		t.Fatal(err)
	}
}

func TestX86DefinedStatusIA32CapabilitiesAreRequired(t *testing.T) {
	if err := x86DefinedStatusIA32Capabilities("flags: fpu cmov popcnt sse4_1 sse4_2\n"); err != nil {
		t.Fatal(err)
	}
	for _, observation := range []string{
		"flags: fpu cmov sse4_1 sse4_2\n", "flags: fpu cmov popcnt sse4_2\n",
		"flags: fpu cmov popcnt sse4_1\n", "notflags: popcnt sse4_1 sse4_2\n",
		"flags: popcnt_extended sse4_1_extended sse4_2_extended\n", "",
	} {
		if x86DefinedStatusIA32Capabilities(observation) == nil {
			t.Errorf("missing/foreign CPU capability was accepted: %q", observation)
		}
	}
}

func TestX86DefinedStatusIA32ReferenceTransportWidth(t *testing.T) {
	kernels := x86DefinedStatusIA32Kernels()
	if len(kernels) != 7 || kernels[0].bits != 16 || kernels[1].bits != 32 {
		t.Fatal("native IA32 kernel denominator changed", kernels)
	}
	declarations, source := x86DefinedStatusIA32Fixture("386")
	if strings.Count(declarations, "*[8]uint32") != 7 ||
		strings.Count(source, "$0-16") != 7 || strings.Count(source, "MOVB AH,4(DI)") != 7 ||
		strings.Contains(source, "Q ") || strings.Contains(source, "PUSHFQ") {
		t.Fatal("IA32 fixture lost actual four-byte transport or physical instruction width")
	}
	goSource := x86DefinedStatusIA32GoDriver(t)
	if !strings.Contains(goSource, "int64(int32(left))") || !strings.Contains(goSource, "int64(int32(right))") {
		t.Fatal("minimum signed IA32 length must be widened before negation")
	}
	cSource := x86DefinedStatusIA32CDriver()
	if strings.Contains(cSource, "= right>>(8*i)") || strings.Contains(cSource, "= left>>(8*i)") ||
		!strings.Contains(cSource, "((uint64_t)right)>>(8*i)") || !strings.Contains(cSource, "((uint64_t)left)>>(8*i)") {
		t.Fatal("independent C vector filling must not shift a uint32 by 32 or more")
	}
	if !strings.Contains(cSource, "bits == 32 ? UINT32_MAX") || !strings.Contains(goSource, "if bits == 32") {
		t.Fatal("full IA32 mask must not shift a uint32 by its width")
	}
}

func TestX86DefinedStatusIA32IndependentCActualCompile(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("required LLVM 22 clang missing")
	}
	dir := t.TempDir()
	input, object := filepath.Join(dir, "model.c"), filepath.Join(dir, "model.o")
	// Freestanding syntax/object checking needs no host libc headers or fake
	// sysroot. The required native counterpart uses the unchanged stdio driver.
	source := strings.Replace(x86DefinedStatusIA32CDriver(), "#include <stdio.h>",
		"extern int printf(const char *, ...);", 1)
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output, err := x87IA32Capture(t, clang, []string{"-target", "i386-unknown-linux-gnu",
				"-ffreestanding", "-Wall", "-Wextra", "-Werror", level, "-c", input, "-o", object}, dir, os.Environ())
			if err != nil || len(output) != 0 {
				t.Fatalf("independent IA32 C model object failed: %v\n%s", err, output)
			}
			parsed, err := elf.Open(object)
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Close()
			if parsed.Class != elf.ELFCLASS32 || parsed.Machine != elf.EM_386 || parsed.Type != elf.ET_REL {
				t.Fatal("independent C model did not produce an IA32 object")
			}
			contents, err := os.ReadFile(object)
			if err != nil || len(contents) == 0 {
				t.Fatal("missing IA32 C model object", err)
			}
			t.Logf("independent IA32 C model %s bytes=%d sha256=%x; compile-only, not executed",
				level, len(contents), sha256.Sum256(contents))
		})
	}
}

// These objects cover every affected LLVM target/API independently of the
// required direct Linux/386 executable. No cross-object is a runtime receipt.
func TestX86DefinedStatusIA32ThreeAPIsFiveTargetsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("required LLVM 22 llc missing")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		declarations, source := x86DefinedStatusIA32Fixture(target.arch)
		goAssemblerOracleOutput(t, target.arch, source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir := x86CPUQueryIRFromDeclaration(t, source, declarations, target.arch, target.triple, api)
				for _, optimized := range []bool{false, true} {
					t.Run(fmt.Sprint("O2=", optimized), func(t *testing.T) {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						compileLLVMToObject(t, llc, target.triple, "status.ll", "status.o", input)
					})
				}
			})
		}
	}
}

func x86DefinedStatusIA32CompileAndRun(t *testing.T, llc, ir, level string) {
	t.Helper()
	dir := t.TempDir()
	llPath, object := filepath.Join(dir, "status.ll"), filepath.Join(dir, "status.o")
	mainPath, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "translated")
	for name, contents := range map[string]string{llPath: ir, mainPath: x86DefinedStatusIA32CDriver()} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output, err := x87IA32Capture(t, llc,
		[]string{level, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", llPath, "-o", object}, dir, os.Environ())
	if err != nil || len(output) != 0 {
		t.Fatalf("LLVM22 IA32 %s object failed: %v\n%s", level, err, output)
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal(err)
	}
	output, err = x87IA32Capture(t, compiler,
		[]string{"-static", "-no-pie", level, "-Wall", "-Wextra", "-Werror=shift-count-overflow",
			object, mainPath, "-o", executable}, dir, os.Environ())
	if err != nil || len(output) != 0 {
		t.Fatalf("static IA32 %s independent C link failed: %v\n%s", level, err, output)
	}
	sealed, err := x87IA32StaticExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, sealed, nil, os.Environ()); string(output) != "LLVM defined-status observations 896 failures 0\n" {
		t.Fatalf("LLVM IA32 %s six-flag/LAHF/full canary oracle: %q", level, output)
	}
}
