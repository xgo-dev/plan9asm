package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var wasmConversionWidth = regexp.MustCompile(`[IF](?:32|64)`)

func wasmConversionGoNames(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	names := regexp.MustCompile(`"(I(?:32|64)(?:Wrap|Extend|Trunc(?:Sat)?|Reinterpret)[A-Za-z0-9]+|F(?:32|64)(?:Convert|Demote|Promote|Reinterpret)[A-Za-z0-9]+)"`).FindAllStringSubmatch(string(data), -1)
	if len(names) != 38 {
		t.Fatalf("Go scalar conversion namespace has %d forms, want 38", len(names))
	}
	result := make([]string, 0, len(names))
	for _, match := range names {
		result = append(result, match[1])
	}
	return result
}

func TestWASMScalarConversionCompleteGoNamespace(t *testing.T) {
	types := map[string]LLVMType{"I32": I32, "I64": I64, "F32": "float", "F64": "double"}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, name := range wasmConversionGoNames(t) {
		kinds := wasmConversionWidth.FindAllString(name, -1)
		input := kinds[len(kinds)-1]
		reg := map[string]Reg{"I32": "R0", "I64": "R0", "F32": "F0", "F64": "F16"}[input]
		symbol := fmt.Sprintf("conversion%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nGet %s\n%s\nReturn\n", symbol, reg, name)
		sigs[symbol] = FuncSig{Name: symbol, Args: []LLVMType{types[input]}, ArgRegs: []Reg{reg}, Ret: types[kinds[0]]}
	}
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source.String(), goos)
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		want := sigs[fn.Sym]
		// R registers require a use to infer I32 instead of their I64 default.
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || got.Ret != want.Ret || len(got.Args) != 1 || got.Args[0] != want.Args[0] {
			t.Errorf("%s: inferred %v -> %s, want %v -> %s: %v", fn.Sym, got.Args, got.Ret, want.Args, want.Ret, err)
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "conversion.ll", "conversion.o", ir)
		})
	}
}

func TestWASMScalarConversionTypedGoEntry(t *testing.T) {
	var source, declarations strings.Builder
	declarations.WriteString("package wasmconversion\n")
	inputs := map[string]string{
		"I32": "I32Const $1\n",
		"I64": "I64Const $1\n",
		"F32": "I32Const $0\nF32ReinterpretI32\n",
		"F64": "F64Const $0\n",
	}
	for index, name := range wasmConversionGoNames(t) {
		kinds := wasmConversionWidth.FindAllString(name, -1)
		fmt.Fprintf(&declarations, "func convert%d()\n", index)
		fmt.Fprintf(&source, "TEXT ·convert%d(SB),4,$0-0\n%s%s\nDrop\nRET\n", index, inputs[kinds[len(kinds)-1]], name)
	}
	pkg := mustGoPackage(t, "wasmconversion", declarations.String())
	context := llvm.NewContext()
	defer context.Dispose()
	options := GoModuleOptions{GOOS: "js", GOARCH: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: testResolveSym("wasmconversion")}
	translated, err := translateGoModuleInContext(context, pkg, []byte(source.String()), options)
	if err != nil {
		t.Fatal(err)
	}
	ir := translated.Module.String()
	translated.Module.Dispose()
	compileLLVMToObject(t, wasmDataTool(t, "llc"), options.TargetTriple, "converted.ll", "converted.o", ir)
}

func TestWASMScalarConversionRejectsInvalidStackAndFormat(t *testing.T) {
	sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
	for _, name := range wasmConversionGoNames(t) {
		kinds := wasmConversionWidth.FindAllString(name, -1)
		other := "I32Const $1\n"
		if kinds[len(kinds)-1] == "I32" {
			other = "I64Const $1\n"
		}
		for _, body := range []string{name, other + name, "RET\n" + name + " $1", "RET\n" + name + ".invalid"} {
			file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+body+"\nRET\n")
			if err != nil {
				continue
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
				t.Errorf("inference accepted %q", body)
			}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Errorf("translation accepted %q", body)
			}
		}
	}
}

func TestWASMScalarConversionDroppedResultTraps(t *testing.T) {
	const source = `TEXT convert(SB),4,$0-0
	Get F16
	I64TruncF64S
	Drop
	I64Const $42
	Return
`
	sigs := map[string]FuncSig{"convert": {Name: "convert", Args: []LLVMType{"double"}, ArgRegs: []Reg{"F16"}, Ret: I64}}
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, optimized := filepath.Join(dir, "input.ll"), filepath.Join(dir, "optimized.ll")
	object, binary := filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
	wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-O2", "-filetype=obj", optimized, "-o", object)
	wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export=convert", object, "-o", binary)
	wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", `
const bytes = require('fs').readFileSync(process.argv[1]);
const {convert} = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
if (convert(-0.75) !== 42n) throw Error('valid input did not convert');
for (const input of [NaN, Infinity, -(2 ** 64), 2 ** 63]) {
  try {
    convert(input);
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) continue;
    throw error;
  }
  throw Error('invalid conversion failed to trap: ' + input);
}
`, binary)
}
