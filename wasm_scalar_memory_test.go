package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type wasmScalarMemoryCase struct {
	name  string
	typ   LLVMType
	width int
	store bool
}

func wasmScalarMemoryCases(t *testing.T) []wasmScalarMemoryCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"(([IF])(32|64)(Load|Store)(8|16|32)?[SU]?)"`)
	types := map[string]LLVMType{"I32": I32, "I64": I64, "F32": "float", "F64": "double"}
	var cases []wasmScalarMemoryCase
	for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
		width := match[5]
		if width == "" {
			width = match[3]
		}
		bits, err := strconv.Atoi(width)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, wasmScalarMemoryCase{match[1], types[match[2]+match[3]], bits / 8, match[4] == "Store"})
	}
	if len(cases) != 23 {
		t.Fatalf("Go scalar memory namespace has %d forms, want 23", len(cases))
	}
	return cases
}

func TestWASMScalarMemoryOperandForms(t *testing.T) {
	const source = `TEXT defaultStore(SB),4,$0-0
	Get R0
	I32Const $0x10203040
	I32Store
	Return
TEXT offsetStore(SB),4,$0-0
	Get R0
	I32Const $0x8090
	I32Store16 3(R15)
	Return
TEXT implicitLoad(SB),4,$0-0
	I64Load16S 3(R0)
	Return
`
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source, goos)
	}
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"defaultStore": {Name: "defaultStore", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: Void},
		"offsetStore":  {Name: "offsetStore", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: Void},
		"implicitLoad": {Name: "implicitLoad", Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: I64},
	}
	got, err := InferWASMAssemblyFuncSig(file.Funcs[2], "implicitLoad")
	if err != nil || len(got.Args) != 1 || got.Args[0] != I64 || got.Ret != I64 {
		t.Fatalf("implicit register load signature = %v -> %s, %v", got.Args, got.Ret, err)
	}
	ir, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect))
	if err != nil {
		t.Fatal(err)
	}
	runLLVMWASMObject(t, ir, "2", `
const bytes = require('fs').readFileSync(process.argv[1]);
const {defaultStore, offsetStore, implicitLoad, memory} = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const view = new DataView(memory.buffer);
defaultStore(0);
if (view.getUint32(0, true) !== 0x10203040) throw Error('default offset failed at valid address zero');
offsetStore(260);
if (view.getUint16(263, true) !== 0x8090) throw Error('store used the spelling register instead of the stack base');
if (implicitLoad(0x100000104n) !== -32624n) throw Error('implicit load used the wrong register or failed to wrap the base');
`)
}

func TestWASMScalarMemoryRejectsInvalidFormats(t *testing.T) {
	for _, body := range []string{
		"I32Const $0\nI64Load $-1",
		"I32Const $0\nF32Load $4294967296",
		"I32Const $0\nI32Load $1.5",
		"I32Load 0(F0)",
		"I64Const $0\nI32Load $0",
		"I32Const $0\nI64Const $1\nI32Store8 $0",
		"RET\nF64Load.invalid $0",
		"RET\nI32Store $0, $1",
	} {
		file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil {
			continue
		}
		if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
			t.Errorf("inference accepted %q", body)
		}
		sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
		if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
			t.Errorf("translation accepted %q", body)
		}
	}
}

func TestWASMScalarMemoryTypedFloatFrame(t *testing.T) {
	const source = `TEXT ·copyBits(SB),4,$0-12
	Get SP
	F32Load in+0(FP)
	F32Store ret+8(FP)
	RET
`
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source, goos)
	}
	pkg := mustGoPackage(t, "floatframe", "package floatframe\nfunc copyBits(in float32) float32\n")
	context := llvm.NewContext()
	defer context.Dispose()
	options := GoModuleOptions{
		GOOS: "js", GOARCH: "wasm", TargetTriple: "wasm32-unknown-unknown",
		ResolveSym: testResolveSym("floatframe"),
	}
	result, err := translateGoModuleInContext(context, pkg, []byte(source), options)
	if err != nil {
		t.Fatal(err)
	}
	ir := result.Module.String()
	result.Module.Dispose()
	compileLLVMToObject(t, wasmDataTool(t, "llc"), options.TargetTriple, "frame.ll", "frame.o", ir)
}

func TestWASMScalarMemoryCompleteGoNamespace(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, row := range wasmScalarMemoryCases(t) {
		ret := row.typ
		args := []LLVMType{I32}
		regs := []Reg{"R0"}
		body := "Get R0\n"
		if row.store {
			ret = Void
			reg := map[LLVMType]Reg{I32: "R1", I64: "R1", "float": "F0", "double": "F16"}[row.typ]
			args, regs = append(args, row.typ), append(regs, reg)
			body += "Get " + string(reg) + "\n"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s%s $3\nReturn\n", row.name, body, row.name)
		sigs[row.name] = FuncSig{Name: row.name, Args: args, ArgRegs: regs, Ret: ret}
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
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || got.Ret != want.Ret || fmt.Sprint(got.Args) != fmt.Sprint(want.Args) {
			t.Errorf("%s: inferred %v -> %s, want %v -> %s: %v", fn.Sym, got.Args, got.Ret, want.Args, want.Ret, err)
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "memory.ll", "memory.o", ir)
		})
	}
}

func TestWASMScalarMemoryDroppedLoadStillTraps(t *testing.T) {
	const source = `TEXT discard(SB),4,$0-0
	Get R0
	I32Load8U $3
	Drop
	I64Const $42
	Return
`
	sigs := map[string]FuncSig{"discard": {Name: "discard", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: I64}}
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect))
	if err != nil {
		t.Fatal(err)
	}
	runLLVMWASMObject(t, ir, "2", `
const bytes = require('fs').readFileSync(process.argv[1]);
const {discard, memory} = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
if (discard(0) !== 42n) throw Error('valid discarded load failed');
for (const address of [memory.buffer.byteLength, 0xffffffff]) {
  try {
    discard(address);
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) continue;
    throw error;
  }
  throw Error('discarded load at ' + address + ' failed to trap');
}
`)
}

func runLLVMWASMObject(t *testing.T, ir, level, script string, arguments ...string) {
	t.Helper()
	runLLVMWASMObjectWithNodeFlags(t, ir, level, script, nil, arguments...)
}

func runLLVMWASMObjectWithNodeFlags(t *testing.T, ir, level, script string, nodeFlags []string, arguments ...string) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "input.ll")
	object, binary := filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	if level == "2" {
		optimized := filepath.Join(dir, "optimized.ll")
		wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
		input = optimized
	}
	wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-O"+level, "-filetype=obj", input, "-o", object)
	wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", object, "-o", binary)
	args := append(append([]string(nil), nodeFlags...), "-e", script, binary)
	wasmFloatBinaryCommand(t, wasmPackedNode(t), append(args, arguments...)...)
}
