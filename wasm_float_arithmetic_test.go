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

// The selected Go anames/a.out namespace and wasmobj writer define these eight
// scalar, zero-operand stack operators independently of translator registries.
func wasmFloatArithmeticGoNames(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "wasm", "anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, match := range regexp.MustCompile(`"(F(?:32|64)(?:Add|Sub|Mul|Div))"`).FindAllSubmatch(data, -1) {
		names = append(names, string(match[1]))
	}
	want := strings.Fields("F32Add F32Sub F32Mul F32Div F64Add F64Sub F64Mul F64Div")
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatal("complete selected-Go arithmetic namespace changed", names)
	}
	return names
}

func wasmFloatArithmeticTypes(name string) (LLVMType, LLVMType, Reg, Reg) {
	typ, _, first, second := wasmFloatBinaryTestTypes(name)
	return typ, typ, first, second
}

func TestWASMFloatArithmeticCompleteGoNamespaceAndObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, name := range wasmFloatArithmeticGoNames(t) {
		typ, _, _, _ := wasmFloatArithmeticTypes(name)
		base := 0
		if typ == "double" {
			base = 16
		}
		for bank := 0; bank < 16; bank++ {
			for _, alias := range []bool{false, true} {
				first := Reg(fmt.Sprintf("F%d", base+bank))
				second := Reg(fmt.Sprintf("F%d", base+15-bank))
				if alias {
					second = first
				}
				function := fmt.Sprintf("arithmetic%d", len(sigs))
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nGet %s\nGet %s\n%s\nReturn\n",
					function, first, second, name)
				args, regs := []LLVMType{typ}, []Reg{first}
				if !alias {
					args, regs = append(args, typ), append(regs, second)
				}
				sigs[function] = FuncSig{Name: function, Args: args, ArgRegs: regs, Ret: typ}
			}
		}
	}
	if len(sigs) != 256 {
		t.Fatal("incomplete eight-opcode, sixteen-register, alias matrix", len(sigs))
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
		if err != nil || got.Ret != want.Ret || len(got.Args) != len(want.Args) {
			t.Errorf("complete arithmetic signature for %s: %+v, %v", fn.Sym, got, err)
			continue
		}
		for index := range want.Args {
			if got.Args[index] != want.Args[index] {
				t.Errorf("%s argument%d type=%s want=%s", fn.Sym, index, got.Args[index], want.Args[index])
			}
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			t.Run(route+"/"+triple, func(t *testing.T) {
				options := wasmPackedOptions(sigs, WASMABIDirect)
				options.TargetTriple = triple
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil || ir == "" {
					t.Fatal("complete original Go arithmetic family is not lowerable", err)
				}
				wasmFloatArithmeticRequireStrictIR(t, ir)
				compileLLVMToObject(t, wasmDataTool(t, "llc"), triple, "arithmetic.ll", "arithmetic.o", ir)
			})
		}
	}
}

func wasmFloatArithmeticRequireStrictIR(t *testing.T, ir string) {
	t.Helper()
	if strings.Contains(ir, "blockaddress") ||
		regexp.MustCompile(`\b(?:fadd|fsub|fmul|fdiv)\s+(?:fast|nnan|ninf|nsz|arcp|contract|afn|reassoc)\b`).MatchString(ir) {
		t.Fatal("Wasm arithmetic acquired invalid control flow or relaxed IEEE semantics")
	}
}

func TestWASMFloatArithmeticRejectsWrongStackAndDeadFormats(t *testing.T) {
	for _, name := range wasmFloatArithmeticGoNames(t) {
		typ, _, first, second := wasmFloatArithmeticTypes(name)
		good := fmt.Sprintf("Get %s\nGet %s\n", first, second)
		wrong := "F16"
		if typ == "double" {
			wrong = "F0"
		}
		bodies := []string{
			name,
			fmt.Sprintf("Get %s\n%s", first, name),
			"I32Const $0\nI32Const $1\n" + name,
			"I64Const $0\nI64Const $1\n" + name,
			fmt.Sprintf("Get %s\nGet %s\n%s", wrong, second, name),
			fmt.Sprintf("Get %s\nGet %s\n%s", first, wrong, name),
			"Get SP\nGet SP\n" + name,
		}
		for _, operand := range []string{" $0", " $1.25", " F0", " F0,F1", " 0(SP)", " symbol(SB)", ".invalid"} {
			bodies = append(bodies, good+name+operand, "RET\n"+name+operand)
		}
		for index, body := range bodies {
			t.Run(fmt.Sprintf("%s/%d", name, index), func(t *testing.T) {
				file, err := Parse(ArchWASM, "TEXT operation(SB),4,$0-0\n"+body+"\nReturn\n")
				if err != nil {
					return // The source parser may reject invalid syntax first.
				}
				if got, err := InferWASMAssemblyFuncSig(file.Funcs[0], "operation"); err == nil {
					t.Errorf("inference accepted an invalid arithmetic stack/format: %+v", got)
				}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					options := wasmPackedOptions(map[string]FuncSig{"operation": {Name: "operation", Ret: typ}}, WASMABIDirect)
					if ir, err := wasmPackedTranslate(t, file, options, route); err == nil || ir != "" {
						t.Errorf("%s accepted wrong arithmetic stack/format:\n%s", route, body)
					}
				}
			})
		}
	}
}

func TestWASMFloatArithmeticTypedGoEntryAndDeadFormats(t *testing.T) {
	var source, declarations strings.Builder
	declarations.WriteString("package arithmetic\n")
	for index, name := range wasmFloatArithmeticGoNames(t) {
		_, _, first, second := wasmFloatArithmeticTypes(name)
		fmt.Fprintf(&declarations, "func operation%d()\n", index)
		fmt.Fprintf(&source, "TEXT ·operation%d(SB),4,$0-0\nGet %s\nGet %s\n%s\nDrop\nRET\n",
			index, first, second, name)
	}
	pkg := mustGoPackage(t, "arithmetic", declarations.String())
	context := llvm.NewContext()
	defer context.Dispose()
	options := GoModuleOptions{GOOS: "js", GOARCH: "wasm", TargetTriple: "wasm32-unknown-unknown",
		ResolveSym: testResolveSym("arithmetic")}
	translated, err := translateGoModuleInContext(context, pkg, []byte(source.String()), options)
	if translated != nil {
		defer translated.Module.Dispose()
	}
	if err != nil || translated == nil {
		t.Fatal("typed Go arithmetic source is not lowerable", err)
	}
	ir := translated.Module.String()
	wasmFloatArithmeticRequireStrictIR(t, ir)
	compileLLVMToObject(t, wasmDataTool(t, "llc"), options.TargetTriple, "typed-arithmetic.ll", "typed-arithmetic.o", ir)
	for _, name := range wasmFloatArithmeticGoNames(t) {
		malformed := fmt.Sprintf("TEXT ·operation0(SB),4,$0-0\nRET\n%s $1\nRET\n", name)
		bad, err := translateGoModuleInContext(context, pkg, []byte(malformed), options)
		if bad != nil {
			bad.Module.Dispose()
		}
		if err == nil || bad != nil {
			t.Fatalf("typed Go accepted malformed dead %s: %v", name, err)
		}
	}
}
