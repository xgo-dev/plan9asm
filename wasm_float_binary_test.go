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

// Discover the whole namespace from the selected Go compiler, independently
// of the implementation's map and the official corpus's observed mnemonics.
func wasmFloatBinaryGoNames(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "wasm", "anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, match := range regexp.MustCompile(`"(F(?:32|64)(?:Eq|Ne|Lt|Gt|Le|Ge|Min|Max))"`).FindAllSubmatch(data, -1) {
		names = append(names, string(match[1]))
	}
	if len(names) != 16 {
		t.Fatalf("selected Go float comparison/minmax namespace changed: %v", names)
	}
	return names
}

func wasmFloatBinaryTestTypes(name string) (LLVMType, LLVMType, Reg, Reg) {
	typ, first, second := LLVMType("float"), Reg("F0"), Reg("F1")
	if strings.HasPrefix(name, "F64") {
		typ, first, second = "double", "F16", "F17"
	}
	result := I32
	if strings.HasSuffix(name, "Min") || strings.HasSuffix(name, "Max") {
		result = typ
	}
	return typ, result, first, second
}

func TestWASMFloatBinaryWholeGoNamespace(t *testing.T) {
	for _, name := range wasmFloatBinaryGoNames(t) {
		t.Run(name, func(t *testing.T) {
			typ, result, first, second := wasmFloatBinaryTestTypes(name)
			source := fmt.Sprintf("TEXT operation(SB),4,$0-0\nGet %s\nGet %s\n%s\nReturn\n", first, second, name)
			wasmDataGoObject(t, source, "js")
			file, err := Parse(ArchWASM, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := FuncSig{Name: "operation", Args: []LLVMType{typ, typ}, Ret: result, ArgRegs: []Reg{first, second}}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"operation": sig}, WASMABIDirect), route)
				if err != nil || ir == "" {
					t.Errorf("%s actual Go opcode not implemented: %v", route, err)
				}
			}
			inferred, err := InferWASMAssemblyFuncSig(file.Funcs[0], "operation")
			if err != nil || inferred.Ret != result || len(inferred.Args) != 2 || inferred.Args[0] != typ || inferred.Args[1] != typ {
				t.Errorf("actual Go stack signature not inferred: %+v, %v", inferred, err)
			}
		})
	}
}

func TestWASMFloatBinaryRejectsOperandsEvenWhenDead(t *testing.T) {
	for _, name := range wasmFloatBinaryGoNames(t) {
		for _, operand := range []string{" $0", " $1.25", " F0", " F0,F1", " 0(SP)", " symbol(SB)"} {
			for _, dead := range []bool{false, true} {
				prefix := ""
				if dead {
					prefix = "RET\n"
				}
				file, err := Parse(ArchWASM, "TEXT operation(SB),4,$0-0\n"+prefix+name+operand+"\nRET\n")
				if err != nil {
					continue
				}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"operation": {Name: "operation", Ret: Void}}, WASMABIDirect), route)
					if err == nil || ir != "" {
						t.Errorf("%s accepted %s%s, dead=%t", route, name, operand, dead)
					}
				}
			}
		}
	}
}

func TestWASMFloatBinaryTypedStackAndRegisterMatrix(t *testing.T) {
	names := wasmFloatBinaryGoNames(t)
	if len(wasmFloatBinaryOps) != len(names) {
		t.Fatal("typed family is not the complete, exact Go namespace")
	}
	var allSource strings.Builder
	sigs := make(map[string]FuncSig)
	for _, name := range names {
		typ, result, first, second := wasmFloatBinaryTestTypes(name)
		if _, ok := wasmFloatBinaryOps[strings.ToUpper(name)]; !ok {
			t.Fatalf("official opcode absent from typed grammar: %s", name)
		}
		base := 0
		if typ == "double" {
			base = 16
		}
		for bank := 0; bank < 16; bank++ {
			for _, alias := range []bool{false, true} {
				x, y := Reg(fmt.Sprintf("F%d", base+bank)), Reg(fmt.Sprintf("F%d", base+15-bank))
				if alias {
					y = x
				}
				function := fmt.Sprintf("bank%d", len(sigs))
				fmt.Fprintf(&allSource, "TEXT %s(SB),4,$0-0\nGet %s\nGet %s\n%s\nDrop\nRET\n", function, x, y, name)
				sigs[function] = FuncSig{Name: function, Ret: Void}
			}
		}
		good := fmt.Sprintf("Get %s\nGet %s\n", first, second)
		wrong := "Get F16\n"
		if typ == "double" {
			wrong = "Get F0\n"
		}
		for _, body := range []string{
			name,
			fmt.Sprintf("Get %s\n%s", first, name),
			"I32Const $0\nI32Const $1\n" + name,
			"I64Const $0\nI64Const $1\n" + name,
			wrong + fmt.Sprintf("Get %s\n%s", second, name),
			fmt.Sprintf("Get %s\n", first) + wrong + name,
			good + name + ".invalid",
		} {
			file, err := Parse(ArchWASM, "TEXT operation(SB),4,$0-0\n"+body+"\nReturn\n")
			if err != nil {
				// The source parser owns target-independent suffix rejection.
				continue
			}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"operation": {Name: "operation", Ret: result}}, WASMABIDirect), route)
				if err == nil || ir != "" {
					t.Fatalf("%s accepted invalid typed stack:\n%s", route, body)
				}
			}
			if sig, err := InferWASMAssemblyFuncSig(file.Funcs[0], "operation"); err == nil {
				t.Fatalf("inference accepted invalid typed stack as %+v:\n%s", sig, body)
			}
		}
	}
	// Every register in both width banks, reversed source order and aliasing
	// is accepted by actual Go and compiled by each public LLVM route.
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, allSource.String(), goos)
	}
	file, err := Parse(ArchWASM, allSource.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "banks.ll", "banks.o", ir)
	}
}

func TestWASMFloatBinaryTypedGoEntryAndDeadFormat(t *testing.T) {
	var source, declarations strings.Builder
	declarations.WriteString("package floatbinary\n")
	for index, name := range wasmFloatBinaryGoNames(t) {
		_, _, first, second := wasmFloatBinaryTestTypes(name)
		fmt.Fprintf(&declarations, "func operation%d()\n", index)
		fmt.Fprintf(&source, "TEXT ·operation%d(SB),4,$0-0\nGet %s\nGet %s\n%s\nDrop\nRET\n", index, first, second, name)
	}
	pkg := mustGoPackage(t, "floatbinary", declarations.String())
	context := llvm.NewContext()
	defer context.Dispose()
	options := GoModuleOptions{GOOS: "js", GOARCH: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: testResolveSym("floatbinary")}
	translated, err := translateGoModuleInContext(context, pkg, []byte(source.String()), options)
	if err != nil {
		t.Fatal(err)
	}
	ir := translated.Module.String()
	translated.Module.Dispose()
	compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "typed-go.ll", "typed-go.o", ir)
	for _, name := range wasmFloatBinaryGoNames(t) {
		malformed := fmt.Sprintf("TEXT ·operation0(SB),4,$0-0\nRET\n%s $1\nRET\n", name)
		translated, err := translateGoModuleInContext(context, pkg, []byte(malformed), options)
		if translated != nil {
			translated.Module.Dispose()
		}
		if err == nil || translated != nil {
			t.Fatalf("typed Go accepted malformed dead %s: %v", name, err)
		}
	}
}
