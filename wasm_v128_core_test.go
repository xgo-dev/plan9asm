package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This semantic inventory is independent of the translator and host Go's
// assembler version. LLVM coverage must also run before Go 1.27 added SIMD.
func wasmV128CoreNames() []string {
	return []string{"V128Const", "V128Not", "V128And", "V128Andnot", "V128Or", "V128Xor", "V128Bitselect", "V128AnyTrue"}
}

func wasmV128CoreConstant(value [2]uint64) string {
	return fmt.Sprintf("V128Const $%d,$%d\n", int64(value[0]), int64(value[1]))
}

func wasmV128CoreInputs(name string) int {
	switch name {
	case "V128Const":
		return 0
	case "V128Not", "V128AnyTrue":
		return 1
	case "V128Bitselect":
		return 3
	default:
		return 2
	}
}

func wasmV128CoreBody(name string, a, b, mask [2]uint64) string {
	if name == "V128Const" {
		return wasmV128CoreConstant(a)
	}
	body := wasmV128CoreConstant(a)
	if wasmV128CoreInputs(name) >= 2 {
		body += wasmV128CoreConstant(b)
	}
	if name == "V128Bitselect" {
		body += wasmV128CoreConstant(mask)
	}
	return body + name + "\n"
}

func wasmV128CoreObjectFixture() (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, name := range wasmV128CoreNames() {
		function := fmt.Sprintf("core%d", index)
		body := wasmV128CoreBody(name, [2]uint64{1, 2}, [2]uint64{3, 4}, [2]uint64{5, 6})
		if name != "V128AnyTrue" {
			body += "V128AnyTrue\n"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", function, body)
		sigs[function] = FuncSig{Name: function, Ret: I32}
	}
	return source.String(), sigs
}

func TestWASMV128CoreThreeAPIObjects(t *testing.T) {
	source, sigs := wasmV128CoreObjectFixture()
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range file.Funcs {
		sig, err := InferWASMAssemblyFuncSig(function, function.Sym)
		if err != nil || len(sig.Args) != 0 || sig.Ret != I32 {
			t.Errorf("V128 core typed stack inference: %+v, %v", sig, err)
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil || ir == "" {
				t.Fatal("V128 core semantic family rejected", err)
			}
			if strings.Contains(ir, "blockaddress") {
				t.Fatal("V128 core introduced an unsupported Wasm code address")
			}
			compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "v128-core.ll", "v128-core.o", ir)
		})
	}
}

func TestWASMV128CoreFormatTypedStackAndDeadCode(t *testing.T) {
	vector := wasmV128CoreConstant([2]uint64{1, 2})
	for _, name := range wasmV128CoreNames() {
		var invalid []string
		instruction := name
		if name == "V128Const" {
			instruction += " $1,$2"
			for _, operands := range []string{"", " $1", " $1,$2,$3", " R0,$1", " $1,R0", " $1.5,$2", " $1,$2.5", " $unresolved,$2", " 0(SP),$2"} {
				invalid = append(invalid, name+operands, "RET\n"+name+operands)
			}
			invalid = append(invalid, name+".Z $1,$2", "RET\n"+name+".Z $1,$2")
		} else {
			for _, operands := range []string{" $0", " R0", " R0,R1", " $1,$2", " 0(SP)", ".Z"} {
				invalid = append(invalid, name+operands, "RET\n"+name+operands)
			}
			inputs := wasmV128CoreInputs(name)
			for count := 0; count < inputs; count++ {
				invalid = append(invalid, strings.Repeat(vector, count)+name)
			}
			for index := 0; index < inputs; index++ {
				for _, scalar := range []string{"I32Const $1\n", "I64Const $1\n", "F64Const $1.0\n", "Get SP\n"} {
					invalid = append(invalid, strings.Repeat(vector, index)+scalar+strings.Repeat(vector, inputs-index-1)+name)
				}
			}
		}
		for index, body := range invalid {
			t.Run(fmt.Sprintf("%s/invalid%d", name, index), func(t *testing.T) {
				file, err := Parse(ArchWASM, "TEXT core(SB),4,$0-0\n"+body+"\nRET\n")
				if err != nil {
					return // Source parsing may reject an invalid operand first.
				}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"core": {Name: "core", Ret: Void}}, WASMABIDirect), route)
					if err == nil || ir != "" || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s malformed or wrongly typed core operation was accepted/folded to Context: %v\n%s", route, err, body)
					}
				}
			})
		}
		// A valid pure instruction after RET needs format validation, not a
		// fictitious live stack input. It remains dead in the returned module.
		t.Run(name+"/valid-dead", func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT core(SB),4,$0-0\nRET\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				if ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"core": {Name: "core", Ret: Void}}, WASMABIDirect), route); err != nil || ir == "" {
					t.Fatalf("%s valid dead core format rejected: %v", route, err)
				}
			}
		})
	}
}

func TestWASMV128CoreTypedGoEntryObjects(t *testing.T) {
	var source, declarations strings.Builder
	declarations.WriteString("package v128core\n")
	for index, name := range wasmV128CoreNames() {
		body := wasmV128CoreBody(name, [2]uint64{1, 2}, [2]uint64{3, 4}, [2]uint64{5, 6})
		if name != "V128AnyTrue" {
			body += "V128AnyTrue\n"
		}
		fmt.Fprintf(&declarations, "func core%d() uint32\n", index)
		fmt.Fprintf(&source, "TEXT ·core%d(SB),4,$0-4\nGet SP\n%sI32Store ret+0(FP)\nRET\n", index, body)
	}
	pkg := mustGoPackage(t, "v128core", declarations.String())
	context := llvm.NewContext()
	defer context.Dispose()
	translated, err := translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{
		GOOS: "js", GOARCH: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: testResolveSym("v128core"),
	})
	if translated != nil {
		defer translated.Module.Dispose()
	}
	if err != nil || translated == nil {
		t.Fatal("typed Go V128 core declaration/body rejected", err)
	}
	compileLLVMToObject(t, wasmDataTool(t, "llc"), "wasm32-unknown-unknown", "v128-core-go.ll", "v128-core-go.o", translated.Module.String())
}
