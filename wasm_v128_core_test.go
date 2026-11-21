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
	names := []string{
		"V128Const", "V128Not", "V128And", "V128Andnot", "V128Or", "V128Xor", "V128Bitselect", "V128AnyTrue",
		"I8x16Add", "I8x16AddSatS", "I8x16AddSatU", "I8x16Sub", "I8x16SubSatS", "I8x16SubSatU",
		"I16x8Add", "I16x8AddSatS", "I16x8AddSatU", "I16x8Sub", "I16x8SubSatS", "I16x8SubSatU", "I16x8Mul",
		"I32x4Add", "I32x4Sub", "I32x4Mul", "I64x2Add", "I64x2Sub", "I64x2Mul",
	}
	for _, shape := range []string{"F32x4", "F64x2"} {
		for _, operation := range strings.Fields("Abs Neg Sqrt Ceil Floor Trunc Nearest Add Sub Mul Div Min Max Pmin Pmax Eq Ne Lt Gt Le Ge") {
			names = append(names, shape+operation)
		}
	}
	for _, shape := range []string{"I8x16", "I16x8", "I32x4", "I64x2"} {
		operations := "Eq Ne LtS GtS LeS GeS"
		if shape != "I64x2" {
			operations += " LtU GtU LeU GeU MinS MinU MaxS MaxU"
		}
		for _, op := range strings.Fields(operations) {
			names = append(names, shape+op)
		}
	}
	for _, shape := range []string{"I8x16", "I16x8", "I32x4", "I64x2"} {
		for _, op := range strings.Fields("Abs Neg AllTrue Bitmask Shl ShrS ShrU") {
			names = append(names, shape+op)
		}
	}
	names = append(names, "I8x16Popcnt")
	names = append(names,
		"I8x16NarrowI16x8S", "I8x16NarrowI16x8U",
		"I16x8NarrowI32x4S", "I16x8NarrowI32x4U",
	)
	for i, output := range []string{"I16x8", "I32x4", "I64x2"} {
		input := [...]string{"I8x16", "I16x8", "I32x4"}[i]
		for _, extension := range []string{"S", "U"} {
			for _, operation := range strings.Fields("ExtendLow ExtendHigh ExtmulLow ExtmulHigh") {
				names = append(names, output+operation+input+extension)
			}
			if i < 2 {
				names = append(names, output+"ExtaddPairwise"+input+extension)
			}
		}
	}
	for _, form := range wasmV128ConversionTestForms {
		names = append(names, form.name)
	}
	return names
}

func wasmV128CoreConstant(value [2]uint64) string {
	return fmt.Sprintf("V128Const $%d,$%d\n", int64(value[0]), int64(value[1]))
}

func wasmV128CoreInputs(name string) int {
	if _, ok := wasmV128ConversionTestLookup(name); ok {
		return 1
	}
	if _, op := wasmV128FloatParts(name); op != "" {
		switch op {
		case "Abs", "Neg", "Sqrt", "Ceil", "Floor", "Trunc", "Nearest":
			return 1
		default:
			return 2
		}
	}
	if _, op := wasmV128IntegerParts(name); wasmV128IntegerUnary(op) {
		return 1
	}
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
	if _, op := wasmV128IntegerParts(name); wasmV128IntegerShift(op) {
		return body + fmt.Sprintf("I32Const $%d\n%s\n", int32(b[0]), name)
	}
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
		sig := FuncSig{Name: function, Ret: I32}
		body := wasmV128CoreBody(name, [2]uint64{1, 2}, [2]uint64{3, 4}, [2]uint64{5, 6})
		floatBits, _ := wasmV128FloatParts(name)
		_, integerOp := wasmV128IntegerParts(name)
		_, conversion := wasmV128ConversionTestLookup(name)
		switch {
		case wasmV128IntegerShift(integerOp):
			body = "Get V0\nGet R0\nI32WrapI64\n" + name + "\n"
			sig.Args = []LLVMType{I64, "<4 x i32>"}
			sig.ArgRegs = []Reg{"R0", "V0"}
		case floatBits != 0 || conversion || wasmV128IntegerOrdering(integerOp) ||
			wasmV128IntegerUnary(integerOp) || strings.HasPrefix(integerOp, "Ext") ||
			strings.HasPrefix(integerOp, "Narrow"):
			body = ""
			for arg := 0; arg < wasmV128CoreInputs(name); arg++ {
				reg := Reg(fmt.Sprintf("V%d", arg))
				body += fmt.Sprintf("Get %s\n", reg)
				sig.Args = append(sig.Args, "<4 x i32>")
				sig.ArgRegs = append(sig.ArgRegs, reg)
			}
			body += name + "\n"
		}
		if !wasmV128CoreScalarResult(name) {
			body += "V128AnyTrue\n"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", function, body)
		sigs[function] = sig
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
		want := sigs[function.Sym]
		if err != nil || sig.Ret != want.Ret || len(sig.Args) != len(want.Args) || len(sig.ArgRegs) != len(want.ArgRegs) {
			t.Errorf("V128 core typed stack inference: %+v, %v", sig, err)
			continue
		}
		for i := range sig.Args {
			if sig.Args[i] != want.Args[i] || sig.ArgRegs[i] != want.ArgRegs[i] {
				t.Errorf("V128 core typed argument %d: %+v, want %+v", i, sig, want)
			}
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
				t.Run(triple, func(t *testing.T) {
					options := wasmPackedOptions(sigs, WASMABIDirect)
					options.TargetTriple = triple
					ir, err := wasmPackedTranslate(t, file, options, route)
					if err != nil || ir == "" {
						t.Fatal("V128 core semantic family rejected", err)
					}
					if strings.Contains(ir, "blockaddress") {
						t.Fatal("V128 core introduced an unsupported Wasm code address")
					}
					compileLLVMToObject(t, wasmDataTool(t, "llc"), triple, "v128-core.ll", "v128-core.o", ir)
				})
			}
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
			inputs := make([]string, wasmV128CoreInputs(name))
			for i := range inputs {
				inputs[i] = vector
			}
			if _, op := wasmV128IntegerParts(name); wasmV128IntegerShift(op) {
				inputs[1] = "I32Const $1\n"
			}
			for index, input := range inputs {
				prefix := strings.Join(inputs[:index], "")
				suffix := strings.Join(inputs[index+1:], "")
				invalid = append(invalid, prefix+name)
				for _, replacement := range []string{vector, "I32Const $1\n", "I64Const $1\n", "F64Const $1.0\n", "Get SP\n"} {
					if replacement != input {
						invalid = append(invalid, prefix+replacement+suffix+name)
					}
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
		if !wasmV128CoreScalarResult(name) {
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
