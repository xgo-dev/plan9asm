package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type wasmLaneTestForm struct {
	name     string
	bits     int
	lane     int
	floating bool
}

// This matrix comes from the Go 1.27 encoder namespace and the architectural
// selector ranges. It must stay independent of the lowerer's descriptors.
func wasmV128LaneTestForms() []wasmLaneTestForm {
	var forms []wasmLaneTestForm
	for _, shape := range []struct {
		prefix   string
		bits     int
		floating bool
	}{
		{"I8x16", 8, false}, {"I16x8", 16, false},
		{"I32x4", 32, false}, {"I64x2", 64, false},
		{"F32x4", 32, true}, {"F64x2", 64, true},
	} {
		forms = append(forms, wasmLaneTestForm{shape.prefix + "Splat", shape.bits, -1, shape.floating})
		extract := []string{"ExtractLane"}
		if shape.bits < 32 {
			extract = []string{"ExtractLaneS", "ExtractLaneU"}
		}
		for _, op := range append(extract, "ReplaceLane") {
			for i := 0; i < 128/shape.bits; i++ {
				forms = append(forms, wasmLaneTestForm{shape.prefix + op, shape.bits, i, shape.floating})
			}
		}
	}
	return forms
}

func (f wasmLaneTestForm) extract() bool { return strings.Contains(f.name, "ExtractLane") }

func (f wasmLaneTestForm) instruction() string {
	if f.lane == -1 {
		return f.name + "\n"
	}
	// Go's assembler encodes the selector from the destination operand.
	return fmt.Sprintf("%s $0,$%d\n", f.name, f.lane)
}

func (f wasmLaneTestForm) scalarType() LLVMType {
	switch {
	case f.floating && f.bits == 64:
		return LLVMType("double")
	case f.floating:
		return LLVMType("float")
	case f.bits == 64:
		return I64
	default:
		return I32
	}
}

func (f wasmLaneTestForm) dynamicBody(name string) (string, FuncSig) {
	sig := FuncSig{Name: name, Ret: "<4 x i32>"}
	body := ""
	if f.lane >= 0 {
		body = "Get V0\n"
	}
	if f.extract() {
		sig.Ret = f.scalarType()
	} else {
		switch f.scalarType() {
		case "float":
			body += "Get F0\n"
			sig.Args, sig.ArgRegs = []LLVMType{"float"}, []Reg{"F0"}
		case "double":
			body += "Get F16\n"
			sig.Args, sig.ArgRegs = []LLVMType{"double"}, []Reg{"F16"}
		default:
			body += "Get R0\n"
			if f.bits != 64 {
				body += "I32WrapI64\n"
			}
			sig.Args, sig.ArgRegs = []LLVMType{I64}, []Reg{"R0"}
		}
	}
	if f.lane >= 0 {
		sig.Args = append(sig.Args, "<4 x i32>")
		sig.ArgRegs = append(sig.ArgRegs, "V0")
	}
	return body + f.instruction(), sig
}

func wasmV128LaneObjectFixture(t *testing.T) (string, map[string]FuncSig) {
	t.Helper()
	forms := wasmV128LaneTestForms()
	if len(forms) != 102 {
		t.Fatal("incomplete Go SIMD lane format matrix", len(forms))
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, form := range forms {
		name := fmt.Sprintf("lane%d", index)
		body, sig := form.dynamicBody(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", name, body)
		sigs[name] = sig
	}
	return source.String(), sigs
}

func TestWASMV128LaneTypedObjects(t *testing.T) {
	source, sigs := wasmV128LaneObjectFixture(t)
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		want := sigs[fn.Sym]
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || got.Ret != want.Ret || !reflect.DeepEqual(got.Args, want.Args) ||
			!reflect.DeepEqual(got.ArgRegs, want.ArgRegs) {
			t.Errorf("%s: inferred %+v, want %+v, error %v", fn.Sym, got, want, err)
		}
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			t.Run(route+"/"+triple, func(t *testing.T) {
				options := wasmPackedOptions(sigs, WASMABIDirect)
				options.TargetTriple = triple
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil || ir == "" {
					t.Fatal("SIMD lane object rejected", err)
				}
				compileLLVMToObject(t, wasmDataTool(t, "llc"), triple, "lanes.ll", "lanes.o", ir)
			})
		}
	}
}

func TestWASMV128LaneSelectorAndStackRejection(t *testing.T) {
	seen := make(map[string]bool)
	for _, form := range wasmV128LaneTestForms() {
		if seen[form.name] {
			continue
		}
		seen[form.name] = true
		t.Run(form.name, func(t *testing.T) {
			for _, prefix := range []string{"", "RET\n"} {
				invalid := []string{" $0", " $0.5", " $lane", " V0"}
				if form.lane >= 0 {
					invalid = []string{
						"", " $1", " $0,$-1", fmt.Sprintf(" $0,$%d", 128/form.bits),
						" $0,$0.5", " $0,$lane", " $0,V0", " V0,$0", " $0,$0,$0",
					}
				}
				for _, args := range invalid {
					wasmLaneReject(t, prefix+form.name+args+"\nRET\n")
				}
			}
			if form.extract() {
				wasmLaneReject(t, "I32Const $1\n"+form.instruction()+"Return\n")
			} else {
				prefix := ""
				if form.lane >= 0 {
					prefix = "V128Const $1,$2\n"
				}
				wasmLaneReject(t, prefix+"V128Const $3,$4\n"+form.instruction()+"Return\n")
			}
		})
	}
}

func wasmLaneReject(t *testing.T, body string) {
	t.Helper()
	file, err := Parse(ArchWASM, "TEXT lane(SB),4,$0-0\n"+body)
	if err != nil {
		return
	}
	if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "lane"); err == nil {
		t.Errorf("inferred an invalid source:\n%s", body)
	}
	sig := FuncSig{Name: "lane", Ret: Void}
	if ir, err := Translate(file, wasmPackedOptions(map[string]FuncSig{"lane": sig}, WASMABIDirect)); err == nil || ir != "" {
		t.Errorf("translated an invalid source:\n%s", body)
	}
}

func (f wasmLaneTestForm) numericRuntimeBody(vector [2]uint64, scalar uint64) string {
	arithmetic := func(value uint64) string {
		if f.bits == 64 {
			return fmt.Sprintf("I64Const $%d\n", int64(value))
		}
		return fmt.Sprintf("I32Const $%d\n", int32(value))
	}
	body := ""
	if f.lane >= 0 {
		body = wasmV128CoreConstant(vector)
	}
	mask := (uint64(1) << uint(f.bits)) - 1
	if f.extract() {
		bit := f.lane * f.bits
		result := vector[bit/64] >> (bit % 64) & mask
		if strings.HasSuffix(f.name, "LaneS") {
			result = uint64(int64(result<<(64-f.bits)) >> (64 - f.bits))
		}
		body += f.instruction()
		if f.floating {
			body += fmt.Sprintf("I%dReinterpretF%d\n", f.bits, f.bits)
		}
		literalWidth := 32
		if f.bits == 64 {
			literalWidth = 64
		}
		return body + arithmetic(result) + fmt.Sprintf("I%dNe\n", literalWidth)
	}

	body += arithmetic(scalar)
	if f.floating {
		body += fmt.Sprintf("F%dReinterpretI%d\n", f.bits, f.bits)
	}
	body += f.instruction()
	for lane := 0; lane < 128/f.bits; lane++ {
		if f.lane == -1 || lane == f.lane {
			bit := lane * f.bits
			half, shift := bit/64, bit%64
			vector[half] = (vector[half] &^ (mask << shift)) | ((scalar & mask) << shift)
		}
	}
	return body + wasmV128CoreConstant(vector) + "V128Xor\nV128AnyTrue\n"
}
