package plan9asm

import (
	"fmt"
	"go/types"
	"reflect"
	"testing"
)

func x86ResultParameterRoleInstructions(t *testing.T, body string) []Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+body+"\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs
}

func TestX86ABI0ResultInitializationParameterLeafRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, typ := range []string{"uintptr", "bool", "float32", "float64", "complex64", "complex128",
			"*uint32", "func()", "map[uint32]uint32", "chan uint32", "string", "[]uint32", "interface{}",
			"struct{}", "[0]uintptr", "struct{ Z [0]uintptr; N uintptr }", "[2]uintptr",
			"struct{ P *uint32; N uintptr }", "struct{ A [2]struct{ P *uint32; N uintptr }; S []uint32 }"} {
			t.Run(arch+"/"+typ, func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(x "+typ+") uint32", "RET")
				file.Funcs[0].Instrs = x86ResultParameterRoleInstructions(t, fmt.Sprintf("MOVL $42,ret0+%d(FP)\nRET", sig.Frame.Results[0].Offset))
				for _, query := range []struct {
					name string
					run  func(Func, FuncSig, string) error
				}{
					{"public", CheckX86ABI0ResultInitialization},
					{"scalar view", checkX86ScalarFPResultInitialization},
				} {
					original := fmt.Sprintf("%#v %#v", file.Funcs[0], sig)
					if err := query.run(file.Funcs[0], sig, arch); err != nil {
						t.Fatal(query.name, "actual scalar/aggregate leaf rejected:", err)
					}
					if original != fmt.Sprintf("%#v %#v", file.Funcs[0], sig) {
						t.Fatal("parameter observation rewrote its source/signature")
					}
					for index := range sig.Frame.Params {
						for _, mutation := range []string{"type", "negative index", "past index", "wrong field", "wrong nested field", "duplicate leaf"} {
							changed := sig
							changed.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
							changed.Frame.Params[index].Fields = append([]int(nil), sig.Frame.Params[index].Fields...)
							slot := &changed.Frame.Params[index]
							switch mutation {
							case "type":
								if slot.Type == Ptr {
									slot.Type = I32
								} else {
									slot.Type = Ptr
								}
							case "negative index":
								slot.Index = -1
							case "past index":
								slot.Index = len(sig.Args)
							case "wrong field":
								slot.Field, slot.Fields = 999, nil
							case "wrong nested field":
								slot.Fields = append(append([]int(nil), frameSlotFields(*slot)...), -1)
							case "duplicate leaf":
								copySlot := *slot
								if len(sig.Frame.Params) > 1 {
									other := (index + 1) % len(sig.Frame.Params)
									copySlot.Offset = sig.Frame.Params[other].Offset
									changed.Frame.Params[other] = copySlot
								} else {
									copySlot.Offset = sig.Frame.Results[0].Offset
									changed.Frame.Params = append(changed.Frame.Params, copySlot)
								}
							}
							if err := query.run(file.Funcs[0], changed, arch); err == nil {
								t.Fatal(query.name, mutation, index, "contradictory parameter acquired entry facts")
							}
						}
					}
					// The official flattened form has one scalar argument per part,
					// not one original aggregate argument per source parameter.
					flat := sig
					flat.Args = nil
					flat.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
					for index := range flat.Frame.Params {
						slot := &flat.Frame.Params[index]
						flat.Args = append(flat.Args, slot.Type)
						slot.Index, slot.Field, slot.Fields = index, -1, nil
					}
					if err := query.run(file.Funcs[0], flat, arch); err != nil {
						t.Fatal(query.name, "valid flattened parts rejected:", err)
					}
				}
			})
		}
	}
}

func TestX86ABI0ResultInitializationActualNestedNumericalLEA(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		pkg, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(x struct{ A [2]struct{ P *uint32; N uintptr }; S []uint32 }) uint32", "RET")
		move, lea := "MOVQ", "LEAQ"
		if arch == "386" {
			move, lea = "MOVL", "LEAL"
		}
		for _, slot := range sig.Frame.Params {
			if slot.Type == Ptr {
				continue
			}
			body := fmt.Sprintf("%s part+%d(FP),AX\n%s 0(AX*8),CX\nMOVL $42,ret0+%d(FP)\nRET", move, slot.Offset, lea, sig.Frame.Results[0].Offset)
			file.Funcs[0].Instrs = x86ResultParameterRoleInstructions(t, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
				t.Fatal(arch, slot, err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
				t.Fatal(arch, slot, err)
			}
		}
		actual := pkg.Types.Scope().Lookup("Value").(*types.Func).Type().(*types.Signature)
		args, slots, _, err := goLLVMArgsAndFrameSlotsForTuple(actual.Params(), arch, types.SizesFor("gc", arch), types.SizesFor("gc", arch), 0, true)
		if err != nil {
			t.Fatal(err)
		}
		flat := sig
		flat.Args, flat.Frame.Params = args, slots
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], flat, arch); err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(flat, sig) {
			t.Fatal("flattened producer control did not change argument roles")
		}
	}
}

func TestX86ResultParameterRoleExactAggregateGrammar(t *testing.T) {
	for _, row := range []struct {
		typ   LLVMType
		path  []int
		leaf  LLVMType
		valid bool
	}{
		{I64, nil, I64, true},
		{Ptr, nil, I64, false},
		{"{ ptr, i64, i64 }", []int{1}, I64, true},
		{"{ { ptr, i32 }, [2 x { ptr, i64 }] }", []int{1, 1, 1}, I64, true},
		{"[18446744073709551615 x i64]", []int{3}, I64, true},
		{"[18446744073709551616 x i64]", []int{3}, I64, false},
		{"[0 x i64]", []int{0}, I64, false},
		{"[2 x i64]", []int{2}, I64, false},
		{"[2 x i64]", []int{-1}, I64, false},
		{"{ ptr, i64 }", []int{1, 0}, I64, false},
		{"{ ptr, i64 }", []int{2}, I64, false},
		{"{ {ptr, i64], i64 }", []int{1}, I64, false},
		{"{ [2 x i64, i64 }", []int{1}, I64, false},
		{"{ ptr,, i64 }", []int{2}, I64, false},
		{"%unbound", []int{0}, I64, false},
		{"<{ ptr, i64 }>", []int{1}, I64, false},
		{"<2 x i64>", []int{1}, I64, false},
		{"[+2 x i64]", []int{1}, I64, false},
	} {
		slot := FrameSlot{Index: 0, Type: row.leaf, Field: -1, Fields: row.path}
		if _, valid := x86ResultParameterRole([]LLVMType{row.typ}, slot); valid != row.valid {
			t.Fatal(row, "leaf classification", valid)
		}
	}
	// Fields is the existing authoritative nested path; Field is not a second
	// extraction and may retain the compatibility producer's outer field.
	slot := FrameSlot{Index: 0, Type: I64, Field: 99, Fields: []int{1, 0}}
	if _, valid := x86ResultParameterRole([]LLVMType{"{ ptr, [2 x i64] }"}, slot); !valid {
		t.Fatal("nested path override was changed")
	}
}
