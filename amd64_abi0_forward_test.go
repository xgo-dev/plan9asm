package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestX86ABI0ForwardCopyScalarWidths(t *testing.T) {
	for _, test := range []struct {
		op, register string
		typ          LLVMType
	}{
		{"MOVB", "AX", I8},
		{"MOVW", "AX", I16},
		{"MOVL", "AX", I32},
		{"MOVQ", "AX", I64},
		{"MOVSS", "X0", "float"},
		{"MOVSD", "X0", "double"},
	} {
		t.Run(test.op, func(t *testing.T) {
			source := fmt.Sprintf(`TEXT copy(SB),$16-16
	%s arg+8(FP), %s
	%s %s, 8(SP)
	%s 8(SP), %s
	%s %s, ret+8(FP)
	RET
`, test.op, test.register, test.op, test.register,
				test.op, test.register, test.op, test.register)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			var instructions []Instr
			for _, ins := range file.Funcs[0].Instrs {
				if ins.Op != "TEXT" {
					instructions = append(instructions, ins)
				}
			}
			slot := FrameSlot{Offset: 8, Type: test.typ}
			if !x86ABI0ForwardCopy(instructions[0], instructions[1], slot, true) ||
				!x86ABI0ForwardCopy(instructions[2], instructions[3], slot, false) {
				t.Fatal("rejected equal-width scalar frame copies")
			}
			slot.Type = I64
			if test.typ == I64 || test.typ == "double" {
				slot.Type = I32
			}
			if x86ABI0ForwardCopy(instructions[0], instructions[1], slot, true) {
				t.Fatal("accepted a copy with the wrong frame-slot width")
			}
		})
	}
}

func TestX86ABI0ForwarderRequiresCompleteTypedShape(t *testing.T) {
	tc := issue44Cases[3]
	pkg := mustGoPackage(t, "test/forward", "package forward\n"+tc.declarations)
	fn := pkg.Types.Scope().Lookup("Y").(*types.Func)
	sig, err := goFuncSigForDeclaredFunc("Y", fn, "amd64", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, old, replacement string
		valid                  bool
	}{
		{name: "exact", valid: true},
		{name: "renamed_code_parameter", old: "code+", replacement: "function_pointer+", valid: true},
		{name: "wrong_argument_offset", old: "AX, 8(SP)", replacement: "AX, 0(SP)"},
		{name: "wrong_argument_width", old: "MOVQ b+8(FP)", replacement: "MOVL b+8(FP)"},
		{name: "missing_argument", old: "MOVQ AX, 8(SP)\n", replacement: ""},
		{name: "wrong_code_slot", old: "code+16(FP)", replacement: "code+8(FP)"},
		{name: "wrong_code_register", old: "CALL *AX", replacement: "CALL *BX"},
		{name: "wrong_result_offset", old: "16(SP), AX", replacement: "8(SP), AX"},
		{name: "wrong_result_destination", old: "ret+24(FP)", replacement: "ret+16(FP)"},
		{name: "mutation", old: "CALL *AX", replacement: "INCQ 0(SP)\nCALL *AX"},
		{name: "second_call", old: "CALL *AX", replacement: "CALL *AX\nCALL *AX"},
		{name: "branch", old: "CALL *AX", replacement: "JMP end\nCALL *AX\nend:"},
		{name: "tail_jump", old: "RET", replacement: "JMP *AX"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := tc.assembly
			if test.old != "" {
				source = strings.Replace(source, test.old, test.replacement, 1)
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			got := inferX86ABI0Forwarder(file.Funcs[0], sig, "amd64")
			if (got != nil) != test.valid {
				t.Fatalf("inferred %+v, want valid=%v", got, test.valid)
			}
			if got != nil && (len(got.Args) != 2 || got.Ret != I64 || got.Frame.Results[0].Offset != 16) {
				t.Fatalf("wrong callback signature: %+v", got)
			}
		})
	}
}

func TestGoABI0NestedAggregateFrameLayout(t *testing.T) {
	pkg := mustGoPackage(t, "test/layout", `package layout
type Mixed struct { Byte uint8; Pair [2]uint64; Z complex128 }
func Y(a Mixed, b complex64) (r Mixed)
`)
	fn := pkg.Types.Scope().Lookup("Y").(*types.Func)
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			sig, err := goFuncSigForDeclaredFunc("Y", fn, arch, nil, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Args[0] != "{ i8, [2 x i64], { double, double } }" || len(sig.Frame.Params) != 7 || len(sig.Frame.Results) != 5 {
				t.Fatalf("incorrect aggregate layout: %+v", sig)
			}
			word := int64(goWordSize(arch))
			wantOffsets := []int64{0, word, word + 8, word + 16, word + 24, word + 32, word + 36}
			wantPaths := []string{", 0", ", 1, 0", ", 1, 1", ", 2, 0", ", 2, 1", ", 0", ", 1"}
			for i, slot := range sig.Frame.Params {
				if slot.Offset != wantOffsets[i] || frameSlotExtractSuffix(slot) != wantPaths[i] {
					t.Fatalf("slot %d = %+v, want offset=%d path=%s", i, slot, wantOffsets[i], wantPaths[i])
				}
			}
		})
	}
}
