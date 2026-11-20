package plan9asm

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type armRawStatusCase struct {
	family      string
	instruction string
	conditional bool
}

// This inventory covers every existing specialized raw-data registration.
// LLVM MC supplies independent encodings; the family's own tests still cover
// its complete operand fields, reserved encodings and arithmetic semantics.
func armRawStatusFamilies() []armRawStatusCase {
	return []armRawStatusCase{
		{family: "StructureFourMultiple", instruction: "vld4.8 {d0,d1,d2,d3},[r4]!"},
		{family: "ModifiedImmediate", instruction: "vmov.i8 q0,#18"},
		{family: "CoreLaneMove", instruction: "vmov.32 r0,d0[0]", conditional: true},
		{family: "StructureOneLane", instruction: "vst1.8 {d0[0]},[r4]!"},
		{family: "StructureFourLane", instruction: "vld4.8 {d0[0],d1[0],d2[0],d3[0]},[r4]!"},
		{family: "Transpose", instruction: "vtrn.8 d0,d1"},
		{family: "ShiftRightNarrow", instruction: "vshrn.i16 d0,q1,#1"},
		{family: "BitClearImmediate", instruction: "vbic.i32 d0,#255"},
		{family: "Extract", instruction: "vext.8 q0,q1,q2,#3"},
		{family: "MoveNarrow", instruction: "vmovn.i16 d0,q1"},
		{family: "ShiftInsert", instruction: "vsli.32 q0,q1,#3"},
		{family: "ShiftRightImmediate", instruction: "vshr.u32 q0,q1,#3"},
		{family: "Reverse", instruction: "vrev32.16 q0,q1"},
		{family: "MultiplyLongLane", instruction: "vmull.u32 q0,d1,d2[0]"},
		{family: "MultiplyLongVector", instruction: "vmull.u8 q0,d1,d2"},
		{family: "AddSub", instruction: "vadd.i32 q0,q1,q2"},
		{family: "VFPLoadStore", instruction: "vstr d0,[r4]", conditional: true},
		{family: "ShiftImmediate", instruction: "vshl.i32 q0,q1,#3"},
		{family: "VFPMove", instruction: "vmov.f32 s0,s1", conditional: true},
		{family: "PairwiseMinMax", instruction: "vpmax.f32 d0,d1,d2"},
		{family: "MinMax", instruction: "vmax.f32 q0,q1,q2"},
		{family: "VFPScalarArithmetic", instruction: "vadd.f32 s0,s1,s2", conditional: true},
		{family: "MultiplyLane", instruction: "vmul.f32 q0,q1,d2[0]"},
		{family: "ConvertFloat32", instruction: "vcvt.f32.s32 q0,q1"},
		{family: "MoveLong", instruction: "vmovl.u8 q0,d1"},
		{family: "WideningAddSub", instruction: "vsubl.u8 q0,d1,d2"},
		{family: "Dup", instruction: "vdup.32 q0,r0", conditional: true},
		{family: "StructureOne", instruction: "vld1.8 {d0,d1},[r4]!"},
		{family: "Bitwise", instruction: "veor q0,q1,q2"},
		{family: "SXTB", instruction: "sxtb r0,r1", conditional: true},
		{family: "VMOVPair", instruction: "vmov r0,r1,d0", conditional: true},
		{family: "VFPMultiple", instruction: "vstmia r4!,{d0,d1}", conditional: true},
		{family: "VFPImmediate", instruction: "vmov.f32 s0,#1.0", conditional: true},
	}
}

func armRawStatusVariants() []armRawStatusCase {
	var variants []armRawStatusCase
	for _, family := range armRawStatusFamilies() {
		variants = append(variants, family)
		if family.conditional {
			for _, condition := range []string{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"} {
				variant := family
				end := strings.IndexAny(variant.instruction, ". ")
				variant.instruction = variant.instruction[:end] + condition + variant.instruction[end:]
				variants = append(variants, variant)
			}
		}
	}
	return variants
}

func assembleARMRawStatusWords(t *testing.T, variants []armRawStatusCase) []uint32 {
	t.Helper()
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc not found")
	}
	var source strings.Builder
	source.WriteString(".syntax unified\n.fpu neon\n")
	for _, variant := range variants {
		fmt.Fprintln(&source, variant.instruction)
	}
	cmd := exec.Command(mc, "-triple=armv7-unknown-linux-gnueabihf", "-show-encoding")
	cmd.Stdin = strings.NewReader(source.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM22 ARM raw-status encoder: %v\n%s", err, output)
	}
	encodings := regexp.MustCompile(`encoding: \[([^\]]+)\]`).FindAllStringSubmatch(string(output), -1)
	if len(encodings) != len(variants) {
		t.Fatalf("got %d encodings for %d variants: %s", len(encodings), len(variants), output)
	}
	words := make([]uint32, len(variants))
	for i, encoding := range encodings {
		fields := strings.Split(encoding[1], ",")
		if len(fields) != 4 {
			t.Fatalf("not an A32 word: %s", encoding[0])
		}
		var code [4]byte
		for j, field := range fields {
			value, err := strconv.ParseUint(strings.TrimSpace(field), 0, 8)
			if err != nil {
				t.Fatal(err)
			}
			code[j] = byte(value)
		}
		words[i] = binary.LittleEndian.Uint32(code[:])
	}
	return words
}

func armRawStatusSource(index int, word uint32) string {
	return fmt.Sprintf("TEXT rawstatus_%d(SB),4,$128-12\n MOVW status+0(FP),R0\n MOVW R0,CPSR\n MOVW scratch+4(FP),R4\n MOVW R4,R0\n MOVW R4,R1\n WORD $%#08x\n MOVW CPSR,R0\n SRL $28,R0\n MOVW R0,ret+8(FP)\n RET\n", index, word)
}

func armRawStatusSignature(name string) FuncSig {
	return FuncSig{Name: name, Args: []LLVMType{I32, Ptr}, Ret: I32, Frame: FrameLayout{
		Params: []FrameSlot{
			{Offset: 0, Type: I32, Index: 0, Field: -1},
			{Offset: 4, Type: Ptr, Index: 1, Field: -1},
		},
		Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
	}}
}

func TestARMRawDataStatusRegistrationCompleteness(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "arm_raw_data_forms.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		name, ok := literal.Type.(*ast.Ident)
		if !ok || name.Name != "armRawDataForm" {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok || key.Name != "family" {
				continue
			}
			value, ok := field.Value.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				t.Fatal("raw status family registration needs an explicit inventory name")
			}
			name, err := strconv.Unquote(value.Value)
			if err != nil || name == "" || registered[name] {
				t.Fatalf("invalid/duplicate raw family registration: %s", value.Value)
			}
			registered[name] = true
		}
		return true
	})
	for _, family := range armRawStatusFamilies() {
		if !registered[family.family] {
			t.Fatalf("fixture family %q has no typed registration", family.family)
		}
		delete(registered, family.family)
	}
	if len(registered) != 0 {
		t.Fatalf("registered raw families have no status oracle: %v", registered)
	}
}

func TestARMRawDataStatusAllConditionsAndObjects(t *testing.T) {
	variants := armRawStatusVariants()
	words := assembleARMRawStatusWords(t, variants)
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for i, word := range words {
		form, ok := decodeARMRawDataForm(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
		if !ok || form.family != variants[i].family {
			t.Fatalf("%s %s decoded as %+v, registered=%v", variants[i].family, variants[i].instruction, form, ok)
		}
		text := armRawStatusSource(i, word)
		requireARMGoAssemblerResult(t, text, true)
		source.WriteString(text)
		name := fmt.Sprintf("rawstatus_%d", i)
		sigs[name] = armRawStatusSignature(name)
	}
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "raw-status-family.ll", "raw-status-family.o", ir)
	}
	t.Logf("%d raw data families, %d independent LLVM-MC variants, three ARM object targets", len(armRawStatusFamilies()), len(variants))
}
