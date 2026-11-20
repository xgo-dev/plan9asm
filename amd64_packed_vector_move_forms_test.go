package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type x86PackedMoveExpectedAxes struct {
	operands     string
	memory, mask int
	write, zero  bool
}

func TestX86PackedMoveGrammarCoversEveryCurrentGoFamilyMember(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]amd64PackedMoveEncoding{
		"_yvmovdqa": amd64PackedMoveVEX, "_yvmovapd": amd64PackedMoveVEXOrEVEX,
		"_yvmovdqa32": amd64PackedMoveEVEX,
	}
	wanted := make(map[Op]amd64PackedMoveEncoding)
	rows := make(map[string]int)
	ast.Inspect(file, func(node ast.Node) bool {
		if value, ok := node.(*ast.ValueSpec); ok && len(value.Names) == 1 && len(value.Values) == 1 {
			name := value.Names[0].Name
			if _, family := tables[name]; family {
				literal, ok := value.Values[0].(*ast.CompositeLit)
				if !ok {
					t.Fatalf("Go packed-move table is no longer literal: %s", name)
				}
				rows[name] = len(literal.Elts)
			}
		}
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var opcode, table string
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, keyOK := field.Key.(*ast.Ident)
			value, valueOK := field.Value.(*ast.Ident)
			if !keyOK || !valueOK {
				continue
			}
			switch key.Name {
			case "as":
				opcode = value.Name
			case "ytab":
				table = value.Name
			}
		}
		if encoding, family := tables[table]; family {
			if !strings.HasPrefix(opcode, "AVMOV") {
				t.Fatalf("unregistered spelling in shared Go move family: %s", opcode)
			}
			wanted[Op(strings.TrimPrefix(opcode, "A"))] = encoding
		}
		return true
	})
	if !reflect.DeepEqual(rows, map[string]int{"_yvmovdqa": 4, "_yvmovapd": 16, "_yvmovdqa32": 12}) || len(wanted) != len(amd64PackedVectorMoveSpecs) {
		t.Fatalf("current Go family changed: rows=%v opcodes=%v", rows, wanted)
	}
	for opcode, encoding := range wanted {
		spec, present := amd64PackedVectorMoveSpecs[opcode]
		if !present || spec.encoding != encoding {
			t.Fatalf("Go opcode/encoding omitted or changed: %s/%d", opcode, encoding)
		}
	}
}

func TestX86PackedMoveGrammarAxesAndFiveLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var opcodes []string
	for opcode := range amd64PackedVectorMoveSpecs {
		opcodes = append(opcodes, string(opcode))
	}
	sort.Strings(opcodes)
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		sigs := make(map[string]FuncSig)
		for _, opcode := range opcodes {
			spec := amd64PackedVectorMoveSpecs[Op(opcode)]
			for index, bank := range []string{"X", "Y", "Z"} {
				if bank == "Z" && spec.encoding == amd64PackedMoveVEX {
					continue
				}
				width, high := 16<<index, 31
				if spec.encoding == amd64PackedMoveVEX {
					high = 15
				}
				if arch == "386" {
					// Go-accepted high X/Y rows have independent Context
					// regressions; actual objects use the physical low bank.
					high = 7
				}
				register := fmt.Sprintf("%s%d", bank, high)
				forms := []x86PackedMoveExpectedAxes{
					{"(AX)," + register, 0, -1, false, false},
					{register + ",(AX)", 1, -1, true, false},
					{register + "," + bank + "0", -1, -1, false, false},
				}
				if spec.encoding != amd64PackedMoveVEX {
					forms = append(forms,
						x86PackedMoveExpectedAxes{"(AX),K7," + register, 0, 1, false, false},
						x86PackedMoveExpectedAxes{register + ",K7,(AX)", 2, 1, true, false},
						x86PackedMoveExpectedAxes{register + ",K7," + bank + "0", -1, 1, false, false})
					maskedForms := append([]x86PackedMoveExpectedAxes(nil), forms[3:]...)
					for _, masked := range maskedForms {
						masked.zero = true
						forms = append(forms, masked)
					}
				}
				for _, expected := range forms {
					name := opcode
					if expected.zero {
						name += ".Z"
					}
					instruction := name + " " + expected.operands
					parsed, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					form, recognized, err := amd64PackedVectorMoveProperties(parsed.Funcs[0].Instrs[1], arch)
					if !recognized || err != nil || form.byteWidth != width || form.memory != expected.memory ||
						form.mask != expected.mask || form.memoryWrite != expected.write || form.zeroing != expected.zero || form.spec != spec {
						t.Fatalf("%s %s changed axes: %+v / %v", arch, instruction, form, err)
					}
					// Each form needs its own entry. A terminal #UD must not hide
					// subsequent formats from actual LLVM object generation.
					function := fmt.Sprintf("moveform%d", len(sigs))
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", function, instruction)
					sigs[function] = FuncSig{Name: function, Ret: Void}
				}
			}
		}
		requireX86GoAssemblerResult(t, arch, source.String(), true)
		triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			ir := x86UnboundVoidVectorMoveFormatObject(t, source.String(), arch, triple)
			compileLLVMToObject(t, llc, triple, "packed-grammar.ll", "packed-grammar.o", ir)
		}
	}
}

func TestX86PackedMoveGrammarRejectsInvalidGoForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, instruction := range []string{
			"VMOVDQA Z0,Z1", "VMOVDQU X16,X0", "VMOVDQU X0,K1,X1", "VMOVDQA.Z X0,X1",
			"VMOVUPS X0,Y1", "VMOVUPD X0,K0,X1", "VMOVAPS.Z X0,X1",
			"VMOVDQU8 (AX),(BX)", "VMOVDQA32 $1,X0", "VMOVDQU16 X0,X1,K1,X2",
			"VMOVDQA64.BCST (AX),Z0", "VMOVUPS.SAE X0,X1", "VMOVDQU32.RN_SAE X0,X1",
		} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + instruction + "\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, false)
				parsed, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				_, recognized, err := amd64PackedVectorMoveProperties(parsed.Funcs[0].Instrs[1], arch)
				if !recognized || err == nil {
					t.Fatalf("invalid Go form accepted: %s %s", arch, instruction)
				}
			})
		}
	}
	for _, name := range []Op{"VMOVUPS.", "VMOVUPS.Z.Z"} {
		ins := Instr{Op: name, Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}}
		if _, _, err := amd64PackedVectorMoveProperties(ins, "amd64"); err == nil {
			t.Fatalf("malformed direct grammar suffix accepted: %s", name)
		}
	}
}

func TestX86PackedMoveDispatchBindsFamilyWithoutMutatingSource(t *testing.T) {
	for opcode := range amd64PackedVectorMoveSpecs {
		for _, arch := range []string{"amd64", "386"} {
			for _, identity := range []Op{"", opcode, Op(strings.ToLower(string(opcode)))} {
				instruction := Instr{Op: identity, Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}}
				registered := instruction
				registered.Op = opcode
				ctx, _ := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{registered}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				if recognized, terminated, err := ctx.lowerPackedVectorMove(opcode, instruction); !recognized || terminated || err != nil {
					t.Fatalf("%s %s identity=%q: %t/%t/%v", arch, opcode, identity, recognized, terminated, err)
				}
				if instruction.Op != identity {
					t.Fatal("internal opcode binding changed the original caller's instruction")
				}
			}
			for _, identity := range []Op{"MOVQ", "VMOVUPS.Z", "UNKNOWN"} {
				instruction := Instr{Op: identity, Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before := output.String()
				if _, _, err := ctx.lowerPackedVectorMove(opcode, instruction); err == nil || output.String() != before {
					t.Fatalf("%s %s contradictory identity=%q emitted IR or was accepted: %v", arch, opcode, identity, err)
				}
			}
		}
	}
}
