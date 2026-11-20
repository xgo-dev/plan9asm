package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86FMA3GrammarMatchesEveryCurrentGoTableMember(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]int)
	wanted := make(map[Op]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		if value, ok := node.(*ast.ValueSpec); ok && len(value.Names) == 1 && len(value.Values) == 1 {
			name := value.Names[0].Name
			if name == "_yvaddpd" || name == "_yvaddsd" {
				literal, ok := value.Values[0].(*ast.CompositeLit)
				if !ok {
					t.Fatalf("Go FMA3 grammar changed shape: %s", name)
				}
				rows[name] = len(literal.Elts)
			}
		}
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var opcode, table string
		for _, item := range literal.Elts {
			pair, ok := item.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, keyOK := pair.Key.(*ast.Ident)
			value, valueOK := pair.Value.(*ast.Ident)
			if !keyOK || !valueOK {
				continue
			}
			if key.Name == "as" {
				opcode = value.Name
			} else if key.Name == "ytab" {
				table = value.Name
			}
		}
		if strings.HasPrefix(opcode, "AVFM") || strings.HasPrefix(opcode, "AVFNM") {
			if table != "_yvaddpd" && table != "_yvaddsd" {
				t.Fatalf("Go FMA3 acquired an unreviewed grammar: %s/%s", opcode, table)
			}
			wanted[Op(strings.TrimPrefix(opcode, "A"))] = table == "_yvaddsd"
		}
		return true
	})
	if len(wanted) != 60 || !reflect.DeepEqual(rows, map[string]int{"_yvaddpd": 8, "_yvaddsd": 3}) {
		t.Fatalf("current Go FMA3 family changed: opcodes=%d rows=%v", len(wanted), rows)
	}
	named := 0
	for opcode, spec := range amd64FMA3Specs {
		if spec.rawOnly {
			if _, exists := wanted[opcode]; exists {
				t.Fatalf("raw-only opcode is now a Go named format: %s", opcode)
			}
			continue
		}
		scalar, exists := wanted[opcode]
		if !exists || scalar != spec.scalar {
			t.Fatalf("Go opcode omitted or changed: %s/%+v", opcode, spec)
		}
		named++
	}
	if named != len(wanted) {
		t.Fatalf("named family count mismatch: %d/%d", named, len(wanted))
	}
	x86FMA3CheckCompleteEncoderAttributes(t)
}

// Independent opcode enumeration and format axes. Every form has a separate
// entry, so an earlier trap/return cannot remove a later LLVM object witness.
func TestX86FMA3FixedRoundingDefaultArchitecture(t *testing.T) {
	const source = "TEXT defaultFMA(SB),4,$0-0\nVFMADD132SD.RD_SAE X0,X1,X2\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"defaultFMA": {Name: "defaultFMA", Ret: Void}},
	})
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("default-architecture format source invented its missing FMA inputs", err)
	}
	file, signatures := x86UnboundVoidFormatSource(t, source, "defaultFMA", "amd64", "x86_64-unknown-linux-gnu")
	ir = x86ScalarFormatObjectUnit(t, file, signatures, "amd64", "x86_64-unknown-linux-gnu", 0)
	llc, _, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "default-fma.ll", "default-fma.o", ir)
}

func x86FMA3NamedFormats(arch string) []string {
	var instructions []string
	ops := append(go127FMA3PackedOps(), go127FMA3ScalarOps()...)
	for _, opcode := range ops {
		scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
		banks := []string{"X", "Y", "Z"}
		if scalar {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"", "merge", "zero"} {
				if arch == "386" && mode != "" {
					continue
				}
				mask, zero := "", ""
				if mode != "" {
					mask = "K1,"
				}
				if mode == "zero" {
					zero = ".Z"
				}
				operands := bank + "0," + bank + "1," + mask + bank + "2"
				memory := "(AX)," + bank + "1," + mask + bank + "2"
				instructions = append(instructions, opcode+zero+" "+operands, opcode+zero+" "+memory)
				if !scalar {
					instructions = append(instructions, opcode+".BCST"+zero+" "+memory)
				}
				if scalar || bank == "Z" {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						instructions = append(instructions, opcode+"."+rounding+zero+" "+operands)
					}
				}
			}
		}
	}
	return instructions
}

func TestX86FMA3GrammarAxesActualGoAndFiveLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		sigs := make(map[string]FuncSig)
		for index, instruction := range x86FMA3NamedFormats(arch) {
			name := fmt.Sprintf("fmaformat%d", index)
			entry := fmt.Sprintf("TEXT %s(SB),4,$0-0\n%s\nRET\n", name, instruction)
			file, err := Parse(ArchAMD64, entry)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, recognized, err := amd64FMA3Properties(ins, arch)
			if err != nil || !recognized || form.spec.rawOnly || form.destination != len(ins.Args)-1 {
				t.Fatalf("%s %s: incomplete grammar %+v/%t/%v", arch, instruction, form, recognized, err)
			}
			if form.memory >= 0 {
				want := form.byteWidth
				if strings.Contains(instruction, ".BCST") || strings.HasSuffix(strings.Split(string(ins.Op), ".")[0], "SS") ||
					strings.HasSuffix(strings.Split(string(ins.Op), ".")[0], "SD") {
					want = 4
					if strings.Contains(string(ins.Op), "PD") || strings.Contains(string(ins.Op), "SD") {
						want = 8
					}
				}
				if form.memory != 0 || form.memoryBytes != want {
					t.Fatalf("%s changed native read extent: %+v; want %d", instruction, form, want)
				}
			}
			source.WriteString(entry)
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
		wanted := map[string]int{"amd64": 1836, "386": 612}[arch]
		if len(sigs) != wanted {
			t.Fatal("complete original FMA3 format denominator changed", arch, len(sigs), wanted)
		}
		requireX86GoAssemblerResult(t, arch, source.String(), true)
		triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			file, observed := x86UnboundVoidFormatSources(t, source.String(), arch, triple)
			if !reflect.DeepEqual(observed, sigs) {
				t.Fatal("complete original FMA format inventory changed its function signatures")
			}
			ir := x86ScalarFormatObjectUnit(t, file, sigs, arch, triple, 0)
			compileLLVMToObject(t, llc, triple, "fma-formats.ll", "fma-formats.o", ir)
		}
		t.Logf("%s: %d independently emitted original-Go format entries", arch, len(sigs))
	}
}

func TestX86FMA3DispatchPreservesOriginalSourceIdentity(t *testing.T) {
	for opcode, spec := range amd64FMA3Specs {
		for _, identity := range []Op{"", opcode, Op(strings.ToLower(string(opcode)))} {
			ins := Instr{Op: identity, x86Encoded: spec.rawOnly, Args: []Operand{
				{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"},
			}}
			original := ins
			ctx, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			recognized, terminated, err := ctx.lowerFMA3(opcode, ins)
			if !recognized || terminated || err != nil || !reflect.DeepEqual(ins, original) {
				t.Fatalf("%s/%s legacy dispatch changed source/failed: %t/%t/%v", opcode, identity, recognized, terminated, err)
			}
		}
		for _, conflict := range []Op{"VMOVUPS", "VFMADD132PS.BCST", opcode + ".Z"} {
			ins := Instr{Op: conflict, x86Encoded: spec.rawOnly, Args: []Operand{
				{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"},
			}}
			original := ins
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			before := output.String()
			recognized, _, err := ctx.lowerFMA3(opcode, ins)
			if !recognized || err == nil || output.String() != before || !reflect.DeepEqual(ins, original) {
				t.Fatalf("%s/%s conflicting dispatch changed source/emitted IR: %t/%v", opcode, conflict, recognized, err)
			}
		}
	}
}
