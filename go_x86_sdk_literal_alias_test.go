package plan9asm

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestGoX86SDKLiteralCompleteOriginalMOVQAliases(t *testing.T) {
	registration, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[Op]Op)
	functions := 0
	for _, declaration := range registration.Decls {
		function, valid := declaration.(*ast.FuncDecl)
		if !valid || function.Name.Name != "archX86" {
			continue
		}
		functions++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, valid := node.(*ast.AssignStmt)
			if !valid || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			selector, valid := assignment.Rhs[0].(*ast.SelectorExpr)
			if !valid || selector.Sel.Name != "AMOVQ" {
				return true
			}
			index, indexed := assignment.Lhs[0].(*ast.IndexExpr)
			owner, owned := selector.X.(*ast.Ident)
			if !indexed || !owned || owner.Name != "x86" {
				t.Fatal("unknown original MOVQ source registration")
			}
			bank, registered := index.X.(*ast.Ident)
			literal, named := index.Index.(*ast.BasicLit)
			if !registered || bank.Name != "instructions" || !named || literal.Kind != token.STRING {
				t.Fatal("unknown original MOVQ source alias name")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil || actual[Op(name)] != "" {
				t.Fatal("duplicate or unbound original MOVQ alias", name, err)
			}
			actual[Op(name)] = "MOVQ"
			return true
		})
	}
	if functions != 1 || !reflect.DeepEqual(actual, x86GoMOVQSourceAliases) || !reflect.DeepEqual(actual, map[Op]Op{"MOVD": "MOVQ", "MOVDQ2Q": "MOVQ"}) {
		t.Fatal("complete Go MOVQ source registrations changed", actual)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, operands := range []string{"$numericTable<>(SB),BX", "BX,DX", "AX,CX", "numericTable<>(SB)(CX*8),X0"} {
			accepted := arch == "amd64" && operands != "numericTable<>(SB)(CX*8),X0" || arch == "386" && operands == "numericTable<>(SB)(CX*8),X0"
			for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
				t.Run(arch+"/"+alias+"/"+operands, func(t *testing.T) {
					source := "TEXT native(SB),4,$0-0\n" + alias + " " + operands + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", accepted)
					if accepted {
						canonical := strings.Replace(source, alias+" ", "MOVQ ", 1)
						if !bytes.Equal(x86OrderingHintGoBytes(t, arch, source), x86OrderingHintGoBytes(t, arch, canonical)) {
							t.Fatal("original private/address/register alias bytes differ from Go MOVQ")
						}
					}
				})
			}
		}
	}
}

func TestGoX86SDKLiteralAliasesPreserveAddressCopiesAndIndices(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		for name, body := range map[string]string{
			"materialization": strings.Replace(x86SDKLiteralBoundedFixture, "MOVQ $numericTable<>(SB),BX", alias+" $numericTable<>(SB),BX", 1),
			"pointer copy":    strings.Replace(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", alias+" BX,DX\nMOVOU (DX)(AX*8),X0", 1),
			"index copy":      strings.Replace(strings.Replace(x86SDKLiteralBoundedFixture, "ADDQ AX,AX", alias+" AX,CX\nADDQ CX,CX", 1), "(AX*8)", "(CX*8)", 1),
			"read":            strings.Replace(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", alias+" (BX)(AX*8),X0", 1),
			"unwritten index": strings.Replace(x86SDKLiteralBoundedFixture, "ADDQ AX,AX", alias+" AX,X0\nADDQ AX,AX", 1),
		} {
			t.Run(alias+"/"+name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, body)
				if err != nil {
					t.Fatal(err)
				}
				original := append([]Instr(nil), file.Funcs[0].Instrs...)
				sig := FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64}, Ret: I64}
				facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericTable<>": 256})
				width := int64(16)
				if name == "read" {
					width = 8
				}
				if err != nil || len(facts) != 2 || !facts[0].Address || facts[1].Address || facts[1].Minimum != 0 || facts[1].Maximum != 240 || facts[1].Width != width {
					t.Fatal("complete Go alias lost its bounded literal address/read class", facts, err)
				}
				if !reflect.DeepEqual(original, file.Funcs[0].Instrs) {
					t.Fatal("local alias dispatch rewrote original source Op/Raw")
				}
				for _, fact := range facts {
					if !reflect.DeepEqual(fact.Original, original[fact.Instruction]) {
						t.Fatal("literal fact seals a canonical replacement, not the original source")
					}
				}
			})
		}
	}
}

func TestGoX86SDKLiteralAliasesCannotGrantRawOrMode32Pointers(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-0\n"+alias+" $numericTable<>(SB),BX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, valid := x86SDKLiteralOperandProperties(file.Funcs[0].Instrs[1], 0, "386"); valid {
			t.Fatal("Go's pre-Pw8 mode32 alias rows granted a full-word GP pointer", alias)
		}
		for _, mark := range []func(*Instr){
			func(ins *Instr) { ins.x86Encoded = true },
			func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{} },
		} {
			original := file.Funcs[0]
			original.Instrs = append([]Instr(nil), original.Instrs...)
			mark(&original.Instrs[1])
			facts, err := proveX86SDKLiteralAccesses(original, FuncSig{Name: "example.invalid/tableowner.entry", Ret: Void}, "amd64", map[string]int64{"numericTable<>": 256})
			if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a source alias changed raw/native origin into literal authority", alias, facts, err)
			}
		}
	}
}

func TestGoX86SDKLiteralAliasesMode32BoundedReadonlyRead(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		body := "MOVL n+0(FP),CX\nCMPL CX,$16\nJAE done\nADDL CX,CX\n" + alias +
			" numericTable<>(SB)(CX*8),X0\ndone:\nMOVL $0,ret0+4(FP)\nRET"
		_, file, sig, source := x86ResultInitializationFixture(t, "386", "func Value(n uint32) uint32", body)
		goAssemblerOracleOutput(t, "386", source, "", true)
		facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "386", map[string]int64{"numericTable<>": 256})
		if err != nil || len(facts) != 1 || facts[0].Address || facts[0].Minimum != 0 || facts[0].Maximum != 240 || facts[0].Width != 8 || facts[0].Original.Op != Op(alias) {
			t.Fatal("mode32 source alias lost its actual pre-Pw8 bounded XMM memory row", alias, facts, err)
		}
	}
}

func TestGoX86SDKLiteralRawBeforeMaterializationRemainsContext(t *testing.T) {
	for _, directive := range []string{"BYTE", "WORD", "LONG", "QUAD"} {
		file, err := Parse(ArchAMD64, "TEXT ·entry<ABIInternal>(SB),4,$0-0\n"+directive+" $0x90\nMOVQ $numericTable<>(SB),BX\nMOVQ (BX),AX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], FuncSig{Name: "example.invalid/tableowner.entry", Ret: I64}, "amd64", map[string]int64{"numericTable<>": 256})
		if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("raw source before a literal carrier escaped the separate native CFG contract", directive, facts, err)
		}
	}
}

func TestGoX86SDKLiteralAliasesRetainIndependentContracts(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		for _, alteration := range []struct{ before, after string }{
			{"CMPQ AX,$16\nJAE done\n", ""},
			{"JAE done", "MOVQ $32,AX\nJAE done"},
			{"MOVOU (BX)(AX*8),X0", "MOVOU X0,(BX)(AX*8)"},
			{"MOVOU (BX)(AX*8),X0", alias + " BX,X0"},
			{"MOVOU (BX)(AX*8),X0", "MOVB $0,BL\nMOVOU (BX)(AX*8),X0"},
			{"MOVOU (BX)(AX*8),X0", "TESTQ $15,BX"},
			{"MOVQ X0,AX", alias + " BX,AX"},
		} {
			body := strings.Replace(x86SDKLiteralBoundedFixture, "MOVQ $numericTable<>(SB),BX", alias+" $numericTable<>(SB),BX", 1)
			body = strings.Replace(body, alteration.before, alteration.after, 1)
			file, err := Parse(ArchAMD64, body)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64}, Ret: I64}, "amd64", map[string]int64{"numericTable<>": 256})
			if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("MOVQ source alias granted another pointer/index/FLAGS/address-bit contract", alias, body, facts, err)
			}
		}
	}
}
