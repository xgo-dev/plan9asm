package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func x86PrivatePointerStackOriginalGFixture(t *testing.T) (string, string) {
	t.Helper()
	data, err := os.ReadFile("parser_g_register_test.go")
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "parser_g_register_test.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64GRegisterRuntime" {
			continue
		}
		start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
		const original = "f7a56465f74e14d6143079a0cf92ff4d373fa904b8f1812e7da8430bcc82b447"
		if fmt.Sprintf("%x", sha256.Sum256(data[start:end])) != original {
			t.Fatal("original g input, PUSH/POP, C reference or runtime observation changed")
		}
		constants := make(map[string]string)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				return true
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			constants[value.Names[0].Name] = text
			return true
		})
		if constants["source"] == "" || constants["mainC"] == "" {
			t.Fatal("original complete ASM/C fixture disappeared")
		}
		return constants["source"], constants["mainC"]
	}
	t.Fatal("original g runtime owner disappeared")
	return "", ""
}

func x86PrivatePointerStackRegisters(arch string) []string {
	registers := strings.Fields("AX CX DX BX SI DI")
	if arch == "386" {
		return append(registers, "BP") // Ordinary GP in mode32, never AMD64 frame BP.
	}
	return append(registers, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15 g")...)
}

func x86PrivatePointerStackProgram(arch, name, source, destination, body string) (string, string) {
	move, stack, word, result := "MOVQ", "Q", 8, "uint64"
	if arch == "386" {
		move, stack, word, result = "MOVL", "L", 4, "uint32"
	}
	if body == "" {
		body = fmt.Sprintf("PUSH%s %s\n%s $0,%s\nPOP%s %s\n", stack, source, move, source, stack, destination)
	}
	assembly := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),%s\n%s%s %d(%s),AX\n%s AX,ret+%d(FP)\nRET\n",
		name, 2*word, move, source, body, move, word, destination, move, word)
	return assembly, fmt.Sprintf("func %s(p *byte) %s\n", name, result)
}

func TestX86PrivatePointerStackOriginalGSourceThreeAPIs(t *testing.T) {
	source, _ := x86PrivatePointerStackOriginalGFixture(t)
	control := strings.Replace(source, "\tPUSHQ g\n\tMOVQ $0, g\n\tPOPQ g\n", "", 1)
	if control == source {
		t.Fatal("independent direct-pointer positive control did not change the original roundtrip")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, control, "func galias(input *byte) uint64", "amd64", triple, api); ir == "" || err != nil {
					t.Fatal("explicit Ptr-to-g direct-source control failed before private transport", err)
				}
				if ir, err := x86ScalarFPBitViewAPI(t, source, "func galias(input *byte) uint64", "amd64", triple, api); ir == "" || err != nil {
					t.Fatal("private full-word roundtrip lost an already established opaque incoming pointer", err)
				}
			})
		}
	}
}

func TestX86PrivatePointerStackCompleteGPSourceAndDestinationRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		registers := x86PrivatePointerStackRegisters(arch)
		for index, source := range registers {
			// All source and result banks, same and distinct destinations. The
			// ordered-role axis does not require another GP Cartesian product.
			for _, destination := range []string{source, registers[(index+1)%len(registers)]} {
				assembly, declaration := x86PrivatePointerStackProgram(arch, "Value", source, destination, "")
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+source+"-"+destination+"/"+api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, assembly, declaration, arch, triple, api); ir == "" || err != nil {
							t.Fatal("whole native-word opaque transport depends on a particular GP alias", err)
						}
					})
				}
			}
		}
	}
}

func TestX86PrivatePointerStackClosedCellsKeepCloneAndJoinRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			stack, word := "Q", int64(8)
			if arch == "386" {
				stack, word = "L", 4
			}
			bx, _, _ := x86ResultGP("BX", word, arch)
			ax, mask, _ := x86ResultGP("AX", word, arch)
			push, pop := x86ScalarLaneInstruction(t, "PUSH"+stack+" BX"), x86ScalarLaneInstruction(t, "POP"+stack+" AX")
			makeSaved := func(pointer bool) x86ResultState {
				state := x86ResultState{valueStack: new(x86ResultValueStack)}
				state.pointerGP[bx] = pointer
				state.callerAddressGP[bx] = true // Deliberately separate: the new tag must not transport it.
				if !pointer {
					state.gp[bx] = 0xff
				}
				if accepted, known := x86ResultValueStackStep(push, &state, nil, 0, arch); !known || !accepted {
					t.Fatal("ordinary full-word private PUSH control failed")
				}
				return state
			}
			for _, paired := range []bool{false, true} {
				left, right := makeSaved(true), makeSaved(paired)
				joined := left.intersect(right)
				if accepted, known := x86ResultValueStackStep(pop, &joined, nil, 0, arch); !known || !accepted || joined.pointerGP[ax] != paired {
					t.Fatal("private cell join invented or discarded a must-pointer role", paired)
				}
				if joined.callerAddressGP[ax] || paired && joined.gp[ax]&mask != 0 {
					t.Fatal("restoring opaque address bits invented numerical pointer bytes")
				}
				clone := left.clone()
				if accepted, known := x86ResultValueStackStep(pop, &clone, nil, 0, arch); !known || !accepted || !clone.pointerGP[ax] || len(left.valueStack.bytes) != int(word) {
					t.Fatal("mutable private POP corrupted the original saved cell or lost its role")
				}
			}
		})
	}
}

func TestX86PrivatePointerStackCannotInventAddressOrEntryAuthority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple, stack, move, word := "x86_64-unknown-linux-gnu", "Q", "MOVQ", 8
		if arch == "386" {
			triple, stack, move, word = "i386-unknown-linux-gnu", "L", "MOVL", 4
		}
		for _, row := range []struct{ name, body string }{
			{"unknown", "PUSH" + stack + " CX\nPOP" + stack + " BX\n"},
			{"numeric", move + " $1,CX\nPUSH" + stack + " CX\nPOP" + stack + " BX\n"},
			{"partial-pointer", "PUSHW BX\n" + move + " $0,BX\nPOPW BX\n"},
			{"flags-not-pointer", "PUSHF" + stack + "\nPOP" + stack + " BX\n"},
			{"pointer-as-numeric", "PUSH" + stack + " BX\nPOP" + stack + " AX\n" + move + " AX,ret+" + strconv.Itoa(word) + "(FP)\nRET\n"},
			{"physical-SP", "PUSH" + stack + " BX\nPOP" + stack + " SP\n"},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				assembly, declaration := x86PrivatePointerStackProgram(arch, "Value", "BX", "BX", row.body)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, assembly, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("private cells created a missing pointer, numerical result or physical stack contract", api, err)
					}
				}
			})
		}
	}
}

func TestX86PrivatePointerStackNestedMixedAndMutatedCells(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple, stack, move := "x86_64-unknown-linux-gnu", "Q", "MOVQ"
		if arch == "386" {
			triple, stack, move = "i386-unknown-linux-gnu", "L", "MOVL"
		}
		push, pop := "PUSH"+stack+" ", "POP"+stack+" "
		rows := []struct {
			name, body string
			accept     bool
		}{
			{"nested-whole", push + "BX\n" + push + "$7\n" + pop + "DX\n" + pop + "AX\n", true},
			{"nested-narrow", push + "BX\nPUSHW $9\nPOPW DX\n" + pop + "AX\n", true},
			{"partial-cell-recombined", push + "BX\nPOPW DX\nPUSHW $9\n" + pop + "AX\n", false},
			{"flags-roundtrip-is-not-pointer", push + "BX\nPOPF" + stack + "\nPUSHF" + stack + "\n" + pop + "AX\n", false},
		}
		branch := move + " $0,CX\nTESTL CX,CX\nJE alternate\n" + push + "BX\nJMP joined\nalternate:\n"
		rows = append(rows,
			struct {
				name, body string
				accept     bool
			}{"both-paths-pointer", branch + push + "BX\njoined:\n" + pop + "AX\n", true},
			struct {
				name, body string
				accept     bool
			}{"one-path-numeric", branch + push + "$1\njoined:\n" + pop + "AX\n", false})
		if arch == "386" {
			rows = append(rows, struct {
				name, body string
				accept     bool
			}{"private-byte-mutated", push + "BX\nXORL $1,(SP)\n" + pop + "AX\n", false})
		}
		for _, row := range rows {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					assembly, declaration := x86PrivatePointerStackProgram(arch, "Value", "BX", "AX", row.body)
					ir, err := x86ScalarFPBitViewAPI(t, assembly, declaration, arch, triple, api)
					if row.accept {
						if ir == "" || err != nil {
							t.Fatal("complete source-owned private pointer cell was lost", err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("partial, mutated or one-path cell invented a complete opaque pointer", err)
					}
				})
			}
		}
	}
}
