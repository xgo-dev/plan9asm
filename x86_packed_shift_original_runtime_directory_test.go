package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

type x86PackedShiftOriginalKernel struct {
	name, instruction, source string
	width, lane, operation    int
	mode, zero, oldCounts     int
	raw                       bool
	physical                  x86PackedShiftRawCase
}

// Keep the complete original 396-kernel protocol, including raw destination1
// aliasing the count input. Actual Go bytes are captured in one owned assembly
// invocation per partition, rather than launching 198 independent assemblers.
func x86PackedShiftOriginalRuntimeDirectory(t *testing.T, memberName string) []x86PackedShiftOriginalKernel {
	t.Helper()
	x86PackedShiftRawOriginalUnchanged(t)
	var kernels []x86PackedShiftOriginalKernel
	var originalInstructions strings.Builder
	index, rawRows := 0, 0
	for _, member := range x86PackedShiftRawMembers {
		if member.mode != "lane" {
			continue
		}
		operation := 0
		if strings.HasPrefix(member.op, "VPSRL") {
			operation = 1
		} else if strings.HasPrefix(member.op, "VPSRA") {
			operation = 2
		}
		for length, bank := range []string{"X", "Y", "Z"} {
			for mode := 0; mode < 5; mode++ {
				if mode == 4 && member.bits == 16 {
					continue
				}
				for _, zero := range []bool{false, true} {
					if zero && mode < 2 {
						continue
					}
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("shift%d", index)
						index++
						if memberName != "" && member.op != memberName {
							continue
						}
						input, suffix, mask, destination := "(BX)", "", "", 0
						row := x86PackedShiftRawCase{member: member, width: 16 << length, input: "memory"}
						if mode == 0 || mode == 2 {
							input, row.input = bank+"1", "register"
						}
						if mode == 4 {
							suffix, row.input = ".BCST", "broadcast"
						}
						if mode >= 2 {
							mask, row.mask = "K1,", 1
						}
						if zero {
							suffix, row.mask = suffix+".Z", 2
						}
						if raw {
							destination = 1
						}
						instruction := fmt.Sprintf("%s%s %s,%s0,%s%s%d", member.op, suffix, input, bank, mask, bank, destination)
						kernel := x86PackedShiftOriginalKernel{name: name, instruction: instruction,
							width: row.width, lane: member.bits / 8, operation: operation, mode: mode, raw: raw}
						if zero {
							kernel.zero = 1
						}
						if raw && (mode == 0 || mode == 2) {
							kernel.oldCounts = 1
						}
						row.evex = !member.vex || row.width == 64 || row.mask != 0 || row.input == "broadcast"
						kernel.physical = row
						kernels = append(kernels, kernel)
						if raw {
							originalInstructions.WriteString(instruction + "\n")
							rawRows++
						}
					}
				}
			}
		}
	}
	if index != 396 || len(kernels) == 0 || rawRows*2 != len(kernels) {
		t.Fatal("original complete named/raw partition denominator changed", index, len(kernels), rawRows)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", originalInstructions.String()+"RET")
	if len(pcs) != rawRows+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("actual original Go instructions/PC boundaries incomplete", len(pcs), rawRows)
	}
	rawIndex := 0
	for index := range kernels {
		kernel := &kernels[index]
		var source strings.Builder
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ data+0(FP),AX\nMOVQ counts+8(FP),BX\nMOVQ out+16(FP),DI\nVMOVUPS (AX),Z0\n", kernel.name)
		if kernel.mode == 0 || kernel.mode == 2 {
			source.WriteString("VMOVUPS (BX),Z1\n")
		} else if kernel.raw {
			source.WriteString("VMOVUPS (AX),Z1\n")
		}
		if kernel.mode >= 2 {
			source.WriteString("KMOVQ mask+24(FP),K1\n")
		}
		destination := 0
		if kernel.raw {
			destination = 1
			observed := code[pcs[rawIndex]:pcs[rawIndex+1]]
			rawIndex++
			independent := kernel.physical.code(false)
			modrm := 4
			if kernel.physical.evex {
				modrm = 5
			}
			independent[modrm] = independent[modrm]&^0x38 | 8 // Original destination1.
			if !bytes.Equal(observed, independent) {
				t.Fatal("actual Go bytes differ from the independent original raw kernel", kernel.name, kernel.instruction, observed, independent)
			}
			source.WriteString(x86RawDisplacementDirectives(observed))
		} else {
			source.WriteString(kernel.instruction + "\n")
		}
		fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\nRET\n", destination, destination, destination)
		kernel.source = source.String()
	}
	return kernels
}

func x86PackedShiftOriginalDeclarations(kernels []x86PackedShiftOriginalKernel, c bool) string {
	var declarations strings.Builder
	for _, kernel := range kernels {
		if c {
			fmt.Fprintf(&declarations, "extern void %s(const void*,const void*,void*,uint64_t);\n", kernel.name)
		} else {
			fmt.Fprintf(&declarations, "func %s(data,counts,out *byte,mask uint64)\n", kernel.name)
		}
	}
	return declarations.String()
}

// Evaluate only the original mainC string-concatenation AST. Every literal,
// lane/reference function and positive guard observation remains byte-for-byte
// original; only the partition's ordinary extern declarations are substituted.
func x86PackedShiftOriginalC(t *testing.T, declarations string) string {
	t.Helper()
	x86PackedShiftRawOriginalUnchanged(t)
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_raw_variable_shift_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var evaluate func(ast.Expr) string
	evaluate = func(expression ast.Expr) string {
		switch value := expression.(type) {
		case *ast.BasicLit:
			text, err := strconv.Unquote(value.Value)
			if value.Kind != token.STRING || err != nil {
				t.Fatal("original C lost its exact string literal", err)
			}
			return text
		case *ast.BinaryExpr:
			if value.Op == token.ADD {
				return evaluate(value.X) + evaluate(value.Y)
			}
		case *ast.Ident:
			if value.Name == "x86TestGuardPagesC" {
				return x86TestGuardPagesC
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if ok && len(value.Args) == 0 && selector.Sel.Name == "String" {
				if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "decl" {
					return declarations
				}
			}
		}
		t.Fatalf("unrecognized original C composition %T", expression)
		return ""
	}
	var result string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86VariableShiftMemoryAndViewsRuntime" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if ok && name.Name == "mainC" {
				if result != "" {
					t.Fatal("duplicate original complete C owner")
				}
				result = evaluate(assignment.Rhs[0])
			}
			return true
		})
	}
	if result == "" {
		t.Fatal("original complete C reference disappeared")
	}
	return result
}
