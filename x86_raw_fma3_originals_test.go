package plan9asm

import (
	"bytes"
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

func x86RawFMA3OriginalWeaviateSource(t *testing.T, evex bool) string {
	t.Helper()
	name, want := "TestTranslateRawVEXFMA3WeaviateRegression", "b1b467465fbfe860657c51db717516f4be905f166fbae74d3da6f6c375c906b6"
	if evex {
		name, want = "TestTranslateRawEVEXFMA3WeaviateRegression", "4b76cad69ad7c5d6269277dbdf85e52f0aa902eff23512f90ee9483687889ff1"
	}
	data, err := os.ReadFile("amd64_raw_vex_fma3_test.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "original-fma.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	var source string
	for _, declaration := range file.Decls {
		function, valid := declaration.(*ast.FuncDecl)
		if !valid || function.Name.Name != name {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			value, valid := node.(*ast.ValueSpec)
			if !valid || len(value.Names) != 1 || value.Names[0].Name != "source" || len(value.Values) != 1 {
				return true
			}
			literal, valid := value.Values[0].(*ast.BasicLit)
			if !valid || literal.Kind != token.STRING || source != "" {
				t.Fatal("original Weaviate source lost its single literal")
			}
			source, err = strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			return false
		})
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != want {
		t.Fatal("the complete original Weaviate assembly literal changed", name)
	}
	return source
}

func TestX86RawFMA3OriginalWeaviateInputsAndInitializedCounterparts(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, evex := range []bool{false, true} {
		source := x86RawFMA3OriginalWeaviateSource(t, evex)
		header, body, found := strings.Cut(source, "\n")
		if !found {
			t.Fatal("original complete source lost its TEXT")
		}
		name, registers, code := "rawFMA", []int{3, 4}, []byte{0xc4, 0xe2, 0x5d, 0x98, 0x1e, 0xc3}
		if evex {
			name, registers, code = "rawFMAEVEX", []int{1, 9}, []byte{0x62, 0xd2, 0x35, 0x48, 0xb8, 0xc9, 0xc3}
		}
		actual, _ := x86NumericalBoundaryGoBytes(t, "amd64", body)
		if !bytes.Equal(actual, code) {
			t.Fatal("original Weaviate bytes changed independently of the decoder", evex, actual, code)
		}
		var prefix strings.Builder
		prefix.WriteString(strings.Replace(header, "$0-0", "$0-8", 1) + "\nMOVQ p+0(FP),SI\nMOVQ p+0(FP),AX\n")
		for _, register := range registers {
			fmt.Fprintf(&prefix, "VMOVUPS (AX),Z%d\n", register)
		}
		initialized := prefix.String() + body
		for _, target := range x86RawReturnTargets {
			if target.arch != "amd64" {
				continue // The original EVEX literal physically uses bank9.
			}
			t.Run(fmt.Sprintf("EVEX=%t/%s", evex, target.triple), func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", target.triple, source)
				x86LEAActualTargetGoObject(t, "amd64", target.triple, initialized)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func "+name+"()", "amd64", target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unchanged bare original source acquired absent machine inputs", err)
						}
						ir, err := x86ScalarFPBitViewAPI(t, initialized, "func "+name+"(p *[128]byte)", "amd64", target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("independent complete original-byte counterpart must translate", err)
						}
						compileLLVMToObject(t, llc, target.triple, "weaviate-initialized.ll", "weaviate-initialized.o", ir)
					})
				}
			})
		}
	}
}

func x86RawFMA3InitializedRIPSource(initialized bool) (string, string) {
	var source, declarations strings.Builder
	for index, row := range x86RawFMA3ObjectCases()[:60] {
		width := 32
		if row.scalar() {
			width = 16
		} else if row.evex {
			width = 64
		}
		code := x86RawFMA3Literal(row.opcode, strings.HasSuffix(row.op, "D"), row.evex, width, row.evex && !row.scalar())
		fmt.Fprintf(&source, "TEXT ·LiteralFMA%d(SB),4,$0-8\n", index)
		fmt.Fprintf(&declarations, "func LiteralFMA%d(mask uint64)\n", index)
		if initialized {
			source.WriteString("KMOVW mask+0(FP),K7\nVPXORD Z0,Z0,Z0\n")
		}
		source.WriteString(x86RawDisplacementDirectives(code))
	}
	return source.String(), declarations.String()
}

func TestX86RawFMA3InitializedRIPWholeSourceAndRawReturn(t *testing.T) {
	source, declarations := x86RawFMA3InitializedRIPSource(true)
	file := mustParseX86RawReturn(t, source)
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil || len(normalized.Funcs) != 60 || len(normalized.Data) != 60 {
		t.Fatal("complete initialized RIP source lost original data or functions", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // These are original 64-bit RIP-relative encodings, not absolute mode32 addresses.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("valid original-byte RIP inputs and canonical raw RET must retain their existing complete roles", err)
					}
					compileLLVMToObject(t, llc, target.triple, "fma-rip-inputs.ll", "fma-rip-inputs.o", ir)
				})
			}
		})
	}
}

func TestX86RawFMA3RIPSourceCannotBorrowOldDestinationOrMask(t *testing.T) {
	source, declaration := x86RawFMA3InitializedRIPSource(true)
	for _, control := range []string{"old", "mask", "both"} {
		t.Run(control, func(t *testing.T) {
			changed := source
			if control != "mask" {
				changed = strings.ReplaceAll(changed, "VPXORD Z0,Z0,Z0\n", "")
			}
			if control != "old" {
				changed = strings.ReplaceAll(changed, "KMOVW mask+0(FP),K7\n", "")
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("a bound RIP DATA image/RET supplied absent old destination or mask", api, err)
				}
			}
		})
	}
}
