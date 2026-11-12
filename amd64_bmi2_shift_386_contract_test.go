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
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type x86BMI2Shift386Program struct {
	name, source, declaration, destination string
}

func x86BMI2Shift386Programs(t *testing.T, source, secondDestination string) []x86BMI2Shift386Program {
	t.Helper()
	parts := strings.Split(source, "TEXT ")
	if len(parts) != 25 || parts[0] != "" {
		t.Fatal("complete historical 24-TEXT inventory changed")
	}
	var programs []x86BMI2Shift386Program
	for index, part := range parts[1:] {
		name := fmt.Sprintf("shift386_%d", index)
		if !strings.HasPrefix(part, name+"(SB),4,$0-12\n") {
			t.Fatal("original TEXT order, frame or result extent changed", index)
		}
		destination := "CX"
		if index%2 != 0 {
			destination = secondDestination
		}
		programs = append(programs, x86BMI2Shift386Program{
			name: name, source: "TEXT " + part, destination: destination,
			declaration: fmt.Sprintf("func %s(count uint32,source *uint32) uint32\n", name),
		})
	}
	return programs
}

// These complete bytes are independent of the translator and raw decoder.
// In mode32 the Q spellings retain Go's W1 bytes, but hardware ignores W.
// The final 89 /r SIB 24 0c store is physically relative to the current ESP,
// even though the original source names the ABI0 result ret+8(FP).
func x86BMI2Shift386ExpectedCode(t *testing.T, index int, destination string) []byte {
	t.Helper()
	third := []byte{0x7a, 0xfa, 0x79, 0xf9, 0x7b, 0xfb}[index/4]
	register := map[string]byte{"CX": 1, "SP": 4, "DX": 2}[destination]
	if register == 0 {
		t.Fatal("unknown independent destination", destination)
	}
	code := []byte{0x8b, 0x44, 0x24, 4, 0x8b, 0x5c, 0x24, 8}
	code = append(code, 0xc4, 0xe2, third, 0xf7, register<<3|3)
	return append(code, 0x89, 0x44|register<<3, 0x24, 12, 0xc3)
}

func x86BMI2Shift386OriginalGoPrior(t *testing.T, source, secondDestination string) []x86BMI2Shift386Program {
	t.Helper()
	programs := x86BMI2Shift386Programs(t, source, secondDestination)
	listing := x86InsertExtractGoListing(t, "386", source)
	codes, instructions := map[string][]byte{}, map[string][]string{}
	owner := ""
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "STEXT" {
			owner = fields[0]
			if dot := strings.LastIndex(owner, "."); dot >= 0 {
				owner = owner[dot+1:]
			}
			if _, duplicate := codes[owner]; duplicate {
				t.Fatal("duplicate original Go TEXT owner", owner)
			}
			codes[owner] = nil
		}
		if chunk := x86InsertExtractListedBytes(line); len(chunk) != 0 {
			pc, err := strconv.ParseInt(fields[0], 0, 64)
			if owner == "" || err != nil || pc != int64(len(codes[owner])) {
				t.Fatal("unbound or noncontiguous original Go bytes", line, err)
			}
			codes[owner] = append(codes[owner], chunk...)
		}
		if row := goAMD64FrameRow.FindStringSubmatch(line); row != nil && !strings.HasPrefix(row[3], "TEXT") {
			instructions[owner] = append(instructions[owner], strings.Join(strings.Fields(row[3]), ""))
		}
	}
	if len(codes) != 24 {
		t.Fatal("original Go object lost a complete TEXT", len(codes))
	}
	for index, program := range programs {
		if !bytes.Equal(codes[program.name], x86BMI2Shift386ExpectedCode(t, index, program.destination)) {
			t.Fatalf("complete original Go bytes differ for %s (%s): %x", program.name, program.destination, codes[program.name])
		}
		rows := instructions[program.name]
		if len(rows) < 4 || rows[len(rows)-1] != "RET" {
			t.Fatal("original Go listing lost its real return", program.name, rows)
		}
		if index%4 < 2 && !strings.HasSuffix(rows[len(rows)-3], ","+program.destination) {
			t.Fatal("original named instruction no longer writes its physical destination", program.name, rows)
		}
	}
	t.Logf("actual complete original Go object: sourceSHA=%x, 24 functions; physical destination write, ESP+12 result store and RET bytes retained; no original program execution", sha256.Sum256([]byte(source)))
	return programs
}

func TestX86BMI2Shift386OriginalGoPhysicalSPAndReturnContract(t *testing.T) {
	source, _, _, _ := x86BMI2Shift386Fixture(t, "SP")
	programs := x86BMI2Shift386OriginalGoPrior(t, source, "SP")
	stack, ordinary := 0, 0
	for _, program := range programs {
		if program.destination == "SP" {
			stack++
		} else {
			ordinary++
		}
	}
	if stack != 12 || ordinary != 12 {
		t.Fatal("original SP and CX coverage changed", stack, ordinary)
	}
	// The first original C sample is value=0/count=0. Every shift writes ESP=0;
	// the next actual store targets address 12 and RET cannot recover the old PC.
	// This is a source/object witness, not a claim that the invalid ABI ran.
	if x86LogicalSourceFrameRegister(SP, "386") != true {
		t.Fatal("physical SP became an ordinary numerical source register")
	}
}

func TestX86BMI2Shift386OriginalSPStaysContextAndCXWorks(t *testing.T) {
	source, _, _, _ := x86BMI2Shift386Fixture(t, "SP")
	programs := x86BMI2Shift386OriginalGoPrior(t, source, "SP")
	var declarations strings.Builder
	for _, program := range programs {
		declarations.WriteString(program.declaration)
	}
	for _, target := range x86RawReturnTargets[:2] {
		t.Run(target.triple, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "386", target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("whole original source acquired an unproved physical stack return", err)
					}
					for _, program := range programs {
						t.Run(program.name, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, program.source, program.declaration, "386", target.triple, api)
							if program.destination == "SP" {
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("SP result replaced the physical ABI0 continuation with a virtual GP", err)
								}
							} else if err != nil || ir == "" {
								t.Fatal("same complete initialized CX program must remain supported", err)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86BMI2Shift386SafeGPCompanionCompleteObjects(t *testing.T) {
	source, signatures, cDeclarations, checks := x86BMI2Shift386Fixture(t, "DX")
	programs := x86BMI2Shift386OriginalGoPrior(t, source, "DX")
	_, originalSignatures, originalCDeclarations, originalChecks := x86BMI2Shift386Fixture(t, "SP")
	if !reflect.DeepEqual(signatures, originalSignatures) || cDeclarations != originalCDeclarations || checks != originalChecks || strings.Count(checks, "if (check(") != 24 {
		t.Fatal("safe GP companion changed original signatures, C calls or 24-kernel denominator")
	}
	var declarations strings.Builder
	for _, program := range programs {
		declarations.WriteString(program.declaration)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets[:2] {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "386", target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("explicit initialized GP companion did not close", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86PackedStringCompileObject(t, llc, target.triple, text, "-O0")
					}
				})
			}
		})
	}
}

func TestX86BMI2Shift386RequiredDriverChoosesSafeGPCompanion(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_bmi2_shift_cross_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixtures, driver, literals := 0, "", []string{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestCrossLinuxRuntimeMatrixBMI2Shift386" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "x86BMI2Shift386Fixture" && len(call.Args) == 2 {
					fixtures++
					if literal, ok := call.Args[1].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						driver, err = strconv.Unquote(literal.Value)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
				if name, ok := assignment.Lhs[0].(*ast.Ident); ok && name.Name == "mainC" {
					ast.Inspect(assignment.Rhs[0], func(node ast.Node) bool {
						if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
							value, err := strconv.Unquote(literal.Value)
							if err != nil {
								t.Fatal(err)
							}
							literals = append(literals, value)
						}
						return true
					})
				}
			}
			return true
		})
	}
	if len(literals) != 3 || fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(literals, "\x00")))) != "40eda8daa32e89f9f9c077d2cf2ef23e41331377a7fc44f5992c46e9e9228718" {
		t.Fatal("original complete C source, 256 samples or page-end/fault oracle changed")
	}
	if fixtures != 1 || driver != "DX" {
		t.Fatalf("required runtime must explicitly execute the safe CX/DX companion, not the original physical-SP source: fixtures=%d role=%q", fixtures, driver)
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "TestCrossLinuxRuntimeMatrix") {
		t.Fatal("safe companion lost the required complete cross-runtime owner", err)
	}
}
