package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"testing"
)

// Executable payloads have their own immutable boundary, independently of the
// enclosing driver hash. The C literal includes every input and observation.
func x86PackedAbsSignOriginalPayloadHashes(data []byte) (map[string]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "original-abs-sign.go", data, 0)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string)
	functions := 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64PackedAbsSignRuntimeSemantics" {
			continue
		}
		functions++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "source" && name.Name != "mainC" {
				return true
			}
			literal, ok := assignment.Rhs[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || hashes[name.Name] != "" {
				err = fmt.Errorf("original ABS/sign payload lost its single literal: %s", name.Name)
				return false
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				err = unquoteErr
				return false
			}
			hashes[name.Name] = fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
			return false
		})
	}
	if err != nil {
		return nil, err
	}
	if functions != 1 || len(hashes) != 2 {
		return nil, fmt.Errorf("original ABS/sign runtime function or complete payload is absent")
	}
	return hashes, nil
}

func TestX86PackedAbsSignOriginalExecutablePayloadIdentity(t *testing.T) {
	data, err := os.ReadFile("amd64_lower_abs_sign_test.go")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"source": "2c3660ebcce2c3d76fcc556f987f5cddd480557965ad4005c41ef6f4749f9218",
		"mainC":  "b2867b9896c8afaab063d25ab65aeff74bd4ffa3645791febac92ec62fd19c60",
	}
	for _, mutation := range []struct{ name, from, to, changed string }{
		{"original", "", "", ""},
		{"assembly", "PABSB X0, X0", "PABSW X0, X0", "source"},
		{"C-input", "i * 29 + 0x80", "i * 31 + 0x80", "mainC"},
		{"C-observation", "gotAbs64[i] != want", "gotAbs64[i] == want", "mainC"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := data
			if mutation.changed != "" {
				changed = bytes.Replace(data, []byte(mutation.from), []byte(mutation.to), 1)
				if bytes.Equal(changed, data) {
					t.Fatal("payload mutation was not applied")
				}
			}
			hashes, err := x86PackedAbsSignOriginalPayloadHashes(changed)
			if err != nil {
				t.Fatal("payload mutation lost the complete parseable original driver", err)
			}
			for role, hash := range want {
				if (hashes[role] != hash) != (role == mutation.changed) {
					t.Fatal("independent original ASM/C boundary was lost", role, mutation.changed)
				}
			}
		})
	}
}
