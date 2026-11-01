package gostaticstorage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestX86SDKTargetExactProfiles(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "darwin/amd64", "windows/386", "windows/amd64"} {
		if !X86SDKTarget(target) {
			t.Fatalf("missing observed target grammar: %s", target)
		}
		compiler, assembly := uint32(16), uint32(20)
		if target == "darwin/amd64" {
			compiler, assembly = 17, 21
		}
		if sdkCompilerObjectFlags(target) != compiler || sdkAssemblyObjectFlags(target) != assembly {
			t.Fatalf("%s lost its exact compiler/assembler object flags", target)
		}
	}
	for _, target := range []string{"darwin/386", "freebsd/amd64", "linux/arm64", "windows/arm64", "js/wasm", "linux/amd64/", " linux/amd64"} {
		if X86SDKTarget(target) {
			t.Fatalf("unobserved x86 SDK target accepted: %q", target)
		}
	}
}

func TestSDKExternalFunctionDirectiveDoesNotSupplyVariableBacking(t *testing.T) {
	for _, test := range []struct {
		name, declaration string
		accepted          bool
	}{
		{"external", "//go:linknamestd callback\nfunc callback(value uint32) bool", true},
		{"variable", "//go:linknamestd callback\nvar callback uint32", false},
		{"implemented", "//go:linknamestd callback\nfunc callback(value uint32) bool { return false }", false},
		{"different-function", "//go:linknamestd callback\nfunc other(value uint32) bool", false},
		{"unattached", "//go:linknamestd callback\n\nfunc callback(value uint32) bool", false},
		{"method", "type Owner struct{}\n//go:linknamestd callback\nfunc (Owner) callback(value uint32) bool", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package fixture\n"+test.declaration, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			var directive *ast.Comment
			for _, group := range file.Comments {
				for _, comment := range group.List {
					if comment.Text == "//go:linknamestd callback" {
						directive = comment
					}
				}
			}
			if directive == nil || sdkExternalFunctionDirective(file, directive, "callback") != test.accepted {
				t.Fatal("directive does not retain its exact attached external-function role")
			}
		})
	}
}
