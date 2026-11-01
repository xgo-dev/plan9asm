//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Retain the exact SDK source that exposed the benchmark regression. Extract
// only its original language declarations for this test package: that is not
// an SDK selection, linked frame, caller or pointee-extent capability.
func amd64MD5OriginalDataBPSource(t *testing.T) (string, GoPackage) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "crypto", "md5", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("original MD5 SDK source %s bytes=%d SHA256=%x", name, len(data), sha256.Sum256(data))
		return data
	}

	assembly := read("md5block_amd64.s")
	if got := fmt.Sprintf("%x", sha256.Sum256(assembly)); got != "36c7e14eaf58fd6bfc63a70c651dd36c6ab99421e1c455a3d203b15fd4ca4d81" {
		t.Fatal("the complete original MD5 source changed; re-audit rather than alter its BP/frame usage", got)
	}
	declarations := map[string]string{}
	for _, name := range []string{"md5.go", "md5block_decl.go"} {
		data := read(name)
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, name, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			selected := ""
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				if declaration.Name.Name == "block" && declaration.Body == nil && declaration.Recv == nil {
					selected = "block"
				}
			case *ast.GenDecl:
				if len(declaration.Specs) != 1 {
					continue
				}
				switch spec := declaration.Specs[0].(type) {
				case *ast.TypeSpec:
					if spec.Name.Name == "digest" {
						selected = "digest"
					}
				case *ast.ValueSpec:
					if len(spec.Names) == 1 && spec.Names[0].Name == "BlockSize" {
						selected = "BlockSize"
					}
				}
			}
			if selected != "" {
				if declarations[selected] != "" {
					t.Fatal("duplicate original MD5 declaration", selected)
				}
				declarations[selected] = string(data[positions.Position(declaration.Pos()).Offset:positions.Position(declaration.End()).Offset])
			}
		}
	}
	var goSource strings.Builder
	goSource.WriteString("package md5\n")
	for _, name := range []string{"BlockSize", "digest", "block"} {
		if declarations[name] == "" {
			t.Fatal("missing original MD5 declaration", name)
		}
		goSource.WriteString(declarations[name] + "\n")
	}
	if declarations["block"] != "func block(dig *digest, p []byte)" || declarations["BlockSize"] != "const BlockSize = 64" {
		t.Fatal("actual original MD5 ABI or block-size declaration changed")
	}
	return string(assembly), mustGoPackage(t, "crypto/md5", goSource.String())
}

func TestAMD64MD5OriginalDataBPSourceObjectsThreeAPIs(t *testing.T) {
	source, pkg := amd64MD5OriginalDataBPSource(t)
	for _, triple := range []string{
		"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatalf("complete original MD5 initialized data BP is not closed: %v", err)
					}
				})
			}
		})
	}
}
