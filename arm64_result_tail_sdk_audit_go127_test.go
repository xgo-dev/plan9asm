//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Or32 is absent from Go 1.20. The cross-SDK first-party caller/ASM observation
// is untagged; this separate current-source root binds the real benchmark origin.
func TestARM64ABI0ResultTailCurrentSDKPublicBoundary(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual SDK source %s bytes=%d SHA256=%x", name, len(data), sha256.Sum256(data))
		return string(data)
	}
	goSource := read("internal/runtime/atomic/atomic_arm64.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), "atomic_arm64.go", goSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, node := range parsed.Decls {
		decl, ok := node.(*ast.FuncDecl)
		if !ok || decl.Name.Name != "Or32" {
			continue
		}
		count++
		if decl.Body != nil || decl.Recv != nil || decl.Type.Params == nil || decl.Type.Results == nil ||
			len(decl.Type.Params.List) != 2 || len(decl.Type.Results.List) != 1 {
			t.Fatal("actual Or32 bodyless ABI declaration changed")
		}
		pointer, ok := decl.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			t.Fatal("actual Or32 first parameter is no longer *uint32")
		}
		for _, typ := range []ast.Expr{pointer.X, decl.Type.Params.List[1].Type, decl.Type.Results.List[0].Type} {
			identifier, ok := typ.(*ast.Ident)
			if !ok || identifier.Name != "uint32" {
				t.Fatal("actual Or32 uint32 language identity changed")
			}
		}
	}
	if count != 1 {
		t.Fatalf("actual Or32 declaration count=%d, want one", count)
	}

	assembly := read("internal/runtime/atomic/atomic_arm64.s")
	start := strings.Index(assembly, "TEXT ·Or32(SB), NOSPLIT, $0-20\n")
	if start < 0 {
		t.Fatal("original Or32 TEXT/frame source changed")
	}
	body := assembly[start:]
	if next := strings.Index(body[1:], "\nTEXT "); next >= 0 {
		body = body[:next+1]
	}
	if strings.Count(body, "ret+16(FP)") != 2 ||
		!strings.Contains(body, "MOVD\tR2, ret+16(FP)") ||
		!strings.Contains(body, "MOVD R2, ret+16(FP)") {
		t.Fatal("both original Or32 paths must retain their native eight-byte result store")
	}
	t.Logf("original Or32 source, not a translated success:\n%s", body)

	linknames := read("internal/runtime/atomic/linkname.go")
	if strings.Count(linknames, "//go:linknamestd Or32\n") != 1 {
		t.Fatal("original public linkname boundary changed; re-audit caller closure")
	}
	callers := read("sync/atomic/asm.s")
	for _, name := range []string{"OrInt32", "OrUint32"} {
		start := strings.Index(callers, "TEXT ·"+name+"(SB),NOSPLIT,$0\n")
		if start < 0 {
			t.Fatalf("original assembly caller %s changed", name)
		}
		body := callers[start:]
		if next := strings.Index(body[1:], "\nTEXT "); next >= 0 {
			body = body[:next+1]
		}
		if strings.Count(body, "\tJMP\tinternal∕runtime∕atomic·Or32(SB)\n") != 1 {
			t.Fatalf("original %s no longer has its source-bound ASM tail caller", name)
		}
		t.Logf("original assembly entry remains outside a generated Go wrapper's closure:\n%s", body)
	}
}
