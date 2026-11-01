//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sdkAMD64FrameActualPackage(t *testing.T, source *GoX86SDKASMDataSource) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range source.guard.selection.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(source.request.Directory, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	actualImports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if mapped, found := source.guard.selection.ImportMap[path]; found {
			path = mapped
		}
		dependency, found := source.guard.imports[path]
		if !found || dependency.Export == "" {
			return nil, fmt.Errorf("missing actual SDK export: %s", path)
		}
		return os.Open(dependency.Export)
	})
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64"), Importer: actualImports, GoVersion: "go1.27"}).Check(source.request.PackagePath, fset, syntax, nil)
	if err != nil {
		t.Fatal("independent complete original SDK Go package", err)
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax}
}

func TestGoAMD64FrameOriginalSDKSourceObservation(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "vendor/golang.org/x/crypto/chacha20poly1305")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("complete actual SDK source/header/CPP/native frame observation", err)
	}
	defer observed.Close()
	data := observed.source
	const assembly = "chacha20poly1305_amd64.s"
	pkg := sdkAMD64FrameActualPackage(t, data)
	declarations, err := data.guard.typedDeclarations(pkg, false)
	if err != nil || len(declarations) != 2 || len(data.observation.Frames[0].Records) != 3 {
		t.Fatal("private helper invented a Go declaration or complete Go/ASM scope was cropped", err)
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal("live complete SDK-primary source", err)
	}
	frame, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: assembly,
		Target: request.Target, Environment: request.Environment,
	})
	if frame != nil {
		frame.Close()
	}
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "SDK/cache") {
		t.Fatal("query-only SDK observation acquired an ordinary owned-main frame role", err)
	}
	input := data.observation.ObjectInputs.Sources[0]
	actual, err := os.ReadFile(filepath.Join(request.Directory, assembly))
	if err != nil || !bytes.Equal(actual, input.Original) {
		t.Fatal("SDK role manufactured or rewrote a source fixture", err)
	}
}
