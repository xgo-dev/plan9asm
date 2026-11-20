//go:build go1.27

package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

// The owned-only BindFixedLocal route must not gain downloaded authority.
// This test-only interface lets the missing independent route fail at runtime
// without adding a production stub or manufacturing a frame capability.
type amd64DownloadedFixedLocalIndependentBinder interface {
	BindDownloadedFixedLocal(
		context.Context,
		plan9asm.GoPackage,
		*plan9asm.File,
		string,
		plan9asm.Options,
	) (plan9asm.Options, *AMD64OriginalFixedLocalBinding, error)
}

// This generated file-proxy module is a first-party mechanism fixture, not a
// signed external module or an external runtime. The original cache directory
// and Go's actual cached-CWD module role are never copied or relabeled.
func TestAMD64DownloadedFixedLocalIndependentObjectHandoff(t *testing.T) {
	request, sourceModule, sourceVersion := amd64DownloadedObservationFixture(t, "fixed-local")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := captureAMD64DownloadedForTest(ctx, request, sourceModule, sourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	}()
	actual := observed.state.packages[request.PackagePath]
	if actual.Dir != request.Directory || actual.Module == nil || !actual.Module.Main ||
		actual.Module.Version != "" || observed.downloaded.primary.sourceModule != sourceModule ||
		observed.downloaded.primary.sourceVersion != sourceVersion ||
		!strings.HasSuffix(request.Directory, filepath.FromSlash(sourceModule+"@"+sourceVersion)) {
		t.Fatal("exact source identity or Go's actual cached-CWD role was lost")
	}
	set := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range actual.GoFiles {
		file, err := parser.ParseFile(set, filepath.Join(request.Directory, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check(request.PackagePath, set, syntax, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := plan9asm.DeriveGoFuncABI0Signature(request.PackagePath+".Value",
		typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	pkg := plan9asm.GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax}
	assembly, err := os.ReadFile(filepath.Join(request.Directory, "value_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	expanded := strings.Replace(string(assembly), "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
	expanded = strings.Replace(expanded, "#include \"local.h\"", "#define ADVANCE 32", 1)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
		Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig}}

	t.Run("OriginalGoObject", func(t *testing.T) {
		output, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
			"list", "-compiled", "-export", "-json", "-mod=readonly", ".")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual original export failed: %v\n%s%s", err, output, stderr)
		}
		decoder := json.NewDecoder(bytes.NewReader(output))
		var selected amd64OriginalListPackage
		var extra any
		if err := decoder.Decode(&selected); err != nil || decoder.Decode(&extra) != io.EOF ||
			!reflect.DeepEqual(selected, actual) || selected.Export == "" {
			t.Fatalf("actual original export/selection was not completely bound: %v", err)
		}
		t.Logf("ORIGINAL_GO_EXPORT_JSON\n%s", output)
		object := filepath.Join(t.TempDir(), "original.o")
		include := filepath.Join(observed.state.environment["GOROOT"], "pkg", "include")
		listing, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
			"tool", "asm", "-S", "-p", pkg.Path, "-I", request.Directory, "-I", include,
			"-o", object, "value_amd64.s")
		if err != nil || len(stderr) != 0 || !bytes.Contains(listing, []byte(pkg.Path+".Value STEXT")) ||
			!bytes.Contains(listing, []byte("PADDL")) {
			t.Fatalf("actual original ASM failed: %v\n%s%s", err, listing, stderr)
		}
		data, err := os.ReadFile(object)
		if err != nil || len(data) == 0 {
			t.Fatalf("actual original object missing: %v", err)
		}
		t.Logf("ORIGINAL_GO_LISTING\n%s\nORIGINAL_GO_OBJECT_HEX %s", listing, hex.EncodeToString(data))
		for _, name := range []string{"go.mod", "value.go", "value_amd64.s", "local.h"} {
			data, err := os.ReadFile(filepath.Join(request.Directory, name))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("ORIGINAL_SOURCE %s SHA256 %s\n%s", name, bytesSHA256(data), data)
		}
		prefix := filepath.Join(originalObservationEnvironment(request.Environment, "GOMODCACHE"),
			"cache", "download", sourceModule, "@v", sourceVersion)
		for _, suffix := range []string{".zip", ".mod", ".info"} {
			data, err := os.ReadFile(prefix + suffix)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("FIRST_PARTY_PROXY_ASSET %s%s bytes=%d SHA256=%s HEX=%s",
				sourceModule+"@"+sourceVersion, suffix, len(data), bytesSHA256(data), hex.EncodeToString(data))
		}
	})
	if t.Failed() {
		return // A failed Go control cannot certify the handoff counterexample.
	}
	t.Run("UnboundAPIs", func(t *testing.T) {
		amd64OriginalFixedLocalAPIs(t, pkg, file, options, expanded, true)
	})
	t.Run("OwnedFactoryRejectsDownloadedCWD", func(t *testing.T) {
		source, err := plan9asm.CaptureGoAMD64FrameSource(ctx, pkg, plan9asm.GoAMD64FrameCaptureRequest{
			GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "value_amd64.s",
			Target: request.Target, Environment: request.Environment,
		})
		if source != nil {
			if err := source.Close(); err != nil {
				t.Error(err)
			}
		}
		if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("actual downloaded CWD Main/empty-version was accepted by the owned public factory: %v", err)
		}
	})
	if err := observed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	t.Run("ActualObjectHandoff", func(t *testing.T) {
		handoff, exists := any(observed).(amd64DownloadedFixedLocalIndependentBinder)
		if !exists {
			t.Fatal("real original Go numeric frame compiled, but the separate BindDownloadedFixedLocal object handoff route is unimplemented")
		}
		bound, binding, err := handoff.BindDownloadedFixedLocal(ctx, pkg, file, "value_amd64.s", options)
		if binding != nil {
			defer func() {
				if err := binding.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		if errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("real original Go numeric frame compiled, but independent downloaded object handoff is unimplemented: %v", err)
		}
		if err != nil || binding == nil {
			t.Fatalf("actual object capture/binding failed: %v", err)
		}
		if err := binding.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		amd64OriginalFixedLocalAPIs(t, pkg, file, bound, expanded, false)
	})
}
