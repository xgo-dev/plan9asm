//go:build go1.27

package sdkfrontend

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
)

func TestSharedSDKNumericalOriginalNoDATAKeepsIndependentRoles(t *testing.T) {
	ctx, request := sdkMetadataOriginalRequest(t, "linux/amd64")
	request.Root = filepath.Dir(filepath.Dir(request.GoBinary))
	request.AssemblyFile = filepath.Join(request.Directory, "count_amd64.s")
	request.Package = &Package{Path: request.PackagePath}
	file, metadata, err := CaptureMetadata(ctx, request)
	if err != nil {
		t.Fatal("complete original source/object precondition", err)
	}
	t.Cleanup(func() {
		if err := metadata.Close(); err != nil {
			t.Error(err)
		}
	})
	if len(file.Funcs) != 3 || len(file.Data)+len(file.Globl) != 0 {
		t.Fatal("complete original count member changed")
	}
	actual, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal("an empty DATA inventory cannot require an initializer owner", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if !reflect.DeepEqual(file, actual) || source.literalOwner != nil || source.minimum != nil || source.minimumAttempted {
		t.Fatal("no-DATA numerical capture invented initializer/minimum or changed original nodes")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("actual independent numerical source not live", err)
	}
}

func TestSharedSDKNoDATACountText(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "count_amd64.s", "text")
}

func TestSharedSDKNoDATACountModule(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "count_amd64.s", "module")
}

func TestSharedSDKNoDATACountGoModule(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "count_amd64.s", "go-module")
}

func TestSharedSDKNoDATAIndexByteText(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "indexbyte_amd64.s", "text")
}

func TestSharedSDKNoDATAIndexByteModule(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "indexbyte_amd64.s", "module")
}

func TestSharedSDKNoDATAIndexByteGoModule(t *testing.T) {
	sharedSDKNoDATAOriginalOwner(t, "indexbyte_amd64.s", "go-module")
}

// Each complete member/API owns a fresh original producer deadline. Sharing
// this fixture must not share the live factory or its remaining budget.
func sharedSDKNoDATAOriginalOwner(t *testing.T, member, api string) {
	t.Helper()
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, "internal/bytealg", member)
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal("complete original no-DATA numerical source", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("original numerical/TEXT nodes did not bind", err)
	}
	var ir string
	switch api {
	case "text":
		ir, err = plan9asm.Translate(file, bound)
	case "module":
		context := llvm.NewContext()
		defer context.Dispose()
		module, translateErr := plan9asm.TranslateModuleInContext(context, file, bound)
		err = translateErr
		if !module.IsNil() {
			defer module.Dispose()
			ir = module.String()
		}
	case "go-module":
		original, readErr := os.ReadFile(request.AssemblyFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		translation, translateErr := plan9asm.TranslateGoModule(pkg, original,
			plan9asm.GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple,
				ResolveSym: bound.ResolveSym, FileName: member, NumericalReads: bound.NumericalReads})
		err = translateErr
		if translation != nil {
			defer translation.Module.Dispose()
			ir = translation.Module.String()
		}
	default:
		t.Fatal("unknown complete original API owner", api)
	}
	if err != nil || ir == "" {
		t.Fatal("complete original numerical continuation lost state/identity", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete original source owner changed after translation", err)
	}
}
