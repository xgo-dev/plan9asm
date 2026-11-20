//go:build go1.27

package plan9asm

import (
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Each owner retains the complete original selected Go/import/compiler graph
// and all three unchanged assembly TEXTs. A private helper receives no fake
// declaration or signature. This tests declaration association, not native
// entry transport, closure storage, a complete translation or execution.
func numericalSDKForeignDeclarationAssociation(t *testing.T, member string) {
	t.Helper()
	ctx, request, metadata, _ := numericalSDKAssemblyFixture(t)
	request.AssemblyFile = member
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("complete original compiler/source/CPU observation", err)
	}
	defer closeNumericalConsumerSource(t, source)
	pkg, file, options := numericalSDKOriginalTypedPackage(t, metadata, member)
	if len(file.Funcs) != 3 || len(file.Data) != 0 || len(file.Globl) != 0 || len(source.reads) != 1 {
		t.Fatal("original complete member or exact CPU-read inventory changed")
	}
	sizes := types.SizesFor("gc", "amd64")
	options.Sigs, err = goSigsForAsmFile(pkg, file, options.ResolveSym, "amd64", sizes, sizes, nil)
	if err != nil || len(options.Sigs) != 2 {
		t.Fatal("actual two bodyless declarations/private helper inventory", err)
	}
	before, err := x86CallerSourceFingerprint(file)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil || bound.NumericalReads == nil {
		t.Fatal("complete original local declaration/foreign TEXT association", err)
	}
	after, err := x86CallerSourceFingerprint(file)
	if err != nil || before != after {
		t.Fatal("declaration association replaced an original TEXT or instruction", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete original declaration/source observation no longer live", err)
	}
	if err := metadata.Verify(ctx); err != nil {
		t.Fatal("association changed the borrowed whole compiler observation", err)
	}
}

func TestGoX86SDKNumericalEqualForeignDeclarationAssociation(t *testing.T) {
	numericalSDKForeignDeclarationAssociation(t, "equal_amd64.s")
}

func TestGoX86SDKNumericalCompareForeignDeclarationAssociation(t *testing.T) {
	numericalSDKForeignDeclarationAssociation(t, "compare_amd64.s")
}

func TestGoX86SDKNumericalForeignCompilerAssociationLiveSeal(t *testing.T) {
	for _, mutation := range []string{"witness", "symabi", "header-object", "selected-object-flags"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, request, metadata, _ := numericalSDKAssemblyFixture(t)
			request.AssemblyFile = "equal_amd64.s"
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeNumericalConsumerSource(t, source)
			pkg, file, options := numericalSDKOriginalTypedPackage(t, metadata, request.AssemblyFile)
			sizes := types.SizesFor("gc", "amd64")
			options.Sigs, err = goSigsForAsmFile(pkg, file, options.ResolveSym, "amd64", sizes, sizes, nil)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := source.BindNumericalReads(ctx, pkg, file, options)
			if err != nil || len(source.native.CompilerAliases) != 2 {
				t.Fatal("complete compiler association precondition", err)
			}
			for name := range numericalCompilerAliasSchema {
				if _, sealed := source.guard.inputs[filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(name))]; !sealed {
					t.Fatal("selected compiler schema source was not live sealed", name)
				}
			}
			original, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
			if err != nil {
				t.Fatal(err)
			}
			var restore func()
			switch mutation {
			case "witness":
				before := source.native.CompilerAliases["runtime.memequal"]
				delete(source.native.CompilerAliases, "runtime.memequal")
				restore = func() { source.native.CompilerAliases["runtime.memequal"] = before }
			case "symabi", "header-object":
				data := metadata.observation.Header.SymABI
				if mutation == "header-object" {
					data = metadata.observation.Header.CompilerObject
				}
				before := data[0]
				data[0] ^= 1
				restore = func() { data[0] = before }
			case "selected-object-flags":
				text := &source.native.ArchiveMembers[1].Texts[0]
				before := text.Flags2
				text.Flags2 ^= 16
				restore = func() { text.Flags2 = before }
			}
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("mutated source/compiler association stayed live", err)
			}
			restore()
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("restoring bytes revived a revoked compiler association", err)
			}
			if ir, err := Translate(file, bound); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("old text options survived compiler association revocation", err)
			}
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := TranslateModuleInContext(context, file, bound)
			if !module.IsNil() {
				module.Dispose()
				t.Fatal("revoked compiler association published a module")
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("old module options survived compiler association revocation", err)
			}
			translated, err := translateGoModuleInContext(context, pkg, original, GoModuleOptions{
				GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple,
				FileName: request.AssemblyFile, ResolveSym: bound.ResolveSym, NumericalReads: bound.NumericalReads,
			})
			if translated != nil {
				if !translated.Module.IsNil() {
					translated.Module.Dispose()
				}
				t.Fatal("revoked compiler association published a Go module")
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("old Go options survived compiler association revocation", err)
			}
		})
	}
}
