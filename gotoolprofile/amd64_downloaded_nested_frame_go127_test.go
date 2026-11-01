//go:build go1.27

package gotoolprofile

import (
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

// A package is not its module root. The original archive must authenticate
// both, without copying the subpackage into a synthetic main module.
func TestAMD64DownloadedNestedFrameOriginalObjects(t *testing.T) {
	testAMD64DownloadedNestedFrameObjects(t, "fixed-local-nested")
}

func TestAMD64DownloadedLargeModuleOriginalObjects(t *testing.T) {
	for _, variant := range []string{"fixed-local-nested-large-archive", "fixed-local-nested-large-payload"} {
		t.Run(variant, func(t *testing.T) {
			testAMD64DownloadedNestedFrameObjects(t, variant)
		})
	}
}

func testAMD64DownloadedNestedFrameObjects(t *testing.T, variant string) {
	t.Helper()
	for _, target := range []struct{ goos, triple string }{
		{"linux", "x86_64-unknown-linux-gnu"},
		{"darwin", "x86_64-apple-darwin"},
		{"windows", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			request, pkg, capture := amd64DownloadedFramePublicFixture(t, variant)
			request.Target = target.goos + "/amd64"
			request.Environment = replaceEnv(request.Environment, map[string]string{"GOOS": target.goos})
			capture.Original.Target = request.Target
			capture.Original.Environment = request.Environment
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := captureAMD64DownloadedForTest(ctx, request, capture.SourceModule, capture.SourceVersion)
			if err != nil {
				t.Fatal("original Go subpackage must compile before the handoff", err)
			}
			defer func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			}()
			selected := observed.state.packages[request.PackagePath]
			if selected.Module == nil || selected.Module.Dir == selected.Dir || selected.Dir != request.Directory {
				t.Fatal("fixture did not retain distinct actual package/module identities")
			}
			sig, err := plan9asm.DeriveGoFuncABI0Signature(pkg.Path+".Value",
				pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(request.Directory, "value_amd64.s"))
			if err != nil {
				t.Fatal(err)
			}
			expanded := strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
			expanded = strings.Replace(expanded, "#include \"local.h\"", "#define ADVANCE 32", 1)
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			options := plan9asm.Options{Goarch: "amd64", TargetTriple: target.triple,
				ResolveSym: func(name string) string { return strings.Replace(name, "·", pkg.Path+".", 1) },
				Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig},
			}
			bound, binding, err := observed.BindDownloadedFixedLocal(ctx, pkg, file, "value_amd64.s", options)
			if err != nil || binding == nil {
				t.Fatal("actual original nested package lost its frame/object handoff", err)
			}
			fixture := amd64DownloadedLLVMFixture{request, capture.SourceModule, capture.SourceVersion,
				pkg, file, bound, expanded, observed, binding}
			llc := amd64DownloadedLLVM22Tool(t, ctx, fixture, "llc")
			for _, api := range []string{"Translate", "Module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir := fixture.ir(t, api)
					for _, level := range []string{"-O0", "-O2"} {
						fixture.object(t, ctx, llc, ir, level)
					}
				})
			}
			if err := binding.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			// Ancestor module bytes remain part of the live original archive,
			// even though they are not in the package's direct file inventory.
			metadata := filepath.Join(selected.Module.Dir, "go.mod")
			before, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(metadata, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadata, append(append([]byte(nil), before...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := binding.Verify(ctx); err == nil {
				t.Fatal("changed ancestor module retained its nested frame capability")
			}
			if err := os.WriteFile(metadata, before, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := plan9asm.Translate(file, bound); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("restoring ancestor metadata revived the revoked nested binding", err)
			}
		})
	}
}
