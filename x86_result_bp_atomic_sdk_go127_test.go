//go:build go1.27

package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86ResultMode32BPActualAtomicWholeSourceRemainsContext(t *testing.T) {
	proof, request := sdkASMDataRequest(t, "386", "internal/runtime/atomic")
	source, err := captureGoX86SDKASMDataSourceRole(proof, request, sdkASMDataOriginalSourceRole)
	if err != nil {
		t.Fatal("actual complete original atomic source observation", err)
	}
	defer source.Close()
	sdkASMDataDiagnosticRetainNamed(t, "-bp-complete-original", source)
	if len(source.observation.CPP) != 1 || len(source.observation.Objects.Sources) != 1 ||
		len(source.observation.Objects.Sources[0].Original.Texts) != 42 ||
		strings.Count(string(source.observation.ObjectInputs.Sources[0].Original), "\nTEXT ") != 42 {
		t.Fatal("the actual discovering file was cropped")
	}
	pkg, err := source.typedPackage("go1.27")
	if err != nil || len(pkg.SourceSelection.Assembly) != 1 {
		t.Fatal("actual selected typed source inventory differs", err)
	}
	var file *File
	for _, selected := range pkg.SourceSelection.Assembly {
		file = selected
	}
	if file == nil || len(file.Funcs) != 42 {
		t.Fatal("complete selected source TEXT inventory differs")
	}
	resolve := testResolveSym(pkg.Path)
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(proof); err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			published := false
			var failure error
			options := Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
			switch api {
			case "text":
				var ir string
				ir, failure = Translate(file, options)
				published = ir != ""
			case "module":
				var module llvm.Module
				module, failure = TranslateModuleInContext(ctx, file, options)
				published = !module.IsNil()
				if published {
					defer module.Dispose()
				}
			case "Go":
				module, err := translateGoModuleInContext(ctx, pkg, []byte(source.observation.CPP[0].Output), GoModuleOptions{
					GOARCH: "386", GOOS: "linux", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve,
				})
				failure = err
				published = module != nil
				if module != nil && !module.Module.IsNil() {
					defer module.Module.Dispose()
				}
			}
			if published || !errors.Is(failure, ErrProbeNeedsContext) ||
				!strings.Contains(failure.Error(), "tail callee needs its independent CALL contract") {
				t.Fatal("ordinary BP acquired terminal/native source authority", published, failure)
			}
			t.Log("complete original42TEXT source still Context, not a file/object/runtime pass:", failure)
		})
	}
	if err := source.Verify(proof); err != nil {
		t.Fatal("complete source selection/compiler inputs changed during the API replay", err)
	}
}
