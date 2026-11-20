package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64BytealgCountSDKTranslate(t *testing.T, pkg GoPackage, source []byte, target, api string) (string, error) {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	if api == "GoModule" {
		translated, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
		})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return translated.Module.String(), nil
	}
	file, err := Parse(ArchARM64, string(source))
	if err != nil {
		return "", err
	}
	sigs := make(map[string]FuncSig)
	for _, name := range []string{"Count", "CountString"} {
		function, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			return "", fmt.Errorf("missing actual SDK Count declaration: %s", name)
		}
		sig, err := DeriveGoFuncABI0Signature(name, function, "arm64", types.SizesFor("gc", "arm64"))
		if err != nil {
			return "", err
		}
		for _, root := range file.Funcs {
			if resolve(root.Sym) == name && strings.HasSuffix(root.Sym, "<ABIInternal>") {
				sig.ARM64GoRegisterABI, err = DeriveARM64GoRegisterABI(function, sig)
				if err != nil {
					return "", err
				}
			}
		}
		sigs[name] = sig
	}
	sigs, err = BindGoARM64ABI0TailDeclarations(pkg, file, resolve, sigs)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		return Translate(file, options)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return module.String(), nil
}

func TestARM64BytealgCountSDKSourceAllAPIsObjects(t *testing.T) {
	pkg := arm64BytealgCountSDKPackage(t)
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "internal", "bytealg", "count_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
	} {
		t.Run(target, func(t *testing.T) {
			var reference string
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64BytealgCountSDKTranslate(t, pkg, source, target, api)
					if err != nil {
						t.Fatal(err)
					}
					canonical := indirectMarkerComparableIR(ir)
					if reference != "" && canonical != reference {
						t.Fatal("three public APIs changed the original SDK Count source semantics")
					}
					reference = canonical
					compileLLVMToObject(t, llc, target, "sdk-count.ll", "sdk-count.o", ir)
				})
			}
		})
	}
}

func TestARM64BytealgCountSDKSourceBindingRejectsCopiedInventory(t *testing.T) {
	pkg := arm64BytealgCountSDKPackage(t)
	// First-party ABI0 continuation with the actual SDK Count declaration.
	// It is an object/source-identity fixture, not an alternative Count oracle.
	const source = `TEXT ·Count(SB),516,$0-40
MOVD b_len+8(FP),R11
MOVD $ret+32(FP),R8
B countresult<>(SB)
TEXT countresult<>(SB),516,$0
MOVD R11,(R8)
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	for _, axis := range []string{"missing selection", "copied declaration", "changed source bytes", "empty source inventory"} {
		t.Run(axis, func(t *testing.T) {
			changed := pkg
			selection := *pkg.SourceSelection
			selection.GoSources = make(map[string][]byte)
			for name, data := range pkg.SourceSelection.GoSources {
				selection.GoSources[name] = append([]byte(nil), data...)
			}
			changed.SourceSelection = &selection
			switch axis {
			case "missing selection":
				changed.SourceSelection = nil
			case "copied declaration":
				changed = mustGoPackage(t, pkg.Path, "package bytealg\nfunc Count(b []byte,c byte) int\nfunc CountString(s string,c byte) int\n")
			case "changed source bytes":
				for name := range selection.GoSources {
					if filepath.Base(name) == "count_native.go" {
						selection.GoSources[name] = []byte(strings.Replace(string(selection.GoSources[name]), "func Count(b", "func Other(b", 1))
					}
				}
			case "empty source inventory":
				selection.SelectedGoFiles = nil
				selection.GoSources = map[string][]byte{}
			}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64BytealgCountSDKTranslate(t, changed, []byte(source), "aarch64-unknown-linux-gnu", api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("invented SDK declaration/source input acquired ABI0 continuation permission: %v", err)
					}
				})
			}
		})
	}
	if ir, err := arm64BytealgCountSDKTranslate(t, pkg, []byte(source), "aarch64-unknown-linux-gnu", "GoModule"); err != nil || ir == "" {
		t.Fatalf("same unmodified actual SDK declaration/source control failed: %v", err)
	}
}
