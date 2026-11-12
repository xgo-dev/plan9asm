//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Each negative replay starts with an actual successful, independently sealed
// authority. A foreign nonnil token must not be silently ignored by dispatch.
func TestNativeAuthorityARM64RejectsNumericalReadBinding(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			triple := "aarch64-unknown-linux-gnu"
			ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), triple, nil)
			if err != nil || ir == "" {
				t.Fatal("actual single-authority consumer precondition", err)
			}
			calls := 0
			resolve := testResolveSym(pkg.Path)
			ir, err = arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), triple,
				func(_ *File, options *Options, goOptions *GoModuleOptions) {
					foreign := &GoX86NumericalReadBinding{}
					options.NumericalReads, goOptions.NumericalReads = foreign, foreign
					callback := func(symbol string) string {
						calls++
						return resolve(symbol)
					}
					options.ResolveSym, goOptions.ResolveSym = callback, callback
				})
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || calls != 0 {
				t.Errorf("mixed native authorities reached callbacks or returned output: calls=%d error=%v", calls, err)
			}
			if !errors.Is(source.Verify(lease), ErrProbeNeedsContext) {
				t.Error("mixed-authority failure did not revoke the actual ARM64 source")
			}
		})
	}
}

func TestNativeAuthorityNumericalRejectsARM64Source(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg, file, unbound, create := numericalConsumerFactory(t, arch)
			for _, api := range []string{"text", "context", "go-module", "binding"} {
				t.Run(api, func(t *testing.T) {
					source, options := create(t)
					positiveAPI := api
					if api == "binding" {
						positiveAPI = "text"
					}
					if numericalFamilyTranslate(t, positiveAPI, pkg, file, options) == "" {
						t.Fatal("actual single-authority consumer returned no output")
					}
					calls := 0
					callback := func(symbol string) string {
						calls++
						return options.NumericalReads.resolve(symbol)
					}
					foreign := &GoARM64ByteCarrierSource{}
					mixed := options
					mixed.ARM64ByteCarrierSource, mixed.ResolveSym = foreign, callback
					context := llvm.NewContext()
					defer context.Dispose()
					var err error
					output := false
					switch api {
					case "text":
						var ir string
						ir, err = Translate(file, mixed)
						output = ir != ""
					case "context":
						var module llvm.Module
						module, err = TranslateModuleInContext(context, file, mixed)
						if !module.IsNil() {
							output = true
							module.Dispose()
						}
					case "go-module":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(context, pkg, numericalWrapperOriginal(t, source), GoModuleOptions{
							FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: arch,
							TargetTriple: options.TargetTriple, ResolveSym: callback,
							NumericalReads: options.NumericalReads, ARM64ByteCarrierSource: foreign,
						})
						if result != nil {
							output = true
							if !result.Module.IsNil() {
								result.Module.Dispose()
							}
						}
					case "binding":
						request := unbound
						request.ARM64ByteCarrierSource, request.ResolveSym = foreign, callback
						var result Options
						result, err = source.BindNumericalReads(options.NumericalReads.context, pkg, file, request)
						output = result.NumericalReads != nil
					}
					if !errors.Is(err, ErrProbeNeedsContext) || output || calls != 0 {
						t.Errorf("mixed native authorities reached callbacks or returned output: calls=%d error=%v", calls, err)
					}
					if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
						t.Error("mixed-authority failure did not revoke the actual numerical source")
					}
				})
			}
		})
	}
}

func TestNativeAuthorityNumericalPrivateSealRejectsARM64Source(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, _, _, create := numericalConsumerFactory(t, arch)
			source, options := create(t)
			binding := options.NumericalReads
			if err := binding.verify(); err != nil {
				t.Fatal("actual original numerical seal precondition", err)
			}
			binding.options.ARM64ByteCarrierSource = &GoARM64ByteCarrierSource{}
			if !errors.Is(binding.verify(), ErrProbeNeedsContext) {
				t.Error("private numerical seal silently retained a foreign ARM64 authority")
			}
			if !errors.Is(source.Verify(binding.context), ErrProbeNeedsContext) {
				t.Error("mixed private seal did not permanently revoke its numerical source")
			}
		})
	}
}
