//go:build go1.27

package gotoolprofile

import (
	"context"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
)

type amd64DownloadedLLVMFixture struct {
	request               AMD64OriginalObservationRequest
	sourceModule, version string
	pkg                   plan9asm.GoPackage
	file                  *plan9asm.File
	options               plan9asm.Options
	assembly              string
	observed              *AMD64OriginalPackageObservation
	binding               *AMD64OriginalFixedLocalBinding
}

func captureAMD64DownloadedLLVMFixture(t *testing.T, ctx context.Context, goos, triple string) amd64DownloadedLLVMFixture {
	t.Helper()
	return captureAMD64DownloadedLLVMVariantFixture(t, ctx, goos, triple, "fixed-local")
}

func captureAMD64DownloadedLLVMVariantFixture(t *testing.T, ctx context.Context, goos, triple, variant string) amd64DownloadedLLVMFixture {
	t.Helper()
	request, pkg, exact := amd64DownloadedFramePublicFixture(t, variant)
	request.Target = goos + "/amd64"
	request.Environment = replaceEnv(request.Environment, map[string]string{"GOOS": goos})
	observed, err := captureAMD64DownloadedForTest(ctx, request, exact.SourceModule, exact.SourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	})
	sig, err := plan9asm.DeriveGoFuncABI0Signature(pkg.Path+".Value",
		pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(request.Directory, "value_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	expanded := strings.Replace(string(actual), "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
	expanded = strings.Replace(expanded, "#include \"local.h\"", "#define ADVANCE 32", 1)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: triple,
		ResolveSym: func(name string) string { return strings.Replace(name, "·", pkg.Path+".", 1) },
		Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig},
	}
	bound, binding, err := observed.BindDownloadedFixedLocal(ctx, pkg, file, "value_amd64.s", options)
	if err != nil || binding == nil {
		t.Fatal("actual exact downloaded object binding failed", err)
	}
	t.Cleanup(func() {
		if err := binding.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := binding.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	return amd64DownloadedLLVMFixture{request, exact.SourceModule, exact.SourceVersion,
		pkg, file, bound, expanded, observed, binding}
}

func (fixture amd64DownloadedLLVMFixture) ir(t *testing.T, api string) string {
	t.Helper()
	var ir string
	var err error
	switch api {
	case "Translate":
		ir, err = plan9asm.Translate(fixture.file, fixture.options)
	case "Module":
		context := llvm.NewContext()
		defer context.Dispose()
		module, translateErr := plan9asm.TranslateModuleInContext(context, fixture.file, fixture.options)
		err = translateErr
		if !module.IsNil() {
			defer module.Dispose()
			ir = module.String()
		}
	case "GoModule":
		module, translateErr := plan9asm.TranslateGoModule(fixture.pkg, []byte(fixture.assembly), plan9asm.GoModuleOptions{
			GOOS: strings.Split(fixture.request.Target, "/")[0], GOARCH: "amd64",
			TargetTriple: fixture.options.TargetTriple, ResolveSym: fixture.options.ResolveSym,
			Sizes: types.SizesFor("gc", "amd64"),
			ManualSig: func(name string) (plan9asm.FuncSig, bool) {
				sig, found := fixture.options.Sigs[name]
				return sig, found
			},
		})
		err = translateErr
		if module != nil && !module.Module.IsNil() {
			defer module.Module.Dispose()
			ir = module.Module.String()
		}
	default:
		t.Fatal("unknown actual consumer API", api)
	}
	if err != nil || !strings.Contains(ir, "fixed_local_native") {
		t.Fatal("downloaded LLVM consumer did not retain actual local proof", err)
	}
	return ir
}

func amd64DownloadedLLVM22Tool(t *testing.T, ctx context.Context, fixture amd64DownloadedLLVMFixture, name string) string {
	t.Helper()
	config := os.Getenv("LLVM_CONFIG")
	if config == "" {
		var err error
		config, err = exec.LookPath("llvm-config-22")
		if err != nil {
			// Some supported installations use unversioned binary names.
			// The selected configuration must still prove LLVM 22 below;
			// an incompatible tool never falls through to another release.
			config, err = exec.LookPath("llvm-config")
		}
		if err != nil {
			t.Fatal("required LLVM22 llvm-config missing", err)
		}
	}
	version, stderr, err := RunBounded(ctx, fixture.request.Directory, fixture.request.Environment, config, "--version")
	if err != nil || len(stderr) != 0 || !strings.HasPrefix(strings.TrimSpace(string(version)), "22.") {
		t.Fatalf("required LLVM22 configuration: %v; %s%s", err, version, stderr)
	}
	directory, stderr, err := RunBounded(ctx, fixture.request.Directory, fixture.request.Environment, config, "--bindir")
	if err != nil || len(stderr) != 0 || !filepath.IsAbs(strings.TrimSpace(string(directory))) {
		t.Fatalf("required LLVM22 tool directory: %v; %s%s", err, directory, stderr)
	}
	tool := filepath.Join(strings.TrimSpace(string(directory)), name)
	version, stderr, err = RunBounded(ctx, fixture.request.Directory, fixture.request.Environment, tool, "--version")
	if err != nil || len(stderr) != 0 || !strings.Contains(string(version), "version 22.") {
		t.Fatalf("required LLVM22 %s: %v; %s%s", name, err, version, stderr)
	}
	return tool
}

func (fixture amd64DownloadedLLVMFixture) object(t *testing.T, ctx context.Context, llc, ir, level string) string {
	t.Helper()
	directory := t.TempDir()
	input, object := filepath.Join(directory, "kernel.ll"), filepath.Join(directory, "kernel.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	output, stderr, err := RunBounded(ctx, directory, fixture.request.Environment, llc,
		level, "-mtriple="+fixture.backendTriple(), "-filetype=obj", input, "-o", object)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual LLVM22 downloaded object failed: %v; %s%s", err, output, stderr)
	}
	data, err := os.ReadFile(object)
	if err != nil || len(data) == 0 {
		t.Fatal("actual downloaded object is empty or unavailable", err)
	}
	t.Logf("ACTUAL_DOWNLOADED_LLVM22_OBJECT target=%s backend=%s level=%s bytes=%d sha256=%s",
		fixture.request.Target, fixture.backendTriple(), level, len(data), bytesSHA256(data))
	return object
}

// The proof's canonical target remains unchanged. A concrete macOS deployment
// version tells both actual tools to emit the Mach-O platform load command.
func (fixture amd64DownloadedLLVMFixture) backendTriple() string {
	if fixture.options.TargetTriple == "x86_64-apple-darwin" {
		return "x86_64-apple-macosx11.0.0"
	}
	return fixture.options.TargetTriple
}

// Every host must compile all three admitted AMD64 target formats. Numerical
// execution is separately required by the exact Linux/amd64 CI fixture below.
func TestAMD64DownloadedFixedLocalLLVM22Objects(t *testing.T) {
	for _, target := range []struct{ goos, triple string }{
		{"linux", "x86_64-unknown-linux-gnu"},
		{"darwin", "x86_64-apple-darwin"},
		{"windows", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			fixture := captureAMD64DownloadedLLVMFixture(t, ctx, target.goos, target.triple)
			llc := amd64DownloadedLLVM22Tool(t, ctx, fixture, "llc")
			for _, api := range []string{"Translate", "Module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir := fixture.ir(t, api)
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) { fixture.object(t, ctx, llc, ir, level) })
					}
				})
			}
			if err := fixture.binding.Verify(ctx); err != nil {
				t.Fatal("object compilation changed original downloaded inputs", err)
			}
		})
	}
}
