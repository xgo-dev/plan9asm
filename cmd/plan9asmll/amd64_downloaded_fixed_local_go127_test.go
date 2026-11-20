//go:build go1.27

package main

import (
	"debug/elf"
	"debug/macho"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// The generated file-proxy module is an owned mechanism fixture, not an
// authenticated external-library pass. Its original cache source stays intact.
func amd64DownloadedFixedLocalTargetFixture(t *testing.T, goos string, mirror bool) (*featureInput, string, compileConfig) {
	t.Helper()
	_, assembly, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	ctx := config.Context
	input := &featureInput{
		Protocol: featureInputProtocol,
		Module:   "example.invalid/fixedlocal", Version: "v1.0.0",
		SourceRoot: filepath.Dir(assembly),
		Sources:    make(map[string]string), Headers: make(map[string]string),
		Directories: make(map[string][]string), AsmFiles: []string{"value_amd64.s"},
	}
	for _, name := range []string{"go.mod", "value.go", "value_amd64.s"} {
		data, err := os.ReadFile(filepath.Join(input.SourceRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256(data)
		input.Directories["."] = append(input.Directories["."], name)
		if name != "go.mod" {
			input.Headers[name] = string(data)
		}
	}
	sort.Strings(input.Directories["."])
	// The archive request can differ from the module declaration inside its
	// unchanged go.mod. Download the exact archive before selecting its package.
	archiveInput := *input
	if mirror {
		archiveInput.Module = "example.invalid/archive-fixedlocal"
	}
	modeInput := &gotoolprofile.InstrumentationConsumerInput{Original: &archiveInput}
	invocation, env := instrumentationVersionedFixture(t, ctx, modeInput)
	input = modeInput.Original
	input.Module = "example.invalid/fixedlocal"
	if mirror {
		// Match the corpus's independent invocation module and real versioned
		// replacement. The downstream source observer separately loads the cache
		// CWD as Main=true/Version=""; neither view is relabeled as the other.
		caller := "module example.invalid/invocation\n\ngo 1.24\n\nrequire " + input.Module + " " + input.Version + "\n" +
			"replace " + input.Module + " " + input.Version + " => " + input.SourceModule + " " + input.Version + "\n"
		if err := os.WriteFile(filepath.Join(invocation, "go.mod"), []byte(caller), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env = featureEnvironment(env, map[string]string{
		"GOOS": goos, "GOARCH": "amd64", "GO386": "", "GOARM": "", "GOARM64": "", "GOWASM": "",
	})
	for _, value := range env {
		key, value, valid := strings.Cut(value, "=")
		if !valid {
			t.Fatal("malformed exact-download fixture environment")
		}
		switch key {
		case "GOPROXY", "GOSUMDB", "GOPATH", "GOMODCACHE", "GOOS", "GOARCH", "GO386", "GOARM", "GOARM64", "GOWASM":
			t.Setenv(key, value)
		}
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	root, stderr, err := gotoolprofile.RunBounded(ctx, invocation, env, binary, "env", "GOROOT")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual exact-download Go source root: %v; %s", err, stderr)
	}
	textflag, err := gotoolprofile.FileSHA256(filepath.Join(strings.TrimSpace(string(root)), "pkg", "include", "textflag.h"))
	if err != nil {
		t.Fatal(err)
	}
	input.ToolSources = map[string]string{"pkg/include/textflag.h": textflag}
	input.Observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), env,
		goos+"/amd64", nil, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input.ID = gotoolprofile.ProfileID(input.Observed)
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, invocation, env, binary,
		"list", "-export", "-compiled", "-json", "-mod=readonly", input.Module)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual exact-cache original Go export failed: %v\n%s%s", err, stdout, stderr)
	}
	t.Logf("ACTUAL_EXACT_CACHE_ORIGINAL_GO_EXPORT\n%s", stdout)
	for name, expected := range input.Sources {
		actual, err := gotoolprofile.FileSHA256(filepath.Join(input.SourceRoot, name))
		if err != nil || actual != expected {
			t.Fatalf("original cache source changed before CLI: %s: %v", name, err)
		}
	}
	return input, invocation, config
}

func TestAMD64DownloadedFixedLocalActualProfileCLI(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, mirror := range []bool{false, true} {
			role := "declared"
			if mirror {
				role = "mirror"
			}
			t.Run(goos+"/"+role, func(t *testing.T) {
				testAMD64DownloadedFixedLocalActualProfileCLI(t, goos, mirror)
			})
		}
	}
}

func testAMD64DownloadedFixedLocalActualProfileCLI(t *testing.T, goos string, mirror bool) {
	t.Helper()
	input, invocation, config := amd64DownloadedFixedLocalTargetFixture(t, goos, mirror)
	t.Chdir(invocation)
	config.FeaturePath = writeFeatureInput(t, input)
	output := t.TempDir()
	report, _, err := runOneTarget(targetSpec{Goos: goos, Goarch: "amd64"},
		[]string{input.Module}, nil, input.AsmFiles, input.Module, output,
		false, 0, true, false, true, "", config)
	if err != nil || report.Success != 1 || report.Failed != 0 || report.NotApplicable != 0 || report.TotalAsm != 1 {
		t.Fatalf("actual original Go object compiled, but exact downloaded profile CLI has no fixed-local consumer: %v; %#v", err, report)
	}
	if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
		t.Fatal(err)
	}
	if len(report.FeatureSelection.CPP) != 1 || len(report.FeatureSelection.Outputs) != 1 ||
		report.FeatureSelection.Outputs[0].IR == "" || report.FeatureSelection.Outputs[0].Object == "" {
		t.Fatal("exact downloaded CLI omitted its actual CPP/LLVM object consumption")
	}
	if len(report.FeatureSelection.Packages) != 1 {
		t.Fatal("exact downloaded CLI lost its actual package identity")
	}
	selected := report.FeatureSelection.Packages[0]
	role := "module"
	if mirror {
		role = "version_replace"
	}
	if selected.SourceRole != role || selected.ModulePath != input.Module ||
		selected.SourceModule != input.SourceModule || selected.ModuleVersion != input.Version ||
		selected.SourceVersion != input.Version {
		t.Fatalf("CLI merged archive and declaration identities: %#v", selected)
	}
	object := filepath.Join(output, filepath.FromSlash(input.Module), "value_amd64.s.o")
	data, err := os.ReadFile(object)
	if err != nil || len(data) == 0 || featureBytesSHA256(data) != report.FeatureSelection.Outputs[0].Object {
		t.Fatalf("actual LLVM object differs from the consumer proof: %v", err)
	}
	if goos == "darwin" {
		file, err := macho.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if file.Cpu != macho.CpuAmd64 || file.Type != macho.TypeObj || file.Section("__text") == nil || file.Section("__text").Size == 0 {
			t.Fatal("LLVM object omitted AMD64 Mach-O text")
		}
	} else {
		file, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if file.Machine != elf.EM_X86_64 || file.Type != elf.ET_REL || file.Section(".text") == nil || file.Section(".text").Size == 0 {
			t.Fatal("LLVM object omitted AMD64 ELF text")
		}
	}
	t.Logf("ACTUAL_DOWNLOADED_FIXED_LOCAL_CLI target=%s/amd64 module=%s source=%s@%s object=%s bytes=%d",
		goos, input.Module, input.SourceModule, input.Version, report.FeatureSelection.Outputs[0].Object, len(data))
	for name, expected := range input.Sources {
		actual, err := gotoolprofile.FileSHA256(filepath.Join(input.SourceRoot, name))
		if err != nil || actual != expected {
			t.Fatalf("CLI rewrote original cache source: %s: %v", name, err)
		}
	}
}

func TestAMD64DownloadedFixedLocalCLIRejectsUnboundAndChangedIdentity(t *testing.T) {
	testAMD64DownloadedFixedLocalIdentityControls(t, "linux", false)
}

func TestAMD64DownloadedFixedLocalMirrorCLIRejectsUnboundAndChangedIdentity(t *testing.T) {
	testAMD64DownloadedFixedLocalIdentityControls(t, "darwin", true)
}

func testAMD64DownloadedFixedLocalIdentityControls(t *testing.T, goos string, mirror bool) {
	t.Helper()
	roles := []string{
		"no-explicit-request", "missing-version", "load-identity",
		"version-in-resolver", "source-module-in-resolver", "source-root-in-resolver", "input-in-resolver",
	}
	if mirror {
		roles = append(roles, "missing-source-module", "false-source-module", "declaration-in-resolver",
			"replacement-path-in-resolver", "replacement-version-in-resolver", "replacement-role-in-resolver",
			"source-bytes-in-resolver", "archive-bytes-in-resolver")
	}
	target, triple := goos+"/amd64", targetTriple(goos, "amd64")
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			input, invocation, config := amd64DownloadedFixedLocalTargetFixture(t, goos, mirror)
			t.Chdir(invocation)
			consumer, err := loadFeatureConsumer(config.Context, writeFeatureInput(t, input), t.TempDir(),
				target, input.Module, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkgs, err := packages.Load(&packages.Config{
				Context: config.Context, Dir: invocation, Env: consumer.Env,
				Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
					packages.NeedModule | packages.NeedDeps | packages.NeedImports |
					packages.NeedTypes | packages.NeedTypesSizes,
			}, input.Module)
			if err != nil || len(pkgs) != 1 || len(pkgs[0].Errors) != 0 {
				t.Fatalf("actual exact-cache CLI load: %v; %+v", err, pkgs)
			}
			pkg := pkgs[0]
			if pkg.Module == nil || pkg.Module.Main || pkg.Module.Version != input.Version ||
				(pkg.Module.Replace != nil) != mirror {
				t.Fatal("fixture did not retain its actual exact imported module role")
			}
			if err := consumer.capturePackages(pkgs); err != nil {
				t.Fatal(err)
			}
			config.Feature = consumer
			config.x86CallerSelections = captureX86CallerSelections(pkgs, target, consumer)
			assembly := filepath.Join(pkg.Dir, "value_amd64.s")
			data, err := os.ReadFile(assembly)
			if err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64,
				strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			resolve := func(name string) string {
				calls++
				if calls == 1 {
					switch role {
					case "version-in-resolver":
						consumer.Input.Version = "v1.0.1"
					case "source-module-in-resolver":
						consumer.Input.SourceModule = "example.invalid/other"
					case "source-root-in-resolver":
						consumer.Input.SourceRoot = invocation
					case "input-in-resolver":
						copied := *consumer.Input
						consumer.Input = &copied
					case "declaration-in-resolver":
						consumer.Input.Module = input.SourceModule
					case "replacement-path-in-resolver":
						pkg.Module.Replace.Path = "example.invalid/other"
					case "replacement-version-in-resolver":
						pkg.Module.Replace.Version = "v1.0.1"
					case "replacement-role-in-resolver":
						pkg.Module.Replace = nil
					case "source-bytes-in-resolver":
						amd64DownloadedFixtureAppend(t, filepath.Join(input.SourceRoot, "value.go"))
					case "archive-bytes-in-resolver":
						archive := filepath.Join(os.Getenv("GOMODCACHE"), "cache", "download", input.SourceModule, "@v", input.Version+".zip")
						amd64DownloadedFixtureAppend(t, archive)
					}
				}
				return strings.Replace(name, "·", pkg.PkgPath+".", 1)
			}
			// Signature inference must not trigger the mutating binding callback.
			sigs, _, err := sigsForAsmFile(pkg, file,
				func(name string) string { return strings.Replace(name, "·", pkg.PkgPath+".", 1) }, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			switch role {
			case "no-explicit-request":
				config.Feature = nil
			case "missing-version":
				consumer.Input.Version = ""
			case "load-identity":
				pkg.Module.Version = "v1.0.1"
			case "missing-source-module":
				consumer.Input.SourceModule = ""
			case "false-source-module":
				consumer.Input.SourceModule = "example.invalid/other"
			}
			bound, source, err := prepareAMD64FixedLocalSource(pkg, file, assembly, target,
				triple, "amd64", config, resolve, sigs, nil)
			if source != nil {
				if closeErr := source.close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if err == nil || source != nil || bound != nil {
				t.Fatalf("unbound/changed %s retained downloaded frame authority: %v", role, err)
			}
			t.Logf("EXACT_SOURCE_IDENTITY_REJECTION %s: %v", role, err)
			want := "fixed-local explicit download identity changed"
			switch role {
			case "no-explicit-request", "missing-version":
				want = "cached external or SDK source cannot acquire an owned-main role"
			case "load-identity", "replacement-path-in-resolver", "replacement-version-in-resolver", "replacement-role-in-resolver":
				want = "fixed-local actual-load identity changed"
			case "missing-source-module", "false-source-module":
				want = "actual exact module download failed"
			case "source-bytes-in-resolver", "archive-bytes-in-resolver":
				want = "changed"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("identity control failed for an unrelated reason, want %q: %v", want, err)
			}
			if !mirror && !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("ordinary missing identity did not retain Context: %v", err)
			}
			if strings.HasSuffix(role, "-in-resolver") && calls == 0 {
				t.Fatal("identity control failed before its actual binding callback")
			}
		})
	}
}

func amd64DownloadedFixtureAppend(t *testing.T, name string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, append(data, []byte("\n// changed owned fixture\n")...), 0600); err != nil {
		t.Fatal(err)
	}
}
