package main

import (
	"context"
	"encoding/json"
	"flag"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestCompileOneExplicitCPUProfileUsesActualAssemblerMacros(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := gotoolprofile.Capture(context.Background(), binary, t.TempDir(), os.Environ(), "linux/amd64", map[string]string{"GOAMD64": "v3"}, testFeatureRunner)
	if err != nil {
		t.Fatal(err)
	}
	rootData, _, err := testFeatureRunner(context.Background(), "", os.Environ(), binary, "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSpace(string(rootData))
	typesPkg := types.NewPackage("example.invalid/cpu", "cpu")
	for _, name := range []string{"v3Probe", "baselineProbe"} {
		typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, name, types.NewSignatureType(nil, nil, nil, nil, nil, false)))
	}
	pkg := &packages.Package{PkgPath: typesPkg.Path(), Types: typesPkg, Imports: map[string]*packages.Package{}}
	dir := t.TempDir()
	asm := filepath.Join(dir, "probe_amd64.s")
	if err := os.WriteFile(asm, []byte("#ifdef GOAMD64_v3\nTEXT ·v3Probe(SB),$0-0\nRET\n#else\nTEXT ·baselineProbe(SB),$0-0\nRET\n#endif\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "profile.ll")
	config := compileConfig{Feature: &featureConsumer{ID: gotoolprofile.ProfileID(observed), Observed: observed, Root: root}}
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ir), "v3Probe") || strings.Contains(string(ir), "baselineProbe") {
		t.Fatalf("explicit actual GOAMD64=v3 selected the baseline CPP branch:\n%s", ir)
	}
}

func testFeatureRunner(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env = dir, env
	var stderr strings.Builder
	command.Stderr = &stderr
	stdout, err := command.Output()
	return stdout, []byte(stderr.String()), err
}

func TestFeatureConsumerProductionSelectsGoAndCPPUnderSameV3Environment(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	t.Chdir(dir)
	filename := writeFeatureInput(t, input)
	output := t.TempDir()
	tasks, _ := collectAsmTasks([]*packages.Package{{PkgPath: input.Module, OtherFiles: []string{filepath.Join(dir, "probe_amd64.s")}, Module: &packages.Module{Path: input.Module, Dir: dir}}}, output, input.AsmFiles)
	if len(tasks) != 1 {
		t.Fatal("own source fixture did not define exactly one task")
	}
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config.FeaturePath, config.Context = filename, ctx
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module, output, false, 0, true, false, true, "../..", config)
	if err != nil {
		t.Fatal(err)
	}
	if report.Success != 1 || report.Failed != 0 || report.FeatureSelection == nil || report.FeatureSelection.ProfileID != input.ID {
		t.Fatalf("actual profile consumer report = %#v", report)
	}
	proof := report.FeatureSelection
	if err := gotoolprofile.ValidateSelection(input, proof, nil, true); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*gotoolprofile.SelectionProof){
		"profile ID":        func(proof *gotoolprofile.SelectionProof) { proof.ProfileID = "" },
		"custom CPU tag":    func(proof *gotoolprofile.SelectionProof) { proof.CustomTags = []string{"amd64.v3"} },
		"package role":      func(proof *gotoolprofile.SelectionProof) { proof.Packages[0].Macros.PackageRole = "allow_asm_abi_path" },
		"macro environment": func(proof *gotoolprofile.SelectionProof) { proof.Packages[0].Macros.Defines = []string{"GOAMD64_v1"} },
		"source SHA": func(proof *gotoolprofile.SelectionProof) {
			proof.Packages[0].SourceSHA256["selected.go"] = strings.Repeat("0", 64)
		},
		"unselected Go source": func(proof *gotoolprofile.SelectionProof) {
			proof.Packages[0].GoFiles, proof.Packages[0].CompiledGoFiles = []string{"fallback.go"}, []string{"fallback.go"}
			delete(proof.Packages[0].SourceSHA256, "selected.go")
			proof.Packages[0].SourceSHA256["fallback.go"] = input.Sources["fallback.go"]
		},
		"CPP origin": func(proof *gotoolprofile.SelectionProof) {
			proof.CPP[0].Inputs["module/probe_amd64.s"] = strings.Repeat("0", 64)
		},
		"omitted CPP":    func(proof *gotoolprofile.SelectionProof) { proof.CPP = nil },
		"omitted LLVM":   func(proof *gotoolprofile.SelectionProof) { proof.Outputs = nil },
		"omitted object": func(proof *gotoolprofile.SelectionProof) { proof.Outputs[0].Object = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.SelectionProof
			if err := json.Unmarshal(canonical, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := gotoolprofile.ValidateSelection(input, &changed, nil, true); err == nil {
				t.Fatal("mutated or legacy compiler-consumption proof was accepted")
			}
		})
	}
	if len(proof.Packages) != 1 || len(proof.Packages[0].CompiledGoFiles) != 1 || proof.Packages[0].CompiledGoFiles[0] != "selected.go" || proof.Packages[0].Macros.PackageRole != "ordinary_path" {
		t.Fatalf("actual Go source/package role selection = %#v", proof.Packages)
	}
	if len(proof.CPP) != 1 || len(proof.Outputs) != 1 || proof.Outputs[0].Object == "" {
		t.Fatalf("missing consumed CPP/LLVM object proof = %#v", proof)
	}
	ir, err := os.ReadFile(tasks[0].OutLL)
	if err != nil || !strings.Contains(string(ir), "v3Probe") || strings.Contains(string(ir), "baselineProbe") {
		t.Fatalf("actual consumer emitted the wrong CPU branch: %s (%v)", ir, err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	env := featureEnvironment(os.Environ(), input.Observed.Environment)
	archive, _, err := gotoolprofile.RunBounded(ctx, dir, env, binary, "list", "-export", "-f", "{{.Export}}", ".")
	if err != nil {
		t.Fatal(err)
	}
	symbols, _, err := gotoolprofile.RunBounded(ctx, dir, env, binary, "tool", "nm", strings.TrimSpace(string(archive)))
	if err != nil || !strings.Contains(string(symbols), "v3Probe") || strings.Contains(string(symbols), "baselineProbe") {
		t.Fatalf("actual Go object selected a different CPP branch:\n%s\n%v", symbols, err)
	}
	var llvmNM string
	for _, name := range []string{"llvm-nm-22", "llvm-nm"} {
		path, err := exec.LookPath(name)
		if err == nil && requireLLVM22LLC(path) == nil {
			llvmNM = path
			break
		}
	}
	if llvmNM == "" {
		t.Fatal("LLVM 22 nm is required for the actual object symbol oracle")
	}
	object := strings.TrimSuffix(tasks[0].OutLL, filepath.Ext(tasks[0].OutLL)) + ".o"
	symbols, _, err = gotoolprofile.RunBounded(ctx, dir, env, llvmNM, "--defined-only", object)
	if err != nil || !strings.Contains(string(symbols), "v3Probe") || strings.Contains(string(symbols), "baselineProbe") {
		t.Fatalf("LLVM 22 object selected a different CPU branch:\n%s\n%v", symbols, err)
	}
}

func TestFeatureConsumerRejectsUnboundSourceToolAndReservedTags(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	t.Chdir(dir)
	for _, tag := range []string{"amd64.v3", "goexperiment.arenas", "linux", "gc", "cgo", "ignore", "race"} {
		if _, err := loadFeatureConsumer(context.Background(), writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, []string{tag}); err == nil {
			t.Fatalf("reserved namespace %q became a custom CPU profile", tag)
		}
	}
	copy := *input.Observed
	copy.DriverSHA256 = strings.Repeat("0", 64)
	forged := *input
	forged.Observed, forged.ID = &copy, gotoolprofile.ProfileID(&copy)
	if _, err := loadFeatureConsumer(context.Background(), writeFeatureInput(t, &forged), t.TempDir(), "linux/amd64", input.Module, nil); err == nil || !strings.Contains(err.Error(), "actual marker/environment/source/tool") {
		t.Fatalf("JSON-only forged driver identity was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "selected.go"), []byte("package cpu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFeatureConsumer(context.Background(), writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil); err == nil || !strings.Contains(err.Error(), "pre-load proof") {
		t.Fatalf("changed pre-load source was accepted: %v", err)
	}
}

func TestFeatureConsumerDefaultCompilationRemainsUnprofiled(t *testing.T) {
	t.Setenv("GOAMD64", "v3")
	typesPkg := types.NewPackage("example.invalid/default", "defaultfixture")
	for _, name := range []string{"v3Probe", "baselineProbe"} {
		typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, name, types.NewSignatureType(nil, nil, nil, nil, nil, false)))
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "default_amd64.s")
	if err := os.WriteFile(asm, []byte("#ifdef GOAMD64_v3\nTEXT ·v3Probe(SB),$0-0\nRET\n#else\nTEXT ·baselineProbe(SB),$0-0\nRET\n#endif\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{PkgPath: typesPkg.Path(), Types: typesPkg, Imports: map[string]*packages.Package{}}
	output := filepath.Join(dir, "default.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: output}, false, compileConfig{}); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(ir), "v3Probe") || strings.Contains(string(ir), "baselineProbe") {
		t.Fatalf("explicit opt-in changed legacy compilation: %s (%v)", ir, err)
	}
}

func TestFeatureConsumerRejectsHeaderMutationAndNewPreferredInclude(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "settings.h"), []byte("#define CANARY 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["settings.h"] = featureBytesSHA256([]byte("#define CANARY 1\n"))
	input.Directories["."] = append(input.Directories["."], "settings.h")
	sort.Strings(input.Directories["."])
	asm := filepath.Join(dir, "probe_amd64.s")
	data, err := os.ReadFile(asm)
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte("#include \"settings.h\"\n"), data...)
	if err := os.WriteFile(asm, data, 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["probe_amd64.s"] = featureBytesSHA256(data)
	t.Chdir(dir)
	consumer, err := loadFeatureConsumer(context.Background(), writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := consumer.captureCPPInputs(asm)
	if err != nil || inputs["module/settings.h"] != input.Sources["settings.h"] {
		t.Fatalf("original header binding was not captured: %v, %v", inputs, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.h"), []byte("#define CANARY 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.captureCPPInputs(asm); err == nil {
		t.Fatal("changed consumed header bytes were accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "new_preferred.h"), []byte("#define CANARY 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifySources(); err == nil {
		t.Fatal("new preferred source-directory member was accepted")
	}
}

func TestFeatureConsumerCLIProducesBoundSelectionReport(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	profile := writeFeatureInput(t, input)
	output, report := t.TempDir(), filepath.Join(t.TempDir(), "report.json")
	args := []string{"-goos=linux", "-goarch=amd64", "-patterns=.", "-module-path=" + input.Module,
		"-asm-files=probe_amd64.s", "-feature-profile=" + profile, "-feature-timeout=1m",
		"-compile", "-keep-obj", "-out=" + output, "-report=" + report}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded))
	_, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
	if err != nil {
		t.Fatalf("actual CLI failed: %v\n%s", err, stderr)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded runReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Success != 1 || decoded.Failed != 0 || decoded.FeatureSelection == nil || decoded.FeatureSelection.ProfileID != input.ID || len(decoded.FeatureSelection.Outputs) != 1 || decoded.FeatureSelection.Outputs[0].Object == "" {
		t.Fatalf("actual CLI did not emit the same-load/CPP/object proof: %s", data)
	}
}

func TestFeatureConsumerCLIChild(t *testing.T) {
	encoded := os.Getenv("PLAN9ASM_CPUCLI_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	flag.CommandLine = flag.NewFlagSet("own-cpu-fixture", flag.ExitOnError)
	os.Args = append([]string{"own-cpu-fixture"}, args...)
	main()
	os.Exit(0)
}

func TestFeatureConsumerExactLocalReplacementKeepsSourceRootIdentity(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	input.Version = "v1.0.0"
	work := t.TempDir()
	mod := "module example.invalid/wrapper\n\ngo 1.24\n\nrequire " + input.Module + " v1.0.0\nreplace " + input.Module + " => " + filepath.ToSlash(dir) + "\n"
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	consumer, err := loadFeatureConsumer(context.Background(), writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadPkgsForFeature("linux", "amd64", []string{input.Module}, nil, input.Module, true, false, consumer)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.capturePackages(pkgs); err != nil {
		t.Fatal(err)
	}
	if len(consumer.Proof.Packages) != 1 || consumer.Proof.Packages[0].CompiledGoFiles[0] != "selected.go" {
		t.Fatalf("exact owned replacement selection was lost: %#v", consumer.Proof)
	}
	pkgs[0].Module.Version = "v2.0.0"
	if err := consumer.capturePackages(pkgs); err == nil {
		t.Fatal("different actual selected module version was accepted")
	}
	pkgs[0].Module.Version = input.Version
	pkgs[0].Module.Replace.Dir = t.TempDir()
	if err := consumer.capturePackages(pkgs); err == nil {
		t.Fatal("redirected local replacement was accepted")
	}
}

func featureConsumerFixture(t *testing.T) (*featureInput, string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":        "module example.invalid/cpu\n\ngo 1.24\n",
		"selected.go":   "//go:build amd64.v3\n\npackage cpu\nfunc v3Probe()\nfunc baselineProbe()\n",
		"fallback.go":   "//go:build !amd64.v3\n\npackage cpu\nfunc v3Probe()\nfunc baselineProbe()\n",
		"probe_amd64.s": "#ifdef GOAMD64_v3\nTEXT ·v3Probe(SB),$0-0\nRET\n#else\nTEXT ·baselineProbe(SB),$0-0\nRET\n#endif\n",
	}
	input := &featureInput{Protocol: featureInputProtocol, Module: "example.invalid/cpu", SourceRoot: dir, Sources: make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]string), AsmFiles: []string{"probe_amd64.s"}}
	var names []string
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256([]byte(source))
		if strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s") {
			input.Headers[name] = source
		}
		names = append(names, name)
	}
	sort.Strings(names)
	input.Directories["."] = names
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	// Discovery requires existing actual cache directories. Prepare them, but
	// retain the producer's original environment to test consumer reobservation.
	if _, err := ordinaryPackageEnvironment("linux", "amd64", os.Environ()); err != nil {
		t.Fatal(err)
	}
	input.Observed, err = gotoolprofile.Capture(context.Background(), binary, t.TempDir(), os.Environ(), "linux/amd64", map[string]string{"GOAMD64": "v3"}, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input.ID = gotoolprofile.ProfileID(input.Observed)
	return input, dir
}

func writeFeatureInput(t *testing.T, input *featureInput) string {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}
