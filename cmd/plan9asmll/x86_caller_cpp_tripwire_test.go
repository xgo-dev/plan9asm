package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Keep the preferred outside-module path inside this fixture's own temporary
// root. Neither the host TMPDIR nor the selected SDK is changed by these tests.
func callerCPPDeepFixture(t *testing.T, companion string, generated bool) x86CallerCPPFixture {
	t.Helper()
	owned := t.TempDir()
	dir := filepath.Join(owned, "owned", "module")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":         "module example.com/caller\n\ngo 1.20\n",
		"caller.go":      x86CallerCLISource,
		"kernel_amd64.s": x86CallerCLIAssembly,
		"other_amd64.s":  companion,
	}
	if generated {
		files["layout.go"] = "package caller\nconst Bias = 7\n"
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOMAXPROCS", "2")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pkgs, err := loadPkgs("linux", "amd64", []string{"."}, nil, "example.com/caller", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual companion package selection: %v (packages=%d)", err, len(pkgs))
	}
	pkg := pkgs[0]
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	input := &featureInput{
		Protocol: featureInputProtocol, Module: pkg.PkgPath, SourceRoot: root,
		AsmFiles:           []string{"kernel_amd64.s"},
		RegisteredAsmFiles: []string{"kernel_amd64.s", "other_amd64.s"},
		Sources:            map[string]string{}, Headers: map[string]string{},
		Directories:       map[string][]string{".": {}},
		CPPSourceProtocol: gotoolprofile.CPPOriginalReplayProtocol,
		CPPOriginals: &gotoolprofile.CPPOriginalReplayInput{
			Sources: map[string]string{}, Units: map[string]gotoolprofile.CPPOriginalUnit{},
			RequiredExpandedOperands: map[string][]gotoolprofile.CPPPackageSearchMiss{
				"kernel_amd64.s": {},
			},
		},
	}
	for name, source := range files {
		input.Directories["."] = append(input.Directories["."], name)
		input.Sources[name] = featureBytesSHA256([]byte(source))
		if filepath.Ext(name) == ".go" || filepath.Ext(name) == ".s" {
			input.Headers[name] = source
		}
		if filepath.Ext(name) == ".s" {
			input.CPPOriginals.Sources["module/"+name] = source
			input.CPPOriginals.Units[name] = gotoolprofile.CPPOriginalUnit{Includes: map[string]string{}}
		}
	}
	sort.Strings(input.Directories["."])
	unit := input.CPPOriginals.Units["other_amd64.s"]
	if generated {
		unit.GeneratedHeaders = []string{"go_asm.h"}
	} else {
		tool := "src/runtime/go_tls.h"
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
		if err != nil {
			t.Fatal(err)
		}
		input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
		input.CPPOriginals.Sources["tool/"+tool] = string(data)
		unit.Includes["../../src/runtime/go_tls.h"] = "tool/" + tool
	}
	input.CPPOriginals.Units["other_amd64.s"] = unit
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, x86CallerCLIAssembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	config := compileConfig{
		Context: ctx, x86CallerSelections: captureX86CallerSelections(pkgs, "linux/amd64", nil),
		Feature: &featureConsumer{Input: input, Context: ctx, Dir: root, Root: runtime.GOROOT()},
	}
	return x86CallerCPPFixture{
		pkg: pkg, file: file, config: config, input: input, root: root,
		defines: plan9asm.GoAssemblerDefines("linux", "amd64"), resolve: resolve, sigs: sigs,
	}
}

func callerCPPOriginalObject(t *testing.T, fixture x86CallerCPPFixture, name, headerDir string) {
	t.Helper()
	object := filepath.Join(t.TempDir(), "original.o")
	args := []string{"tool", "asm", "-p", fixture.pkg.PkgPath,
		"-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", object}
	if headerDir != "" {
		args = append(args, "-I", headerDir)
	}
	for _, define := range fixture.defines {
		args = append(args, "-D", define)
	}
	args = append(args, filepath.Join(fixture.root, name))
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	stdout, stderr, err := gotoolprofile.RunBounded(fixture.config.Context, fixture.root, env, "go", args...)
	if err != nil || len(stdout) != 0 || len(stderr) != 0 {
		t.Fatalf("actual Go companion object %s: %v\n%s\n%s", name, err, stdout, stderr)
	}
	if info, err := os.Lstat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("actual Go companion produced no regular object: %v", err)
	}
	digest, err := gotoolprofile.FileSHA256(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GO_ORIGINAL_COMPANION_OBJECT file=%s source_sha256=%s object_sha256=%s",
		name, fixture.input.Sources[name], digest)
}

func TestX86CallerCLICompanionGeneratedHeaderRetainsActualOrigin(t *testing.T) {
	fixture := callerCPPDeepFixture(t,
		"#include \"go_asm.h\"\nTEXT ·other(SB),4,$0-0\nMOVQ $const_Bias,AX\nRET\n", true)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Observed, err = gotoolprofile.Capture(fixture.config.Context, binary, t.TempDir(),
		os.Environ(), "linux/amd64", nil, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.ID = gotoolprofile.ProfileID(fixture.input.Observed)
	metadata, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"},
		[]string{"."}, nil, fixture.input.AsmFiles, fixture.input.Module, t.TempDir(),
		compileConfig{Context: fixture.config.Context, FeaturePath: writeFeatureInput(t, fixture.input)})
	if err != nil {
		t.Fatalf("actual generated-header producer: %v", err)
	}
	fixture.input.GeneratedHeaders = metadata
	consumer, err := loadFeatureConsumer(fixture.config.Context, writeFeatureInput(t, fixture.input),
		t.TempDir(), "linux/amd64", fixture.input.Module, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadGeneratedHeaderPackages(consumer, []string{"."}, nil)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual generated-header consumer selection: %v (packages=%d)", err, len(pkgs))
	}
	if err := consumer.capturePackages(pkgs); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if err := consumer.captureGeneratedMetadata(pkgs, nil, output); err != nil {
		t.Fatalf("independent actual Go -asmhdr consumer: %v", err)
	}
	headers, err := filepath.Glob(filepath.Join(output, ".generated-header-*", "go_asm.h"))
	if err != nil || len(headers) != 1 {
		t.Fatalf("actual compiler header artifacts: %v, %v", headers, err)
	}
	data, err := os.ReadFile(headers[0])
	if err != nil || featureBytesSHA256(data) != consumer.Proof.GeneratedHeaders.Headers[0].HeaderSHA256 ||
		consumer.Proof.GeneratedHeaders.Headers[0].Definitions["const_Bias"] != "7" {
		t.Fatalf("actual consumed compiler header differs from the sealed definitions: %v", err)
	}
	header := consumer.Proof.GeneratedHeaders.Headers[0]
	t.Logf("GO_ACTUAL_ASMHDR package=%s target=%s compiler_sha256=%s header_sha256=%s object_sha256=%s definitions_sha256=%s",
		header.PackagePath, header.Target, header.CompileToolSHA256, header.HeaderSHA256,
		header.ObjectSHA256, header.DefinitionsSHA256)
	fixture.pkg = pkgs[0]
	fixture.config.Feature = consumer
	fixture.config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/amd64", consumer)
	fixture.sigs, _, err = sigsForAsmFile(fixture.pkg, fixture.file, fixture.resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	callerCPPOriginalObject(t, fixture, "kernel_amd64.s", filepath.Dir(headers[0]))
	callerCPPOriginalObject(t, fixture, "other_amd64.s", filepath.Dir(headers[0]))
	before, err := json.Marshal(consumer.Input)
	if err != nil {
		t.Fatal(err)
	}
	bound, loaded, err := fixture.bind()
	if err != nil || loaded == nil {
		t.Fatalf("actual generated companion failed caller source closure: %v", err)
	}
	after, err := json.Marshal(consumer.Input)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("generated companion mutated the object input: %v", err)
	}
	ccfg, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	ccfg.Context = fixture.config.Context
	task := asmTask{OutLL: filepath.Join(t.TempDir(), "caller.ll")}
	if err := translateAndCompileModule(fixture.file, targetTriple("linux", "amd64"), "amd64",
		task, false, ccfg, fixture.resolve, bound); err != nil {
		t.Fatalf("generated-companion caller LLVM 22 object: %v", err)
	}
	objectSHA, err := gotoolprofile.FileSHA256(strings.TrimSuffix(task.OutLL, ".ll") + ".o")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LLVM22_CALLER_OBJECT target=linux/amd64 object_sha256=%s", objectSHA)
	if err := loaded.verify(fixture.config.Context, fixture.defines, consumer); err != nil {
		t.Fatalf("unchanged generated companion failed final object guard: %v", err)
	}
	if _, _, err := consumer.preprocessCPP(filepath.Join(fixture.root, "other_amd64.s"),
		fixture.pkg.PkgPath, fixture.defines); err == nil {
		t.Fatal("generated companion obtained missing requested-object operand authority")
	}
	original := consumer.Proof.GeneratedHeaders
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{"missing metadata", "wrong package", "consumed definition"} {
		t.Run(axis, func(t *testing.T) {
			var changed gotoolprofile.MetadataProof
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			consumer.Proof.GeneratedHeaders = &changed
			defer func() { consumer.Proof.GeneratedHeaders = original }()
			switch axis {
			case "missing metadata":
				consumer.Proof.GeneratedHeaders = nil
			case "wrong package":
				changed.Headers[0].PackagePath += "/wrong"
			case "consumed definition":
				changed.Headers[0].Definitions["const_Bias"] = "8"
				changed.Headers[0].DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(changed.Headers[0].Definitions)
			}
			if _, _, err := fixture.bind(); err == nil || fixture.config.Context.Err() != nil ||
				!strings.Contains(err.Error(), "actual caller CPP/typed assembly changed") {
				t.Fatalf("changed generated companion retained bound authority or lacked its precise CPP guard: %v", err)
			}
			if err := loaded.verify(fixture.config.Context, fixture.defines, consumer); err == nil ||
				fixture.config.Context.Err() != nil || !strings.Contains(err.Error(), "actual caller CPP/typed assembly changed") {
				t.Fatalf("changed generated companion survived the final object guard or lacked its precise diagnostic: %v", err)
			}
		})
	}
	t.Run("paired producer definitions", func(t *testing.T) {
		var changed gotoolprofile.MetadataProof
		if err := json.Unmarshal(encoded, &changed); err != nil {
			t.Fatal(err)
		}
		changed.Headers[0].Definitions["const_Bias"] = "8"
		changed.Headers[0].DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(changed.Headers[0].Definitions)
		previous := consumer.Input.GeneratedHeaders
		consumer.Input.GeneratedHeaders = &changed
		defer func() { consumer.Input.GeneratedHeaders = previous }()
		if err := consumer.captureGeneratedMetadata(pkgs, nil, t.TempDir()); err == nil ||
			fixture.config.Context.Err() != nil || !strings.Contains(err.Error(), "independent generated-header definitions/imports differ") {
			t.Fatalf("paired producer metadata replaced actual -asmhdr definitions or failed outside independent agreement: %v", err)
		}
	})
}

func TestX86CallerCLICompanionExpandedSDKPreferredAppearanceRevokesFinalGuard(t *testing.T) {
	for _, kind := range []string{"regular file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			fixture := callerCPPDeepFixture(t,
				"#define SELECT \\\n#include \"../../src/runtime/go_tls.h\" \\\n\nSELECT\nTEXT ·other(SB),4,$0-0\nRET\n", false)
			callerCPPOriginalObject(t, fixture, "kernel_amd64.s", "")
			callerCPPOriginalObject(t, fixture, "other_amd64.s", "")
			_, loaded, err := fixture.bind()
			if err != nil || loaded == nil {
				t.Fatalf("unchanged exact SDK fallback failed caller closure: %v", err)
			}
			if err := loaded.verify(fixture.config.Context, fixture.defines, fixture.config.Feature); err != nil {
				t.Fatal(err)
			}
			preferred, err := gotoolprofile.CPPPreferredPackageInclude(fixture.root,
				"other_amd64.s", "../../src/runtime/go_tls.h")
			if err != nil {
				t.Fatal(err)
			}
			owned := filepath.Dir(filepath.Dir(fixture.root))
			relative, err := filepath.Rel(owned, preferred)
			if err != nil || !filepath.IsLocal(relative) || relative != filepath.FromSlash("src/runtime/go_tls.h") {
				t.Fatalf("preferred candidate escaped the exact test-owned root: %s, %v", relative, err)
			}
			if _, err := os.Lstat(preferred); !os.IsNotExist(err) {
				t.Fatalf("preferred candidate was not initially absent: %v", err)
			}
			if err := os.MkdirAll(filepath.Dir(preferred), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "regular file" {
				if err := os.WriteFile(preferred, []byte("#define FORGED 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				local := filepath.Join(owned, "symlink-target.h")
				if err := os.WriteFile(local, []byte("#define FORGED 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(local, preferred); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := fixture.config.Feature.preprocessCallerCPP(filepath.Join(fixture.root, "other_amd64.s"),
				fixture.pkg.PkgPath, fixture.defines); err == nil || fixture.config.Context.Err() != nil ||
				!strings.Contains(err.Error(), "preferred CPP candidate exists") {
				t.Fatalf("late preferred %s did not revoke physical ENOENT: %v", kind, err)
			}
			if err := loaded.verify(fixture.config.Context, fixture.defines, fixture.config.Feature); err == nil ||
				fixture.config.Context.Err() != nil || !strings.Contains(err.Error(), "actual caller CPP/typed assembly changed") {
				t.Fatalf("late preferred %s survived the final caller CPP guard or failed outside CPP: %v", kind, err)
			}
		})
	}
}
