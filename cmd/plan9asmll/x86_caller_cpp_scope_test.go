package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

type x86CallerCPPFixture struct {
	pkg     *packages.Package
	file    *plan9asm.File
	config  compileConfig
	input   *featureInput
	root    string
	defines []string
	resolve func(string) string
	sigs    map[string]plan9asm.FuncSig
}

func makeX86CallerCPPFixture(t *testing.T, companion string, localHeader bool, expandedSDK bool) x86CallerCPPFixture {
	t.Helper()
	extra := map[string]string{"other_amd64.s": companion}
	if localHeader {
		extra["bias.h"] = "#define BIAS 7\n"
	}
	pkg, file, config := x86CallerCLILoad(t, extra)
	root, err := filepath.EvalSymlinks(pkg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	input := &featureInput{
		Module: pkg.PkgPath, AsmFiles: []string{"kernel_amd64.s"},
		Sources: map[string]string{}, Headers: map[string]string{},
		CPPSourceProtocol: gotoolprofile.CPPOriginalReplayProtocol,
		CPPOriginals: &gotoolprofile.CPPOriginalReplayInput{
			Sources: map[string]string{},
			Units:   map[string]gotoolprofile.CPPOriginalUnit{},
			RequiredExpandedOperands: map[string][]gotoolprofile.CPPPackageSearchMiss{
				"kernel_amd64.s": {},
			},
		},
	}
	for name := range extra {
		text := []byte(extra[name])
		input.Sources[name] = featureBytesSHA256(text)
		input.Headers[name] = string(text)
		input.CPPOriginals.Sources["module/"+name] = string(text)
	}
	for _, name := range []string{"kernel_amd64.s", "other_amd64.s"} {
		text, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256(text)
		input.Headers[name] = string(text)
		input.CPPOriginals.Sources["module/"+name] = string(text)
		input.CPPOriginals.Units[name] = gotoolprofile.CPPOriginalUnit{
			Includes: map[string]string{},
		}
	}
	unit := input.CPPOriginals.Units["other_amd64.s"]
	if localHeader {
		unit.Includes["bias.h"] = "module/bias.h"
	}
	if expandedSDK {
		tool := "src/runtime/go_tls.h"
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
		if err != nil {
			t.Fatal(err)
		}
		input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
		input.CPPOriginals.Sources["tool/"+tool] = string(data)
		unit.Includes["../../src/runtime/go_tls.h"] = "tool/" + tool
	}
	config.Feature = &featureConsumer{
		Input: input, Context: config.Context, Dir: root, Root: runtime.GOROOT(),
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	defines := plan9asm.GoAssemblerDefines("linux", "amd64")
	for _, name := range []string{"kernel_amd64.s", "other_amd64.s"} {
		object := filepath.Join(t.TempDir(), "original.o")
		args := []string{"tool", "asm", "-p", pkg.PkgPath,
			"-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", object}
		for _, define := range defines {
			args = append(args, "-D", define)
		}
		args = append(args, filepath.Join(root, name))
		env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
		stdout, stderr, err := gotoolprofile.RunBounded(config.Context, root, env, "go", args...)
		if err != nil || len(stdout) != 0 || len(stderr) != 0 {
			t.Fatalf("actual original companion assembly %s: %v\n%s\n%s", name, err, stdout, stderr)
		}
		if info, err := os.Stat(object); err != nil || info.Size() == 0 {
			t.Fatalf("missing original companion object: %v", err)
		}
	}
	return x86CallerCPPFixture{
		pkg: pkg, file: file, config: config, input: input, root: root,
		defines: defines, resolve: resolve, sigs: sigs,
	}
}

func (fixture x86CallerCPPFixture) bind() (map[string]plan9asm.FuncSig, *x86CallerTypedPackage, error) {
	return bindX86CallerRegions(fixture.pkg, fixture.file, "linux/amd64", "amd64",
		filepath.Join(fixture.root, "kernel_amd64.s"), fixture.defines,
		fixture.config, fixture.resolve, fixture.sigs)
}

// The actual package selection is broader than the one-file object request.
// All companion bytes still enter the caller/exposure closure.
func TestX86CallerCLICompanionCPPIsSeparateFromObjectConsumption(t *testing.T) {
	cases := []struct {
		name        string
		source      string
		localHeader bool
		expandedSDK bool
	}{
		{"literal", "TEXT ·other(SB),4,$0-0\nRET\n", false, false},
		{"local_macro", "#include \"bias.h\"\nTEXT ·other(SB),4,$0-0\nMOVQ $BIAS,AX\nRET\n", true, false},
		{"expanded_sdk", "#define SELECT \\\n#include \"../../src/runtime/go_tls.h\" \\\n\nSELECT\nTEXT ·other(SB),4,$0-0\nRET\n", false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := makeX86CallerCPPFixture(t, test.source, test.localHeader, test.expandedSDK)
			before, err := json.Marshal(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			bound, loaded, err := fixture.bind()
			if err != nil || loaded == nil {
				t.Fatalf("actual selected companion must close source exposure without borrowing an object receipt: %v", err)
			}
			after, err := json.Marshal(fixture.input)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("caller closure mutated the original object input: %v", err)
			}
			if _, _, err := fixture.config.Feature.preprocessCPP(
				filepath.Join(fixture.root, "other_amd64.s"), fixture.pkg.PkgPath, fixture.defines); err == nil {
				t.Fatal("source-only companion acquired missing final CPP/object authority")
			}

			ccfg, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			ccfg.Context = fixture.config.Context
			task := asmTask{OutLL: filepath.Join(t.TempDir(), "caller.ll")}
			if err := translateAndCompileModule(fixture.file, targetTriple("linux", "amd64"),
				"amd64", task, false, ccfg, fixture.resolve, bound); err != nil {
				t.Fatalf("closed actual caller failed LLVM 22 object compilation: %v", err)
			}
			object := strings.TrimSuffix(task.OutLL, ".ll") + ".o"
			if info, err := os.Stat(object); err != nil || info.Size() == 0 {
				t.Fatalf("missing actual LLVM 22 caller object: %v", err)
			}
		})
	}
}

func TestX86CallerCLICompanionCPPStillClosesAssemblyExposures(t *testing.T) {
	for name, source := range map[string]string{
		"call":    "TEXT ·other(SB),4,$0-0\nCALL ·kernel(SB)\nRET\n",
		"address": "TEXT ·other(SB),4,$0-0\nLEAQ ·kernel(SB),AX\nRET\n",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := makeX86CallerCPPFixture(t, source, false, false)
			if _, _, err := fixture.bind(); err == nil {
				t.Fatal("actual companion exposure obtained a raw-return caller region")
			}
		})
	}
}

func TestX86CallerCLICompanionCPPRejectsChangedProofAndPhysicalInputs(t *testing.T) {
	for _, axis := range []string{
		"missing requested set", "null requested set", "missing unit",
		"changed graph", "paired graph hash", "changed companion", "changed local header",
	} {
		t.Run(axis, func(t *testing.T) {
			fixture := makeX86CallerCPPFixture(t,
				"#include \"bias.h\"\nTEXT ·other(SB),4,$0-0\nMOVQ $BIAS,AX\nRET\n", true, false)
			switch axis {
			case "missing requested set":
				delete(fixture.input.CPPOriginals.RequiredExpandedOperands, "kernel_amd64.s")
			case "null requested set":
				fixture.input.CPPOriginals.RequiredExpandedOperands["kernel_amd64.s"] = nil
			case "missing unit":
				delete(fixture.input.CPPOriginals.Units, "other_amd64.s")
			case "changed graph", "paired graph hash":
				name := "module/other_amd64.s"
				changed := fixture.input.CPPOriginals.Sources[name] + "// changed\n"
				fixture.input.CPPOriginals.Sources[name] = changed
				if axis == "paired graph hash" {
					fixture.input.Sources["other_amd64.s"] = featureBytesSHA256([]byte(changed))
				}
			case "changed companion", "changed local header":
				name, text := "other_amd64.s", "TEXT ·other(SB),4,$0-0\nCALL ·kernel(SB)\nRET\n"
				if axis == "changed local header" {
					name, text = "bias.h", "#define BIAS 8\n"
				}
				if err := os.WriteFile(filepath.Join(fixture.root, name), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := fixture.bind(); err == nil {
				t.Fatalf("changed %s obtained caller closure", axis)
			}
		})
	}
}

func TestX86CallerCLICompanionCPPRemainsGuardedThroughFinalObject(t *testing.T) {
	for _, name := range []string{"other_amd64.s", "bias.h"} {
		t.Run(name, func(t *testing.T) {
			fixture := makeX86CallerCPPFixture(t,
				"#include \"bias.h\"\nTEXT ·other(SB),4,$0-0\nMOVQ $BIAS,AX\nRET\n", true, false)
			_, loaded, err := fixture.bind()
			if err != nil || loaded == nil {
				t.Fatalf("unchanged companion failed source closure: %v", err)
			}
			path := filepath.Join(fixture.root, name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(original, []byte("// changed\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := loaded.verify(fixture.config.Context, fixture.defines, fixture.config.Feature); err == nil {
				t.Fatalf("changed companion %s survived the final object guard", name)
			}
		})
	}
}
