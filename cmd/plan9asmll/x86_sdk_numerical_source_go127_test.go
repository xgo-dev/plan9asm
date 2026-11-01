//go:build go1.27

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestCompileOneX86SDKOriginalCRC32NumericalDataJoin(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		compileX86SDKOriginalCRC32NumericalDataJoin(t, "explicit")
	})
}

func TestCompileOneX86SDKOriginalCRC32NumericalDataJoinEffectiveDefaults(t *testing.T) {
	t.Run("effective-defaults", func(t *testing.T) {
		compileX86SDKOriginalCRC32NumericalDataJoin(t, "effective-defaults")
	})
}

func setX86SDKNumericalCLIProfile(t *testing.T, profile string) {
	t.Helper()
	cache := x86SDKNumericalCLIBuildCache(t)
	for key, value := range map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOPACKAGESDRIVER": "off",
		"GOPROXY": "off", "CGO_ENABLED": "0", "GOAMD64": "v1", "GO386": "sse2",
		"GOOS": "linux", "GOARCH": "amd64", "GOARM": "", "GOARM64": "", "GOWASM": "",
	} {
		t.Setenv(key, value)
	}
	for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		path, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, path)
	}
	t.Setenv("GOCACHE", cache)
	if profile == "effective-defaults" {
		for _, key := range []string{"GOAMD64", "GO386", "GOPROXY", "GOTMPDIR", "GOMODCACHE", "GOPATH", "CGO_ENABLED"} {
			// Setenv owns restoration and prohibits parallel environment users;
			// the actual load below observes an absent key, not a forged receipt.
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func compileX86SDKOriginalCRC32NumericalDataJoin(t *testing.T, profile string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, profile)
	ctx := arm64PrivateCLIContext(t)
	directory := filepath.Join(runtime.GOROOT(), "src", "hash", "crc32")
	input := filepath.Join(directory, "crc32_amd64.s")
	original, err := os.ReadFile(input)
	if err != nil || !strings.Contains(string(original), "CMPB internal∕cpu·X86+const_offsetX86HasAVX512VPCLMULQDQL(SB), $1") {
		t.Fatal("original current SDK counterexample is absent", err)
	}
	environment := os.Environ()
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx, Dir: directory, Env: environment,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedModule | packages.NeedDeps | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes,
	}, ".")
	if err != nil || len(pkgs) != 1 || pkgs[0].PkgPath != "hash/crc32" || len(pkgs[0].Errors) != 0 {
		t.Fatalf("actual original SDK selection failed: %v %+v", err, pkgs)
	}
	selection, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, "go",
		"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("original stock Go package failed: %v\n%s%s", err, selection, stderr)
	}
	t.Logf("original SDK assembly SHA256=%x; actual selection SHA256=%x", sha256.Sum256(original), sha256.Sum256(selection))
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/amd64", nil)
	if profile == "explicit" {
		t.Run("ordinary-proof-failure-publishes-nothing", func(t *testing.T) {
			folder := t.TempDir()
			// Complete actual declarations now legitimately bind these CMP
			// reads without an SDK reload. A genuinely missing load owner must
			// still fail before publishing and must not become a source retry.
			unbound := config
			unbound.x86CallerSelections = nil
			err := compileOneAttempt(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: filepath.Join(folder, "ordinary.ll")}, false, unbound)
			if _, retryable := x86SDKNumericalRetryCause(err); retryable || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("missing actual declaration owner bypassed its pre-publication guard: %v", err)
			}
			artifacts, err := os.ReadDir(folder)
			if err != nil || len(artifacts) != 0 {
				t.Fatalf("ordinary proof rejection published output: %v, %v", artifacts, err)
			}
		})
		t.Run("ordinary-declarations-complete-object-without-reload", func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "ordinary.ll")
			// This one attempt has acquireSDKNumerical=false. Success cannot
			// borrow compileOne's separate guarded SDK retry or its observations.
			if err := compileOneAttempt(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatal("complete actual CRC32 declarations still require SDK source authority", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "load volatile i8") ||
				!strings.Contains(string(ir), `@"internal/cpu.X86" = external global `) {
				t.Fatal("ordinary CPU declaration lost its real external byte-read role", err)
			}
			if object, err := os.Lstat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !object.Mode().IsRegular() || object.Size() == 0 {
				t.Fatal("ordinary complete-source LLVM22 object is missing", err)
			}
		})
		t.Run("actual-reload-has-distinct-types-and-owned-roots", func(t *testing.T) {
			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			reloaded, snapshot, release, err := loadX86SDKNumericalPackage(ctx, binary, pkgs[0], config.x86CallerSelections[pkgs[0]])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := release(); err != nil {
					t.Error(err)
				}
			})
			if reloaded == pkgs[0] || reloaded.Types == pkgs[0].Types || snapshot.types != reloaded.Types {
				t.Fatal("reload merely relabelled the original package/types")
			}
			var temp string
			for _, entry := range snapshot.env {
				if strings.HasPrefix(entry, "GOTMPDIR=") {
					temp = strings.TrimPrefix(entry, "GOTMPDIR=")
				}
			}
			if !filepath.IsAbs(temp) || temp == os.Getenv("GOTMPDIR") {
				t.Fatal("reload did not own its temporary root")
			}
			if err := release(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(temp); !os.IsNotExist(err) {
				t.Fatalf("owned reload workspace survived close: %v", err)
			}
		})
		t.Run("nondefault-CPU-is-not-relabelled", func(t *testing.T) {
			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			selected := *config.x86CallerSelections[pkgs[0]]
			selected.env = append(append([]string(nil), selected.env...), "GOAMD64=v2")
			reloaded, snapshot, release, err := loadX86SDKNumericalPackage(ctx, binary, pkgs[0], &selected)
			if reloaded != nil || snapshot != nil || release != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("nonbaseline profile acquired a baseline selection: %v", err)
			}
			unbound := config
			unbound.x86CallerSelections = map[*packages.Package]*x86CallerPackageSelection{pkgs[0]: &selected}
			folder := t.TempDir()
			err = compileOne(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: filepath.Join(folder, "rejected.ll")}, false, unbound)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("unbound CPU profile was not refused: %v", err)
			}
			artifacts, err := os.ReadDir(folder)
			if err != nil || len(artifacts) != 0 {
				t.Fatalf("failed complete-file proof published output: %v, %v", artifacts, err)
			}
		})
		t.Run("cancellation-is-not-source-exclusion", func(t *testing.T) {
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			reloaded, snapshot, release, err := loadX86SDKNumericalPackage(cancelled, "go", pkgs[0], config.x86CallerSelections[pkgs[0]])
			if reloaded != nil || snapshot != nil || release != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled load did not preserve cancellation: %v", err)
			}
		})
	}
	output := filepath.Join(t.TempDir(), "crc32.ll")
	if err := compileOne(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatalf("unchanged SDK Go compilation passed but CLI translation/object failed: %v", err)
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
		t.Fatal("original SDK assembly changed during CLI consumption", err)
	}
	object, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o")
	if err != nil || !object.Mode().IsRegular() || object.Size() == 0 {
		t.Fatal("actual SDK LLVM22 object is missing", err)
	}
	if profile == "effective-defaults" {
		// Exercise the ordinary entry point as well as compileOne: the reload
		// must consume defaults from the real invocation, not a test-only seam.
		out := t.TempDir()
		report := filepath.Join(t.TempDir(), "report.json")
		repository, err := filepath.Abs("../..")
		if err != nil {
			t.Fatal(err)
		}
		args, err := json.Marshal([]string{"-targets=linux/amd64", "-patterns=.", "-compile", "-keep-obj",
			"-strict-load", "-out=" + out, "-report=" + report, "-repo-root=" + repository})
		if err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(args))
		stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory, env, os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
		if err != nil {
			t.Fatalf("ordinary unchanged SDK CLI failed: %v\n%s%s", err, stdout, stderr)
		}
		data, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		var decoded matrixReport
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.Success != 1 || decoded.Failed != 0 ||
			decoded.NotApplicable != 0 || decoded.TotalAsm != 1 || decoded.TotalTargets != 1 {
			t.Fatalf("original SDK CLI complete result differs: %v\n%s", err, data)
		}
	}
}

func TestCompileOneX86SDKBytealgCountExistingObjects(t *testing.T) {
	compileX86SDKBytealgExistingObject(t, "count_amd64.s")
}

func TestCompileOneX86SDKBytealgIndexByteExistingObjects(t *testing.T) {
	compileX86SDKBytealgExistingObject(t, "indexbyte_amd64.s")
}

func compileX86SDKBytealgExistingObject(t *testing.T, name string) {
	t.Helper()
	compileX86SDKExistingObject(t, "internal/bytealg", name)
}

func compileX86SDKExistingObject(t *testing.T, packagePath, name string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, "effective-defaults")
	ctx := arm64PrivateCLIContext(t)
	dir := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(packagePath))
	actual, err := packages.Load(&packages.Config{Context: ctx, Dir: dir, Env: os.Environ(),
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedModule | packages.NeedDeps | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes,
	}, ".")
	if err != nil || len(actual) != 1 || len(actual[0].Errors) != 0 {
		t.Fatalf("original SDK %s load: %v, %+v", packagePath, err, actual)
	}
	if err := loadLinknameSyntax(actual[0]); err != nil {
		t.Fatal(err)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelections(actual, "linux/amd64", nil)
	t.Run(name, func(t *testing.T) {
		// Retain each whole original private-continuation program and its
		// ordinary compileOne path, including the guarded SDK retry.
		file := filepath.Join(t.TempDir(), "original.ll")
		if err := compileOne(actual[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
			asmTask{PkgPath: actual[0].PkgPath, AsmFile: filepath.Join(dir, name), OutLL: file}, false, config); err != nil {
			t.Fatalf("unchanged ordinary SDK %s regressed: %v", packagePath, err)
		}
		if object, err := os.Stat(strings.TrimSuffix(file, ".ll") + ".o"); err != nil || object.Size() == 0 {
			t.Fatalf("ordinary SDK %s object absent: %v", packagePath, err)
		}
	})
}
