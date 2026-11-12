package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestDataOnlyAssemblyProducesObjectsAcrossSupportedTargets(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var llvmNM string
	for _, name := range []string{"llvm-nm-22", "llvm-nm"} {
		tool, err := exec.LookPath(name)
		if err == nil && requireLLVM22LLC(tool) == nil {
			llvmNM = tool
			break
		}
	}
	if llvmNM == "" {
		t.Fatal("LLVM 22 nm is required for the actual data object oracle")
	}
	for _, target := range []string{
		"darwin/amd64", "linux/amd64", "windows/amd64",
		"linux/386", "windows/386", "linux/arm",
		"darwin/arm64", "linux/arm64", "windows/arm64",
		"js/wasm", "wasip1/wasm",
	} {
		for _, profiled := range []bool{false, true} {
			mode := "ordinary"
			if profiled {
				mode = "profiled"
			}
			t.Run(target+"/"+mode, func(t *testing.T) {
				input, dir := featureConsumerFixture(t)
				if err := os.Remove(filepath.Join(dir, "probe_amd64.s")); err != nil {
					t.Fatal(err)
				}
				const source = "DATA ·payload+0(SB)/8, $0x123456789abcdef\nGLOBL ·payload(SB),$8\n"
				if err := os.WriteFile(filepath.Join(dir, "data.s"), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				delete(input.Sources, "probe_amd64.s")
				delete(input.Headers, "probe_amd64.s")
				input.Sources["data.s"] = featureBytesSHA256([]byte(source))
				input.Headers["data.s"] = source
				const bss = "GLOBL ·zero(SB),$8\n"
				if err := os.WriteFile(filepath.Join(dir, "bss.s"), []byte(bss), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources["bss.s"] = featureBytesSHA256([]byte(bss))
				input.Headers["bss.s"] = bss
				input.Directories["."] = []string{"bss.s", "data.s", "fallback.go", "go.mod", "selected.go"}
				input.AsmFiles = []string{"bss.s", "data.s"}
				binary, err := exec.LookPath("go")
				if err != nil {
					t.Fatal(err)
				}
				binary, err = filepath.Abs(binary)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				input.Observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), os.Environ(), target, nil, gotoolprofile.RunBounded)
				if err != nil {
					t.Fatal(err)
				}
				input.ID = gotoolprofile.ProfileID(input.Observed)
				env := featureEnvironment(os.Environ(), input.Observed.Environment)
				_, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, binary, "list", "-export", ".")
				if err != nil {
					t.Fatalf("actual Go data-only package: %v\n%s", err, stderr)
				}
				// Use the assembler's own symbol/data listing. Go 1.27.1 nm
				// crashes when enumerating a GLOBL-only archive member; that
				// separate tool failure is not an assembly rejection or skip.
				for file, symbol := range map[string]string{"data.s": "payload", "bss.s": "zero"} {
					goObject := filepath.Join(t.TempDir(), file+".o")
					listing, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, binary, "tool", "asm", "-S", "-p", input.Module, "-o", goObject, file)
					if err != nil || !strings.Contains(string(listing)+string(stderr), input.Module+"."+symbol) {
						t.Fatalf("actual Go assembler lost %s symbol: %v\n%s\n%s", symbol, err, listing, stderr)
					}
					if info, err := os.Stat(goObject); err != nil || info.Size() == 0 {
						t.Fatalf("actual Go assembler must produce a nonempty object: %v", err)
					}
				}
				config, err := resolveCompileConfig(true, "", true, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.Context = ctx
				if profiled {
					config.FeaturePath = writeFeatureInput(t, input)
				}
				spec, err := parseTargetSpec(target)
				if err != nil {
					t.Fatal(err)
				}
				output := t.TempDir()
				t.Chdir(dir)
				report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, output, false, 0, true, false, true, repoRoot, config)
				if err != nil || report.Success != 2 || report.Failed != 0 || report.NotApplicable != 0 {
					t.Fatalf("data-only source did not compile: report=%+v err=%v", report, err)
				}
				for file, symbol := range map[string]string{"data.s": "payload", "bss.s": "zero"} {
					object := filepath.Join(output, filepath.FromSlash(input.Module), file+".o")
					symbols, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, llvmNM, "--defined-only", object)
					if err != nil || !strings.Contains(string(symbols), input.Module+"."+symbol) {
						t.Fatalf("LLVM 22 object lost %s symbol: %v\n%s\n%s", symbol, err, symbols, stderr)
					}
				}
				if profiled {
					if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
						t.Fatalf("data-only scope lacks actual CPP/LLVM consumer proof: %v", err)
					}
				}
			})
		}
	}
}
