//go:build go1.27

package main

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestRunOneTargetSDKFixedLocalPreservesActualDefaultProfile(t *testing.T) {
	runSDKFixedLocalDefaultProfile(t, false)
}

func TestRunOneTargetSDKFixedLocalCanonicalCommandPaths(t *testing.T) {
	runSDKFixedLocalDefaultProfile(t, true)
}

func runSDKFixedLocalDefaultProfile(t *testing.T, commandPaths bool) {
	t.Helper()
	for _, profile := range []string{"off", "original-config"} {
		t.Run(profile, func(t *testing.T) {
			for key, value := range map[string]string{
				"GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "",
				"GOPACKAGESDRIVER": "off", "GOOS": "linux", "GOARCH": "amd64",
				"GO386": "", "GOARM": "", "GOARM64": "", "GOWASM": "",
			} {
				t.Setenv(key, value)
			}
			// Preserve actual compiler defaults, including CGO. An existing
			// config is a producer input, not a request to replace it with off.
			for _, key := range []string{"CGO_ENABLED", "GOAMD64", "GOPROXY"} {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			configPath := "off"
			if profile == "original-config" {
				parent, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				configPath = filepath.Join(parent, "go-env")
				if err := os.WriteFile(configPath, []byte("GOPROXY=https://original-config.invalid,direct\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("GOENV", configPath)
			if commandPaths {
				parent := t.TempDir()
				for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
					// Unlike filepath.Join, this preserves the original command
					// spelling until the real load-boundary resolver observes it.
					path := parent + string(filepath.Separator) + "." + string(filepath.Separator) + strings.ToLower(key)
					if runtime.GOOS == "windows" {
						path = filepath.ToSlash(path)
					}
					if err := os.MkdirAll(path, 0700); err != nil {
						t.Fatal(err)
					}
					t.Setenv(key, path)
				}
			}
			const path = "vendor/golang.org/x/crypto/chacha20poly1305"
			input := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(path), "chacha20poly1305_amd64.s")
			original, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			ctx := arm64PrivateCLIContext(t)
			defaults, stderr, err := gotoolprofile.RunBounded(ctx, "", os.Environ(), "go", "env", "CGO_ENABLED", "GOENV", "GOPROXY")
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual compiler/default config precondition: %v; %s", err, stderr)
			}
			t.Logf("actual original default profile:\n%s", defaults)
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = ctx
			output := t.TempDir()
			report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"},
				[]string{path}, nil, nil, "", output, false, 0, false, false, true, "../..", config)
			if err != nil || report.TotalAsm != 1 || len(report.AsmFiles) != 1 || report.Success != 1 ||
				report.Failed != 0 || report.NotApplicable != 0 || len(report.Fails) != 0 {
				t.Fatalf("complete actual SDK source failed: %v; %+v", err, report)
			}
			irPath := filepath.Join(output, filepath.FromSlash(path), filepath.Base(input)+".ll")
			ir, err := os.ReadFile(irPath)
			if err != nil || !bytes.Contains(ir, []byte("define ")) ||
				!bytes.Contains(ir, []byte(`target triple = "x86_64-unknown-linux-gnu"`)) {
				t.Fatal("complete original SDK source omitted target LLVM definitions", err)
			}
			object, err := elf.Open(strings.TrimSuffix(irPath, ".ll") + ".o")
			if err != nil {
				t.Fatal(err)
			}
			defer object.Close()
			if object.Machine != elf.EM_X86_64 || object.Type != elf.ET_REL ||
				object.Section(".text") == nil || object.Section(".text").Size == 0 {
				t.Fatal("complete original SDK source omitted AMD64 ELF text")
			}
			after, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("complete original SDK source was cropped or replaced", err)
			}
		})
	}
}
