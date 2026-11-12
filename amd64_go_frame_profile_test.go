package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestGoAMD64FrameSourceActualCPUProfiles(t *testing.T) {
	// Share only this root's owned build cache. Go 1.27 builds its objdump
	// helper there; rebuilding that tool for every profile adds no coverage.
	// Every fixture retains its own source/module/temp directories and still
	// runs actual Go selection, export, object and post-capture verification.
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		for _, profile := range []string{"v1", "v2", "v3", "v4"} {
			t.Run(target.name+"/"+profile, func(t *testing.T) {
				pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
				request.Target = target.name
				request.Environment = append(request.Environment, "GOAMD64="+profile)
				options.TargetTriple = target.triple
				assembly := filepath.Join(request.Directory, request.AssemblyFile)
				original, err := os.ReadFile(assembly)
				if err != nil {
					t.Fatal(err)
				}
				// Go must select the exact feature-tagged original file before
				// the frame factory independently observes its native object.
				tagged := fmt.Sprintf("//go:build amd64.%s\n\n%s", profile, original)
				if err := os.WriteFile(assembly, []byte(tagged), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				env := append(append([]string(nil), request.Environment...),
					"GOOS="+strings.Split(target.name, "/")[0], "GOARCH=amd64",
					"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
				output, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
					"list", "-json", "-compiled", "-export", "-mod=readonly", ".")
				if err != nil {
					t.Fatalf("independent actual Go profile control: %v\n%s", err, output)
				}
				var selected goAMD64FrameSelection
				if err := json.Unmarshal(output, &selected); err != nil || selected.Export == "" ||
					len(selected.SFiles) != 1 || selected.SFiles[0] != request.AssemblyFile {
					t.Fatalf("actual Go omitted profile-selected assembly/export: %v\n%s", err, output)
				}
				source := requireGoAMD64FrameCapture(t, pkg, request)
				if source.env["GOAMD64"] != profile || source.env["GOOS"]+"/"+source.env["GOARCH"] != target.name {
					t.Fatal("capture substituted a different actual CPU/target profile")
				}
				bound, err := source.BindFixedLocal(ctx, pkg, file, options)
				if err != nil {
					t.Fatal(err)
				}
				fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "profile.ll", "profile.o", ir)
					compileLLVMToObject(t, llc, target.triple, "profile-opt.ll", "profile-opt.o", x86MulDivRoundOptimize(t, ir))
				})
				if err := source.Verify(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestGoAMD64FrameSourceCPUProfileRevocation(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, profile := range []string{"v1", "v2", "v3", "v4"} {
		t.Run(profile, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			request.Environment = append(request.Environment, "GOAMD64="+profile)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			before := append([]string(nil), source.request.Environment...)
			replacement := "v1"
			if profile == "v1" {
				replacement = "v2"
			}
			source.request.Environment = append(source.request.Environment, "GOAMD64="+replacement)
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a different actual CPU profile retained the original observation", err)
			}
			source.request.Environment = before
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("restoring the CPU profile revived a revoked observation", err)
			}
		})
	}
}

func TestGoAMD64FrameSourceCPUProfilesDoNotGrantGeneratedCPP(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, profile := range []string{"v1", "v2", "v3", "v4"} {
		t.Run(profile, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			request.Environment = append(request.Environment, "GOAMD64="+profile)
			name := filepath.Join(request.Directory, request.AssemblyFile)
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			conditional := fmt.Sprintf("#ifdef GOAMD64_%s\n#include \"go_asm.h\"\n%s\n#endif\n", profile, original)
			if err := os.WriteFile(name, []byte(conditional), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil {
				source.Close()
				t.Fatal("conditional generated header acquired an ordinary profile observation")
			}
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "qualified metadata") {
				t.Fatal("generated CPP still needs its own source mapping, not CPU rejection", err)
			}
		})
	}
}
