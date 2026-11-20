package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestARM64NativeScratchActualAliasedBuiltinToolCache(t *testing.T) {
	pkg, request := arm64ScratchActualSourceFixture(t, "linux")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	query, err := goasmcmd.Observe(ctx, request.Directory, os.Environ(),
		request.GoBinary, "env", "GOCACHE")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := filepath.EvalSymlinks(strings.TrimSpace(string(query.Stdout)))
	if err != nil || !filepath.IsAbs(cache) {
		t.Fatalf("actual stock Go cache identity: %q %v", cache, err)
	}
	alias := filepath.Join(t.TempDir(), "actual-go-cache")
	if err := os.Symlink(cache, alias); err != nil {
		t.Fatal(err)
	}
	request.Environment = append(request.Environment, "GOCACHE="+alias)
	observations := make(map[string]goasmcmd.Observation)
	for _, tool := range []string{"asm", "compile", "objdump", "pack"} {
		observed, err := goasmcmd.Observe(ctx, request.Directory, request.Environment,
			request.GoBinary, "tool", "-n", tool)
		if err != nil {
			t.Fatalf("actual stock %s route: %v", tool, err)
		}
		observations[tool] = observed
		encoded, err := json.Marshal(observed)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("SCRATCH_TOOL_CHILD %s", encoded)
	}
	source, err := CaptureGoARM64ScratchSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	for tool, observed := range observations {
		original := strings.TrimSpace(string(observed.Stdout))
		physical, err := filepath.EvalSymlinks(original)
		if err != nil {
			t.Fatal(err)
		}
		data, err := goAMD64FrameRead(physical)
		if err != nil {
			t.Fatal(err)
		}
		if digest, present := source.inputs[physical]; !present || digest != sha256.Sum256(data) {
			t.Fatalf("actual %s binary bytes were not retained at their physical route", tool)
		}
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// A later alias redirection must invalidate the observation, even though
	// the previously sealed physical binaries and exports are still present.
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), alias); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
		t.Fatalf("redirected generated-input cache retained a native observation: %v", err)
	}
}

func TestARM64NativeScratchToolRoutesRetainSourceBoundaries(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, toolDir := filepath.Join(root, "cache"), filepath.Join(root, "sdk", "pkg", "tool", "host")
	for _, directory := range []string{cache, toolDir, filepath.Join(root, "foreign")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, extension := range []string{"", ".exe"} {
		for _, tool := range []string{"asm", "compile", "objdump", "pack"} {
			name := tool + extension
			for _, directory := range []string{toolDir, cache} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("role control, not executable evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			newSource := func() *GoARM64ScratchSource {
				return &GoARM64ScratchSource{
					request:  GoARM64ScratchCaptureRequest{GoBinary: filepath.Join(root, "sdk", "bin", "go"+extension)},
					settings: map[string]string{"GOCACHE": cache, "GOTOOLDIR": toolDir},
					inputs:   make(map[string][32]byte),
				}
			}
			t.Run(name+"/SDK", func(t *testing.T) {
				if err := newSource().readObservedTool(tool, filepath.Join(toolDir, name)); err != nil {
					t.Fatal(err)
				}
			})
			t.Run(name+"/cache", func(t *testing.T) {
				err := newSource().readObservedTool(tool, filepath.Join(cache, name))
				lazy := tool == "objdump" || tool == "pack"
				if lazy && err != nil || !lazy && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("registered lazy-tool role=%t: %v", lazy, err)
				}
			})
			for _, path := range []string{filepath.Join(root, "foreign", name), filepath.Join(cache, name+"-foreign"), name} {
				if err := newSource().readObservedTool(tool, path); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("foreign tool route acquired an input role: %q %v", path, err)
				}
			}
		}
	}
	foreign := filepath.Join(root, "foreign", "export")
	if err := os.WriteFile(foreign, []byte("not an observed cache export"), 0600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(cache, "escaped-export")
	if err := os.Symlink(foreign, escape); err != nil {
		t.Fatal(err)
	}
	source := &GoARM64ScratchSource{settings: map[string]string{"GOCACHE": cache}, inputs: make(map[string][32]byte)}
	if _, err := source.readObservedExport(arm64ScratchPackage{Export: escape}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("escaping cache export acquired a source role: %v", err)
	}
}
