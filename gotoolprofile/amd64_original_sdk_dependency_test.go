package gotoolprofile

import (
	"path/filepath"
	"strings"
	"testing"
)

// SDK dependencies are actual source/export inputs, not ordinary third-party
// ASM packages or owners of the requested function's private local frame.
// A routine import must not make their special macros impersonate an ordinary
// package role. The unchanged original Go compiler accepts this complete graph.
func TestAMD64OriginalObservationActualSDKDependencyRoles(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "sdk-import")
			request.Target = target
			goos, _, _ := strings.Cut(target, "/")
			request.Environment = replaceEnv(request.Environment, map[string]string{"GOOS": goos})
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			output, diagnostic, err := RunBounded(ctx, request.Directory, request.Environment,
				request.GoBinary, "list", "-export", "-mod=readonly", ".")
			if err != nil {
				t.Fatalf("original Go rejects SDK-dependent first-party source: %v\n%s\n%s", err, output, diagnostic)
			}
			t.Logf("ORIGINAL_SDK_DEPENDENCY_EXPORT target=%s package=%s", target, strings.TrimSpace(string(output)))
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatalf("ordinary root must retain SDK dependencies under their own source/export role: %v", err)
			}
			t.Cleanup(func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			})
			if observed.state.packages["runtime"].Export == "" || observed.state.packages["errors"].Export == "" {
				t.Fatal("SDK graph vanished instead of retaining its actual compiler exports")
			}
			state := observed.state
			for _, pkg := range state.packages {
				if !pkg.Standard || pkg.ImportPath == "unsafe" {
					continue
				}
				for _, file := range append(append([]string(nil), pkg.GoFiles...), pkg.SFiles...) {
					name := filepath.Join(pkg.Dir, file)
					if state.files.hashes[name] == "" {
						t.Fatalf("SDK source lost original byte guard: %s", name)
					}
					if _, exists := state.files.cpp[name]; exists {
						t.Fatalf("SDK dependency acquired ordinary target CPP authority: %s", name)
					}
				}
			}
			if _, exists := state.files.cpp[filepath.Join(request.Directory, "value_amd64.s")]; !exists {
				t.Fatal("ordinary target lost its independent CPP proof")
			}
			goRoot := state.environment["GOROOT"]
			macros, err := CaptureAssemblerMacros(goRoot, state.profile, "runtime")
			if err != nil {
				t.Fatal(err)
			}
			if macros.PackageRole == "allow_asm_abi_path" && ValidateOrdinaryAssemblerMacros(macros, state.profile, "runtime") == nil {
				t.Fatal("special SDK macros became an ordinary target macro permission")
			}
			for file, digest := range macros.ToolSourceSHA256 {
				name, err := CPPRegularSource(goRoot, file)
				if err != nil || state.files.hashes[name] != digest {
					t.Fatalf("SDK special macro registration lost exact source guard: %s: %v", file, err)
				}
			}
			if state.files.hashes[filepath.Join(goRoot, "pkg", "include", "textflag.h")] == "" {
				t.Fatal("actual SDK shared headers lost their lifetime guard")
			}
			// Corrupt the private witness, never the shared SDK or Go cache.
			// Each retained role must participate in the same live byte check.
			runtimePackage := state.packages["runtime"]
			for role, name := range map[string]string{
				"source": filepath.Join(runtimePackage.Dir, runtimePackage.GoFiles[0]),
				"ASM":    filepath.Join(runtimePackage.Dir, runtimePackage.SFiles[0]),
				"export": runtimePackage.Export,
				"tool":   filepath.Join(goRoot, "src", "cmd", "go", "internal", "work", "gc.go"),
				"header": filepath.Join(goRoot, "pkg", "include", "textflag.h"),
			} {
				prior := state.files.hashes[name]
				if prior == "" {
					t.Fatalf("missing SDK %s witness", role)
				}
				state.files.hashes[name] = strings.Repeat("0", 64)
				err := state.files.verify()
				state.files.hashes[name] = prior
				if err == nil {
					t.Fatalf("SDK %s witness mutation escaped original-byte verification", role)
				}
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatalf("independent SDK source/export/tool recapture: %v", err)
			}
		})
	}
}
