package gotoolprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func amd64OriginalModuleDependencyFixture(t *testing.T, target string) (AMD64OriginalObservationRequest, string) {
	t.Helper()
	request := amd64OriginalObservationFixture(t, "nested")
	goos, _, _ := strings.Cut(target, "/")
	request.Target = target
	request.Environment = replaceEnv(request.Environment, map[string]string{"GOOS": goos})
	root := filepath.Dir(filepath.Dir(request.Directory))
	dependency := filepath.Join(root, "internal", "dependency")
	if err := os.Mkdir(dependency, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(request.Directory, "value.go"): `package observation
import dependency "example.invalid/observation/internal/dependency"
type Pair struct { Padding [3]uint64; High uint64 }
func Value(a uint64) uint64
func Reference(p *dependency.Pair) uint64 { return dependency.Read(p) }
`,
		filepath.Join(dependency, "dependency.go"): `package dependency
type Pair struct { Low, High uint64 }
func Read(p *Pair) uint64
`,
		filepath.Join(dependency, "local.h"): "#define DEPENDENCY_BIAS 7\n",
		filepath.Join(dependency, "read_amd64.s"): `#include "textflag.h"
#include "go_asm.h"
#include "local.h"
#ifdef Pair_Padding
WRONG_PACKAGE_HEADER_NAMESPACE
#endif
TEXT ·Read(SB),NOSPLIT,$0-16
MOVQ p+0(FP),AX
MOVQ Pair_High(AX),AX
ADDQ $DEPENDENCY_BIAS,AX
MOVQ AX,ret+8(FP)
RET
`,
	}
	for name, source := range files {
		if err := os.WriteFile(name, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return request, dependency
}

// The dependency's generated header belongs to its actual compiler export,
// not to the root's ordinary CPP or private local frame. A same-named root
// layout deliberately has a different offset; stock Go must select the
// dependency's own namespace before the observation can be accepted.
func TestAMD64OriginalObservationActualModuleDependencyRoles(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			request, dependency := amd64OriginalModuleDependencyFixture(t, target)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			stdout, diagnostic, err := RunBounded(ctx, request.Directory, request.Environment,
				request.GoBinary, "list", "-export", "-mod=readonly", ".")
			if err != nil || strings.TrimSpace(string(stdout)) != request.PackagePath || len(diagnostic) != 0 {
				t.Fatalf("stock Go rejects the dependency's original generated header: %v\n%s\n%s", err, stdout, diagnostic)
			}
			t.Logf("ORIGINAL_MODULE_DEPENDENCY_EXPORT target=%s package=%s", target, request.PackagePath)

			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil || observed == nil {
				t.Fatalf("dependency CPP was confused with the ordinary root: %v", err)
			}
			t.Cleanup(func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			})
			state := observed.state
			dep := state.packages["example.invalid/observation/internal/dependency"]
			if dep.Standard || dep.Module == nil || dep.Export == "" || dep.Dir != dependency {
				t.Fatalf("actual dependency source/export role was lost: %+v", dep)
			}
			assembly := filepath.Join(dependency, "read_amd64.s")
			if _, exists := state.files.cpp[assembly]; exists {
				t.Fatal("dependency acquired ordinary root CPP authority")
			}
			if _, exists := state.files.cpp[filepath.Join(request.Directory, "value_amd64.s")]; !exists {
				t.Fatal("root lost its independent ordinary CPP observation")
			}
			if _, exists := state.declarations["Read"]; exists {
				t.Fatal("dependency declaration became a root frame declaration")
			}

			// Corrupt only private witness hashes, never the shared toolchain or
			// compiler cache. Every retained role must participate in verification.
			for role, name := range map[string]string{
				"Go source": filepath.Join(dependency, "dependency.go"),
				"ASM":       assembly,
				"header":    filepath.Join(dependency, "local.h"),
				"export":    dep.Export,
			} {
				prior := state.files.hashes[name]
				if prior == "" {
					t.Fatalf("dependency %s lacks its original-byte guard", role)
				}
				state.files.hashes[name] = strings.Repeat("0", 64)
				err := state.files.verify()
				state.files.hashes[name] = prior
				if err == nil {
					t.Fatalf("dependency %s mutation escaped verification", role)
				}
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatalf("complete unchanged source/export graph failed independent recheck: %v", err)
			}

			// Exercise real private source changes as well as witness mutation.
			// Never overwrite an actual compiler-cache export or SDK file.
			changed := map[string]string{
				"linux/amd64":   filepath.Join(dependency, "dependency.go"),
				"darwin/amd64":  assembly,
				"windows/amd64": filepath.Join(dependency, "local.h"),
			}[target]
			original, err := os.ReadFile(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(changed, append(original, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("changed dependency source retained its public original observation")
			}
		})
	}
}
