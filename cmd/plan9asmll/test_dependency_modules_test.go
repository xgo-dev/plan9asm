package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestTestModuleConsumerRejectsCallerSuppliedStdlibRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("package caller\n")
	if err := os.WriteFile(filepath.Join(root, "caller.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := featureBytesSHA256(data)
	source := gotoolprofile.TestModuleSource{
		Protocol: gotoolprofile.TestDependencyModuleProtocol, GoVersion: runtime.Version(),
		Sources: map[string]string{"caller.go": digest}, Headers: map[string]string{"caller.go": string(data)},
		Directories: map[string][]gotoolprofile.TestSourceEntry{
			".": {{Name: "caller.go", Kind: "file", SHA256: digest}},
		},
	}
	// A self-consistent snapshot is not authority to impersonate actual GOROOT.
	if err := gotoolprofile.VerifyTestModuleSource(ctx, source, root, ""); err != nil {
		t.Fatal(err)
	}
	consumer := featureConsumer{
		Context: ctx, Root: runtime.GOROOT(), Observed: &gotoolprofile.Observation{GoVersion: runtime.Version()},
	}
	if err := consumer.bindTestModuleSource(source, root, ""); err == nil {
		t.Fatal("caller-supplied stdlib@GoVersion temp root acquired actual Go source/tool authority")
	}
	if len(consumer.TestModuleGuards) != 0 {
		t.Fatal("failed binding retained an authorized source-root guard")
	}
}

func TestTestModuleConsumerRejectsActualModuleBoundaryChanges(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	consumer := featureConsumer{Input: &featureInput{Module: "example.invalid/main"}}
	for name, actual := range map[string]*packages.Package{
		"candidate reused as foreign": {
			PkgPath: "example.invalid/main/loader",
			Module:  &packages.Module{Path: "example.invalid/main", Version: "v1.0.0", Dir: root},
		},
		"unversioned owner": {
			PkgPath: "example.invalid/main/loader",
			Module:  &packages.Module{Path: "example.invalid/main/loader", Dir: root},
		},
		"package owner changed": {
			PkgPath: "example.invalid/main/loader",
			Module:  &packages.Module{Path: "example.invalid/other", Version: "v1.0.0", Dir: root},
		},
		"local replacement": {
			PkgPath: "example.invalid/foreign",
			Module: &packages.Module{
				Path: "example.invalid/foreign", Version: "v1.0.0", Dir: root,
				Replace: &packages.Module{Path: "../local", Dir: root},
			},
		},
		"replacement source root changed": {
			PkgPath: "example.invalid/foreign",
			Module: &packages.Module{
				Path: "example.invalid/foreign", Version: "v1.0.0", Dir: root,
				Replace: &packages.Module{Path: "example.invalid/fork", Version: "v1.0.1", Dir: filepath.Join(root, "missing")},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := consumer.foreignTestSourcePackage(actual); err == nil {
				t.Fatal("unproven actual Module/Replace acquired foreign source authority")
			}
		})
	}
}

func TestTestModuleConsumerExportGuardThroughFinalVerification(t *testing.T) {
	input, root := testDeclarationRoleFixture(t, "linux/amd64")
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(t.TempDir(), "actual-export.a")
	before := []byte("owned actual export fixture")
	if err := os.WriteFile(export, before, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer := featureConsumer{
		Context: ctx, Input: input, Dir: root,
		GeneratedGuard: map[string]string{export: featureBytesSHA256(before)},
	}
	if err := consumer.verifySources(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(export, []byte("changed after load"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifySources(); err == nil {
		t.Fatal("actual dependency export changed before final object without failing")
	}
}
