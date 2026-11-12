//go:build go1.27

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Keep the complete SDK counterexample above the isolated hasADX and TEST
// rules. This is the ordinary typed GoModule API, not the CLI's SDK bridge,
// a manufactured declaration package or a filtered function translation.
func TestOriginalSDKMathBigAMD64WholeGoModule(t *testing.T) {
	setSimpleSDKProfile(t)
	t.Setenv("CGO_ENABLED", "0")
	loaded, err := loadPackage("math/big", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	pkg := loaded.Package
	if pkg.PkgPath != "math/big" || pkg.Types == nil || pkg.TypesSizes == nil || len(pkg.Syntax) == 0 {
		t.Fatal("actual selected SDK package lacks complete types, syntax or sizes")
	}
	input := ""
	for _, name := range pkg.OtherFiles {
		if filepath.Base(name) == "arith_amd64.s" {
			if input != "" {
				t.Fatal("duplicate selected SDK arithmetic assembly")
			}
			input = name
		}
	}
	if input == "" || filepath.Clean(input) != filepath.Join(pkg.Dir, "arith_amd64.s") {
		t.Fatal("the actual SDK did not select its original arithmetic assembly", input)
	}
	variable, valid := pkg.Types.Scope().Lookup("hasADX").(*types.Var)
	if !valid || variable.Pkg() != pkg.Types || variable.IsField() || variable.Type().Underlying() != types.Typ[types.Bool] || pkg.TypesSizes.Sizeof(variable.Type()) != 1 {
		t.Fatal("the original SDK feature flag is not a real same-package mutable bool")
	}
	source, inputs, err := plan9asm.ReadGoAssemblySourceWithReport(input, pkg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	goPackage := goPackageView(pkg)
	expanded := plan9asm.ExpandGoAssemblySource(goPackage, source, "amd64")
	parsed, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(expanded), plan9asm.GoAssemblerDefines("linux", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"·addVV": true, "·subVV": true, "·lshVU": true, "·rshVU": true,
		"·mulAddVWW": true, "·addMulVVWW": true,
	}
	if len(parsed.Funcs) != len(wanted) {
		t.Fatalf("the complete original SDK TEXT inventory changed: got %d, want %d", len(parsed.Funcs), len(wanted))
	}
	seen := make(map[string]bool, len(wanted))
	for _, function := range parsed.Funcs {
		if !wanted[function.Sym] || seen[function.Sym] {
			t.Fatal("unexpected or duplicate original SDK TEXT", function.Sym)
		}
		seen[function.Sym] = true
	}
	translated, err := plan9asm.TranslateGoModule(goPackage, source, plan9asm.GoModuleOptions{
		FileName: input, GOOS: "linux", GOARCH: "amd64", Sizes: pkg.TypesSizes, FrameSizes: pkg.TypesSizes,
		TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolveSymFunc(pkg.PkgPath),
	})
	if err != nil {
		t.Fatal("complete original arithmetic file did not translate through the ordinary GoModule API", err)
	}
	defer translated.Module.Dispose()
	if err := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction); err != nil {
		t.Fatal("the complete SDK module did not verify", err)
	}
	if len(translated.Functions) != len(wanted) {
		t.Fatal("GoModule omitted an original SDK TEXT", len(translated.Functions))
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	seen = make(map[string]bool, len(wanted))
	for _, function := range translated.Functions {
		if !wanted[function.TextSymbol] || seen[function.TextSymbol] || function.ResolvedSymbol != resolve(function.TextSymbol) {
			t.Fatal("the full source-to-output function mapping is not bijective", function)
		}
		entry := translated.Module.NamedFunction(function.ResolvedSymbol)
		if entry.IsNil() || entry.FirstBasicBlock().IsNil() {
			t.Fatal("an original SDK function has no translated body", function)
		}
		seen[function.TextSymbol] = true
	}
	ir := translated.Module.String()
	if !strings.Contains(ir, `load volatile i8, ptr @"math/big.hasADX"`) ||
		!strings.Contains(ir, `@"math/big.hasADX" = external global `) {
		t.Fatal("the actual mutable feature flag lost its external volatile byte read")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	llc := sdkLLVM22LLC(t, ctx)
	directory := t.TempDir()
	file, object := filepath.Join(directory, "arith-amd64.ll"), filepath.Join(directory, "arith-amd64.o")
	if err := os.WriteFile(file, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory, os.Environ(), llc,
		"-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", "-o", object, file)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("the complete ordinary GoModule SDK file failed LLVM22 object compilation: %v\n%s%s", err, stdout, stderr)
	}
	info, err := os.Stat(object)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatal("the complete SDK object is absent or empty", err)
	}
	for name, expected := range inputs.Inputs {
		data, err := os.ReadFile(name)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
			t.Fatal("an original SDK assembly/header input changed during translation", name, err)
		}
	}
	t.Logf("complete original math/big: functions=%d sourceSHA256=%x LLVM22 objectBytes=%d; no native execution claimed",
		len(translated.Functions), sha256.Sum256(source), info.Size())
}
