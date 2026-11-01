package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

const arm64PrivateCLISource = `DATA constant<>(SB)/8,$7
GLOBL constant<>(SB),8,$8
TEXT ·Run(SB),4,$0-16
MOVD x+0(FP),R19
MOVD constant<>(SB),R0
ADDS $1,R19,R9
CALL mix<>(SB)
EOR R0,R20
MOVD R20,ret+8(FP)
RET
TEXT mix<>(SB),4,$0-0
ADC $0,R9,R20
MUL R19,R20,R20
RET
`

func arm64PrivateCLIPackage(t *testing.T, declaration, source string) (*packages.Package, string) {
	t.Helper()
	dir := t.TempDir()
	goPath, asmPath := filepath.Join(dir, "p.go"), filepath.Join(dir, "p_arm64.s")
	for path, contents := range map[string]string{goPath: declaration, asmPath: source} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, goPath, declaration, 0)
	if err != nil {
		t.Fatal(err)
	}
	config := types.Config{Sizes: types.SizesFor("gc", "arm64")}
	typed, err := config.Check("example.com/privatearm64", fset, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &packages.Package{
		PkgPath: typed.Path(), Types: typed, TypesSizes: config.Sizes,
		GoFiles: []string{goPath}, CompiledGoFiles: []string{goPath},
	}, asmPath
}

func arm64PrivateCLIContext(t *testing.T) context.Context {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	if testDeadline, present := t.Deadline(); present && testDeadline.Add(-3*time.Second).Before(deadline) {
		deadline = testDeadline.Add(-3 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	return ctx
}

func requireARM64PrivateCLIOriginalObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local")
	stdout, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, env,
		"go", "tool", "asm", "-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-o", object, input)
	if err != nil {
		t.Fatalf("original Go assembler: %v\n%s%s", err, stdout, stderr)
	}
	if info, err := os.Stat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("original Go did not produce a nonempty object: %v", err)
	}
}

func TestCompileOneARM64PrivateRegisterSource(t *testing.T) {
	requireARM64PrivateCLIOriginalObject(t, arm64PrivateCLISource)
	pkg, input := arm64PrivateCLIPackage(t, "package p\nfunc Run(uint64) uint64\n", arm64PrivateCLISource)
	for _, target := range []struct{ name, os, triple string }{
		{"darwin", "darwin", "aarch64-apple-darwin"},
		{"linux", "linux", "aarch64-unknown-linux-gnu"},
		{"linux_musl", "linux", "aarch64-unknown-linux-musl"},
		{"freebsd", "freebsd", "aarch64-unknown-freebsd"},
		{"windows", "windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			output := filepath.Join(t.TempDir(), "private.ll")
			if err := compileOne(pkg, plan9asm.ArchARM64, target.os, "arm64", target.triple,
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatal(err)
			}
			ir, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(ir), "@\""+pkg.PkgPath+".mix$local\"") ||
				strings.Count(string(ir), "define ") != 1 || !strings.Contains(string(ir), "\nbb__5f_5farm64_5fprivate_5f") {
				t.Fatalf("private helper was not kept in its source caller's CFG:\n%s", ir)
			}
			object := strings.TrimSuffix(output, ".ll") + ".o"
			if info, err := os.Stat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 did not produce a nonempty %s object: %v", target.name, err)
			}
		})
	}
}

func TestCompileOneARM64PrivateSourceBeforeModuleSplit(t *testing.T) {
	source := arm64PrivateCLISource + strings.Replace(arm64PrivateCLISource[strings.Index(arm64PrivateCLISource, "TEXT ·Run"):strings.Index(arm64PrivateCLISource, "TEXT mix")],
		"·Run", "·Other", 1)
	requireARM64PrivateCLIOriginalObject(t, source)
	pkg, input := arm64PrivateCLIPackage(t,
		"package p\nfunc Run(uint64) uint64\nfunc Other(uint64) uint64\n", source)
	config, err := resolveCompileConfig(true, "", false, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions, config.MaxInstructions = 1, 1
	config.Context = arm64PrivateCLIContext(t)
	output := filepath.Join(t.TempDir(), "private.ll")
	if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{output, strings.TrimSuffix(output, ".ll") + ".part-0001.ll"} {
		ir, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(ir), "define ") != 1 || !strings.Contains(string(ir), "\nbb__5f_5farm64_5fprivate_5f") {
			t.Fatalf("chunk lost its closed private source: %s", filename)
		}
		if _, err := os.Stat(strings.TrimSuffix(filename, ".ll") + ".o"); !os.IsNotExist(err) {
			t.Fatalf("temporary chunk object was not released: %v", err)
		}
	}
}

func TestCompileOneARM64PrivateSourceRejectsHiddenEscape(t *testing.T) {
	for _, test := range []struct{ name, suffix string }{
		{"late_address", "TEXT ·Other(SB),4,$0-0\nMOVD $mix<>(SB),R0\nRET\n"},
		{"data_address", "DATA pointer<>(SB)/8,$mix<>(SB)\nGLOBL pointer<>(SB),8,$8\n"},
		{"non_call", "TEXT ·Other(SB),4,$0-0\nB mix<>(SB)\n"},
		{"native_pc", "TEXT ·Other(SB),4,$0-0\nADR 4(PC),R0\nRET\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := arm64PrivateCLISource + test.suffix
			requireARM64PrivateCLIOriginalObject(t, source)
			pkg, input := arm64PrivateCLIPackage(t,
				"package p\nfunc Run(uint64) uint64\nfunc Other()\n", source)
			config, err := resolveCompileConfig(true, "", false, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.MaxFunctions, config.MaxInstructions = 1, 1
			config.Context = arm64PrivateCLIContext(t)
			output := filepath.Join(t.TempDir(), "private.ll")
			err = compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("unproved private/native source was not rejected: %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("unsafe full-file contract emitted an earlier chunk: %v", err)
			}
		})
	}
}
