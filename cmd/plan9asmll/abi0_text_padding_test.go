package main

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestValidateDeclaredTextArgSizesAcceptsOnlyABI0TailPadding(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		for _, size := range []int64{0, 1, 4, 8, 12, 17, 28} {
			word := int64(wordSize(arch))
			padded := alignOff(size, word)
			for _, declared := range []int64{size, padded, padded + 1, padded + word} {
				t.Run(fmt.Sprintf("%s/%d/%d", arch, size, declared), func(t *testing.T) {
					file := &plan9asm.File{Funcs: []plan9asm.Func{{
						Sym: "·Value", ArgSize: declared,
						Instrs: []plan9asm.Instr{{Op: plan9asm.OpTEXT,
							Raw: fmt.Sprintf("TEXT ·Value(SB),$0-%d", declared)}},
					}}}
					resolve := func(string) string { return "example.com/padded.Value" }
					err := validateDeclaredTextArgSizes(file, resolve,
						map[string]int64{"example.com/padded.Value": size}, arch)
					wantErr := declared != size && declared != padded
					if (err != nil) != wantErr {
						t.Fatalf("logical=%d, ABI0=%d, TEXT=%d: %v", size, padded, declared, err)
					}
				})
			}
		}
	}
	for _, test := range []struct{ symbol, arch string }{
		{"·Value<ABIInternal>", "arm64"},
		{"·Value", "unknown"},
	} {
		file := &plan9asm.File{Funcs: []plan9asm.Func{{
			Sym: test.symbol, ArgSize: 16,
			Instrs: []plan9asm.Instr{{Op: plan9asm.OpTEXT, Raw: "TEXT " + test.symbol + "(SB),$0-16"}},
		}}}
		resolve := func(string) string { return "example.com/padded.Value" }
		if err := validateDeclaredTextArgSizes(file, resolve,
			map[string]int64{"example.com/padded.Value": 12}, test.arch); err == nil {
			t.Fatalf("invented an ABI0 alignment contract for %s/%s", test.arch, test.symbol)
		}
	}
}

func paddedSqrtPackage(t *testing.T, name string) *packages.Package {
	t.Helper()
	path := "example.com/padded"
	pkg := types.NewPackage(path, "padded")
	param := types.NewParam(token.NoPos, pkg, "x", types.Typ[types.Float32])
	result := types.NewParam(token.NoPos, pkg, "r", types.Typ[types.Float32])
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(param), types.NewTuple(result), false)
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, name, sig))
	return &packages.Package{PkgPath: path, Types: pkg, Imports: map[string]*packages.Package{}}
}

func TestCompileOnePaddedSqrtUsesOriginalExternalTEXT(t *testing.T) {
	cfg, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	// These are the original TEXT spelling, input offset and result offset of
	// barnex/fmath.Sqrtf and chran554/go3d/fmath.Sqrt, including the +0 symbol.
	for _, name := range []string{"Sqrtf", "Sqrt"} {
		pkg := paddedSqrtPackage(t, name)
		for _, target := range []struct{ os, triple string }{
			{"linux", "x86_64-unknown-linux-gnu"},
			{"darwin", "x86_64-apple-darwin"},
			{"windows", "x86_64-pc-windows-msvc"},
		} {
			t.Run(name+"/"+target.os, func(t *testing.T) {
				dir := t.TempDir()
				asm := filepath.Join(dir, "sqrt_amd64.s")
				source := fmt.Sprintf("TEXT ·%s+0(SB),$0-16\nSQRTSS x+0(FP),X0\nMOVSS X0,r+8(FP)\nRET\n", name)
				if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(dir, "sqrt.ll")
				err := compileOne(pkg, plan9asm.ArchAMD64, target.os, "amd64", target.triple,
					asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out}, false, cfg)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(ir), `asm sideeffect "sqrtss $2, $0"`) {
					t.Fatalf("missing original f32 square root:\n%s", ir)
				}
			})
		}
	}
}

func TestCompileOnePaddedSqrtDoesNotPermitUndeclaredFPBytes(t *testing.T) {
	pkg := paddedSqrtPackage(t, "Sqrt")
	for _, test := range []struct{ name, body string }{
		{"input padding", "SQRTSS x+4(FP),X0\nMOVSS X0,r+8(FP)"},
		{"wrong result offset", "SQRTSS x+0(FP),X0\nMOVSS X0,r+4(FP)"},
		{"tail padding", "SQRTSS x+0(FP),X0\nMOVSS X0,r+12(FP)"},
		{"tail padding address", "SQRTSS x+0(FP),X0\nLEAQ r+12(FP),AX\nMOVSS X0,r+8(FP)"},
		{"wide read", "SQRTSD x+0(FP),X0\nMOVSS X0,r+8(FP)"},
		{"wide write", "SQRTSS x+0(FP),X0\nMOVSD X0,r+8(FP)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			asm := filepath.Join(dir, "sqrt_amd64.s")
			source := "TEXT ·Sqrt+0(SB),$0-16\n" + test.body + "\nRET\n"
			if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: filepath.Join(dir, "sqrt.ll")}, false, compileConfig{})
			if err == nil || !strings.Contains(err.Error(), "translate:") {
				t.Fatalf("want a translation failure for undeclared FP bytes, got %v", err)
			}
		})
	}
}
