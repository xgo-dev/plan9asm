package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func TestTranslateGoModule_UsesDeclsAndLinkname(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func Compare(a, b int) int
//go:linkname cmp runtime.cmp
func cmp(a, b int) int
`)

	asm := []byte(`TEXT ·Compare(SB),NOSPLIT,$0-24
	CALL runtime·cmp(SB)
	MOVD $0, R0
	RET
`)

	tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
		FileName:     "compare_arm64.s",
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()

	if _, ok := tr.Signatures["test/pkg.Compare"]; !ok {
		t.Fatalf("missing package function signature")
	}
	if _, ok := tr.Signatures["runtime.cmp"]; !ok {
		t.Fatalf("missing go:linkname target signature")
	}
	if got := tr.Functions[0].ResolvedSymbol; got != "test/pkg.Compare" {
		t.Fatalf("resolved symbol: got %q", got)
	}
}

func TestTranslateGoModule_ExpandsGeneratedWasmOffsets(t *testing.T) {
	pkg := mustGoPackage(t, "runtime", `package runtime
type gobuf struct {
	sp   uintptr
	pc   uintptr
	g    uintptr
	ctxt uintptr
}
func gogo(buf *gobuf)
`)
	tr, err := TranslateGoModule(pkg, []byte(`#include "go_asm.h"
TEXT ·gogo(SB),NOSPLIT,$0-8
	MOVD buf+0(FP), R0
	MOVD gobuf_g(R0), R1
	RET
`), GoModuleOptions{
		FileName:     "asm_wasm.s",
		GOARCH:       "wasm",
		TargetTriple: "wasm32-unknown-unknown",
		ResolveSym:   testResolveSym("runtime"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	ir := tr.Module.String()
	if !strings.Contains(ir, "getelementptr i8") || !strings.Contains(ir, "i32 16") ||
		!strings.Contains(ir, "load volatile i64") {
		t.Fatalf("generated gobuf_g offset was not resolved through go_asm.h:\n%s", ir)
	}
}

func TestTranslateGoModule_UsesCallerWasmTypeSizes(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/wasm32", `package wasm32
func Consume(value int, data []byte) int
`)
	tr, err := TranslateGoModule(pkg, []byte(`TEXT ·Consume(SB),NOSPLIT,$0-16
	I64Const $0
	I64Store ret+32(FP)
	RET
`), GoModuleOptions{
		FileName:     "consume_wasm.s",
		GOARCH:       "wasm",
		Sizes:        &types.StdSizes{WordSize: 4, MaxAlign: 4},
		FrameSizes:   &types.StdSizes{WordSize: 8, MaxAlign: 8},
		TargetTriple: "wasm32-unknown-unknown",
		ResolveSym:   testResolveSym("example.com/wasm32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	sig := tr.Signatures["example.com/wasm32.Consume"]
	want := []LLVMType{I32, "{ ptr, i32, i32 }"}
	if len(sig.Args) != len(want) {
		t.Fatalf("Consume args = %v, want %v", sig.Args, want)
	}
	for i := range want {
		if sig.Args[i] != want[i] {
			t.Fatalf("Consume arg %d = %s, want %s", i, sig.Args[i], want[i])
		}
	}
	if got := sig.Frame.Params[3].Offset; got != 24 {
		t.Fatalf("slice capacity FP offset = %d, want official Go wasm offset 24", got)
	}
	if got := sig.Frame.Results[0].Offset; got != 32 {
		t.Fatalf("result FP offset = %d, want official Go wasm offset 32", got)
	}
}

func TestTranslateGoModule_UsesManualSigForPlainLocalHelper(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func IndexByte(b []byte, c byte) int
`)
	manualCalled := false
	asm := []byte(`TEXT ·IndexByte(SB),NOSPLIT,$0-40
	B indexbytebody<>(SB)

TEXT indexbytebody<>(SB),NOSPLIT,$0
	MOVD $0, R0
	RET
`)

	tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
		FileName:     "indexbyte_arm64.s",
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
		ManualSig: func(resolved string) (FuncSig, bool) {
			if resolved != "test/pkg.indexbytebody" {
				return FuncSig{}, false
			}
			manualCalled = true
			return FuncSig{Name: resolved, Args: []LLVMType{"{ ptr, i64, i64 }", "i8"}, Ret: I64}, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if !manualCalled {
		t.Fatalf("manual signature callback was not used")
	}
	if _, ok := tr.Signatures["test/pkg.indexbytebody"]; !ok {
		t.Fatalf("missing manual helper signature")
	}
}

func TestTranslateGoModule_UsesManualSigExternalName(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func Call()
`)
	asm := []byte(`TEXT ·Call(SB),NOSPLIT,$0-0
	CALL runtime·memmove(SB)
	RET
`)

	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
				FileName:   "call_" + goarch + ".s",
				GOARCH:     goarch,
				ResolveSym: testResolveSym("test/pkg"),
				ManualSig: func(resolved string) (FuncSig, bool) {
					if resolved != "runtime.memmove" {
						return FuncSig{}, false
					}
					return FuncSig{Name: "memmove", Args: []LLVMType{Ptr, Ptr, I64}, Ret: Ptr}, true
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Module.Dispose()
			ir := tr.Module.String()
			if !strings.Contains(ir, "@memmove") || strings.Contains(ir, "runtime.memmove") {
				t.Fatalf("manual external name not applied:\n%s", ir)
			}
		})
	}
}

func TestTranslateGoModule_X87Mode(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func Round(x float64) int64
`)
	asm := []byte(`TEXT ·Round(SB),NOSPLIT,$0-16
	FINIT
	FMOVD x+0(FP), F0
	FRNDINT
	FMOVVP F0, ret+8(FP)
	RET
`)

	tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
		FileName:     "round_386.s",
		GOARCH:       "386",
		TargetTriple: "i386-unknown-linux-gnu",
		X87Mode:      X87Software,
		ResolveSym:   testResolveSym("test/pkg"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()

	ir := tr.Module.String()
	if !strings.Contains(ir, "@llvm.ctlz.i64") || strings.Contains(ir, "asm sideeffect") {
		t.Fatalf("software x87 mode was not propagated:\n%s", ir)
	}
}

func mustGoPackage(t *testing.T, pkgPath, src string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pkg.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{}
	pkg, err := conf.Check(pkgPath, fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: pkgPath, Types: pkg, Syntax: []*ast.File{f}}
}

func testResolveSym(pkgPath string) func(string) string {
	return func(sym string) string {
		sym = goStripABISuffix(sym)
		if strings.HasPrefix(sym, "·") {
			return pkgPath + "." + strings.TrimPrefix(sym, "·")
		}
		if !strings.Contains(sym, "·") && !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
			return pkgPath + "." + sym
		}
		sym = strings.ReplaceAll(sym, "∕", "/")
		return strings.ReplaceAll(sym, "·", ".")
	}
}

func TestGoModule386StackResult(t *testing.T) {
	pkg := mustGoPackage(t, "example", "package example\nfunc F() uint32")
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"uninitialized", "MOVL 0(SP), AX", false},
		{"TLS-relocation", "MOVL 0(SP)(TLS*1), AX", true},
		{"partial", "MOVB $1, 0(SP)\nMOVL 0(SP), AX", false},
		{"adjust", "ADJSP $4\nMOVL $11, 0(SP)\nMOVL 0(SP), AX\nADJSP $-4", true},
		{"different-slot", "SUBL $4, SP\nMOVL $1, 0(SP)\nADDL $4, SP\nMOVL 0(SP), AX", false},
		{"lea", "MOVL $11, 0(SP)\nLEAL -4(SP), SP\nMOVL 4(SP), AX\nLEAL 4(SP), SP", true},
		{"save", "MOVL $11, AX\nPUSHAL\nXORL AX, AX\nPOPAL", true},
		{"save-undefined", "PUSHAL\nMOVL $11, AX\nPOPAL", false},
		{"int80", "MOVL $20, AX\nINT $0x80", true},
		{"int80-undefined", "INT $0x80", false},
		{"branch", "MOVL $0, AX\nTESTL AX, AX\nJE done\nMOVL $11, 0(SP)\ndone:\nMOVL 0(SP), AX", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TranslateGoModule(pkg, []byte("TEXT ·F(SB),4,$8-4\n"+tc.body+"\nMOVL AX, ret+0(FP)\nRET"), GoModuleOptions{GOOS: "linux", GOARCH: "386", TargetTriple: "i686-unknown-linux-gnu", ResolveSym: testResolveSym("example")})
			if tr != nil {
				defer tr.Module.Dispose()
				if tc.name == "TLS-relocation" && !strings.Contains(tr.Module.String(), "call ptr @llvm.threadlocal.address.p0(ptr @runtime.tlsg)") {
					t.Fatal("indexed TLS load lost the runtime TLS relocation")
				}
			}
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t err=%v", tc.accepted, err)
			}
		})
	}
}

func TestGoModule386FramePointerStore(t *testing.T) {
	pkg := mustGoPackage(t, "example", "package example\nfunc F() uint32")
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"full", "MOVL $11, (DX)", true},
		{"partial", "MOVB $11, (DX)", false},
		{"replaced", "MOVL $1024, DX\nMOVL $11, (DX)", false},
		{"join", "MOVL $0, AX\nTESTL AX, AX\nJE store\nMOVL $1024, DX\nstore:\nMOVL $11, (DX)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TranslateGoModule(pkg, []byte("TEXT ·F(SB),4,$0-4\nLEAL ret+0(FP), DX\n"+tc.body+"\nRET"), GoModuleOptions{GOOS: "linux", GOARCH: "386", TargetTriple: "i686-unknown-linux-gnu", ResolveSym: testResolveSym("example")})
			if tr != nil {
				defer tr.Module.Dispose()
			}
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t, err=%v", tc.accepted, err)
			}
		})
	}
}

func TestGoModule386SyscallResultOnSuccess(t *testing.T) {
	pkg := mustGoPackage(t, "example", "package example\nfunc F() int64")
	const setup = "MOVL $140, AX\nLEAL ret+0(FP), SI\n"
	const trap = "INT $0x80\n"
	const failure = "MOVL $-1, ret+0(FP)\nMOVL $-1, ret+4(FP)\n"
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"zero-taken", setup + trap + "CMPL AX, $0\nJE done\n" + failure + "done:\nRET", true},
		{"zero-fallthrough", setup + trap + "TESTL AX, AX\nJNE fail\nRET\nfail:\n" + failure + "RET", true},
		{"error-can-return", setup + trap + "RET", false},
		{"other-syscall", setup + "MOVL $20, AX\n" + trap + "CMPL AX, $0\nJE done\n" + failure + "done:\nRET", false},
		{"other-buffer", setup + "MOVL BX, SI\n" + trap + "CMPL AX, $0\nJE done\n" + failure + "done:\nRET", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TranslateGoModule(pkg, []byte("TEXT ·F(SB),4,$0-8\n"+tc.body), GoModuleOptions{GOOS: "linux", GOARCH: "386", TargetTriple: "i686-unknown-linux-gnu", ResolveSym: testResolveSym("example")})
			if tr != nil {
				defer tr.Module.Dispose()
			}
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%t, err=%v", tc.want, err)
			}
		})
	}
}
