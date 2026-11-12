package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Derive the external call from the current Go toolchain's real declaration.
// The test supplies no guessed register inputs or memory/noalias annotation.
func arm64CallInputMemmoveSig(t *testing.T) FuncSig {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(testGOROOT(t), "src/runtime/stubs.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "memmove" {
			if err := format.Node(&source, fset, fn); err != nil {
				t.Fatal(err)
			}
		}
	}
	if source.Len() == 0 {
		t.Fatal("actual runtime memmove declaration not found")
	}
	pkg := arm64PrivateCallDeclarations(t, source.String())
	sizes := types.SizesFor("gc", "arm64")
	sig, err := goFuncSigForDeclaredFunc("memmove", pkg.Types.Scope().Lookup("memmove").(*types.Func), "arm64", sizes, sizes, true)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func arm64CallCopyLoopSource(call, copyBody string) string {
	return fmt.Sprintf(`#include "textflag.h"
TEXT ·CopyLoop(SB),NOSPLIT,$56-32
	MOVD dst+0(FP),R7
	MOVD src+8(FP),R6
	MOVD n+16(FP),R4
	CBZ R4,done
	MOVD R7,8(RSP)
	MOVD R6,16(RSP)
	MOVD $1,R5
	MOVD R5,24(RSP)
	MOVD R7,32(RSP)
	MOVD R6,40(RSP)
	MOVD R4,48(RSP)
	%s runtime·memmove(SB)
	MOVD 32(RSP),R7
	MOVD 40(RSP),R6
	MOVD 48(RSP),R4
	ADD $1,R7
	ADD $1,R6
	MOVD dst+0(FP),R1
	MOVD n+16(FP),R3
	ADD R3,R1,R8
	SUB R7,R8,R4
loop:
	CMP $16,R4
	BLT bytes
%s
	ADD $16,R7
	ADD $16,R6
	SUB $16,R4
	B loop
bytes:
	CBZ R4,done
	MOVBU (R6),R5
	MOVB R5,(R7)
	ADD $1,R7
	ADD $1,R6
	SUB $1,R4
	B bytes
done:
	MOVD n+16(FP),R0
	MOVD R0,ret+24(FP)
	RET
`, call, copyBody)
}

func arm64CallCopyLoopModule(t *testing.T, source, target string) string {
	t.Helper()
	pkg := arm64PrivateCallDeclarations(t, "func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr\n")
	callee := arm64CallInputMemmoveSig(t)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: target,
		ResolveSym: func(sym string) string {
			return strings.ReplaceAll(goStripABISuffix(strings.TrimPrefix(sym, "·")), "·", ".")
		},
		ManualSig: func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Module.Dispose()
	return bound.Module.String()
}

func TestARM64TypedCallReloadCopyLoopObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	pkg := arm64PrivateCallDeclarations(t, "func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr\n")
	callee := arm64CallInputMemmoveSig(t)
	resolve := func(sym string) string {
		return strings.ReplaceAll(goStripABISuffix(strings.TrimPrefix(sym, "·")), "·", ".")
	}
	for _, call := range []string{"CALL", "BL"} {
		for _, tc := range []struct{ name, body string }{
			{"scalar", "MOVD (R6),R2\nMOVD 8(R6),R5\nMOVD R2,(R7)\nMOVD R5,8(R7)"},
			{"pair", "LDP (R6),(R2,R5)\nSTP (R2,R5),(R7)"},
		} {
			source := arm64CallCopyLoopSource(call, tc.body)
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				t.Run(call+"_"+tc.name+"_"+target, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
						GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
						ManualSig: func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" },
					})
					if err != nil {
						t.Fatal(err)
					}
					defer bound.Module.Dispose()
					compileLLVMToObject(t, llc, target, "go-call-loop.ll", "go-call-loop.o", bound.Module.String())
					opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: bound.Signatures}
					text, err := Translate(file, opt)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target, "text-call-loop.ll", "text-call-loop.o", text)
					module, err := TranslateModuleInContext(ctx, file, opt)
					if err != nil {
						t.Fatal(err)
					}
					defer module.Dispose()
					compileLLVMToObject(t, llc, target, "module-call-loop.ll", "module-call-loop.o", module.String())
				})
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64TypedCallReloadCopyLoop(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, call := range []string{"CALL", "BL"} {
		for _, tc := range []struct{ name, body string }{
			{"scalar", "MOVD (R6),R2\nMOVD 8(R6),R5\nMOVD R2,(R7)\nMOVD R5,8(R7)"},
			{"pair", "LDP (R6),(R2,R5)\nSTP (R2,R5),(R7)"},
		} {
			t.Run(call+"_"+tc.name, func(t *testing.T) {
				source := arm64CallCopyLoopSource(call, tc.body)
				runARM64LocalRegisterGoOracle(t, source, `package main
import "unsafe"
func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr
func main() {
 for _, n := range []int{0,1,2,7,8,16,17,31,32,33,64,131} {
  for _, d := range []int{0,1,3,17} {
   for _, s := range []int{0,1,5,19} {
    var dst, want, src [160]byte
    for i := range dst { dst[i]=0xa7; want[i]=0xa7; src[i]=byte(i*37+n*11) }
    for i:=0;i<n;i++ { want[d+i]=src[s+i] }
    if CopyLoop(unsafe.Pointer(&dst[d]),unsafe.Pointer(&src[s]),uintptr(n))!=uintptr(n) || dst!=want {
     panic("actual Go typed CALL/spill/FP-reload/copy-loop mismatch")
    }
   }
  }
 }
}

`, len(runner) != 0, "1.20")
				t.Log("actual Go passed 192 complete-buffer/canary vectors")
				ir := arm64CallCopyLoopModule(t, source, target)
				const driver = `#include <stdint.h>
#include <string.h>
extern uint64_t CopyLoop(void *, const void *, uint64_t);
int main(void) {
 const int sizes[]={0,1,2,7,8,16,17,31,32,33,64,131};
 const int dstOffsets[]={0,1,3,17}, srcOffsets[]={0,1,5,19};
 for(int z=0;z<12;z++) {
  for(int d=0;d<4;d++) {
   for(int s=0;s<4;s++) {
    unsigned char dst[160],want[160],src[160];
    int n=sizes[z],di=dstOffsets[d],si=srcOffsets[s];
    for(int i=0;i<160;i++) { dst[i]=want[i]=0xa7; src[i]=(unsigned char)(i*37+n*11); }
    memcpy(want+di,src+si,n);
    if(CopyLoop(dst+di,src+si,(uint64_t)n)!=(uint64_t)n || memcmp(dst,want,160)) return 1;
   }
  }
 }
 return 0;
}
`
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "call_reload_copy_loop", target, ir, driver, runner)
			})
		}
	}
}
