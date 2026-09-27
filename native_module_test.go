package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func TestNativeNakedModule(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			t.Run(goos+"/"+goarch, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				opts := NativeOptions{GOOS: goos, GOARCH: goarch, PackagePath: "probe", Imports: map[string]string{"imported_strlen": "strlen", "imported_mixed": "mixed"}}
				source := nativeCallbackSource
				if goarch == "amd64" {
					source = nativeAMD64Callback
				}
				mod, err := TranslateNativeModule(ctx, []byte(source), opts)
				if err != nil {
					t.Fatal(err)
				}
				defer mod.Dispose()
				// Address consumers in the SAME IR module deliberately use real signatures
				// unlike the void() carriers. O2 and LTO must preserve arguments and results.
				builder := ctx.NewBuilder()
				defer builder.Dispose()
				for _, mixed := range []bool{false, true} {
					name := "entry"
					args := []llvm.Type{llvm.PointerType(ctx.Int8Type(), 0)}
					if mixed {
						name = "mixedEntry"
						args = []llvm.Type{ctx.Int64Type(), ctx.Int64Type()}
					}
					ty := llvm.FunctionType(ctx.Int64Type(), args, false)
					wrapper := llvm.AddFunction(mod, "call_"+name, ty)
					builder.SetInsertPointAtEnd(ctx.AddBasicBlock(wrapper, "entry"))
					ptr := builder.CreateLoad(llvm.PointerType(ctx.Int8Type(), 0), mod.NamedGlobal("probe."+name), "address")
					var vals []llvm.Value
					for n := range args {
						vals = append(vals, wrapper.Param(n))
					}
					result := builder.CreateCall(ty, ptr, vals, "result")
					builder.CreateRet(result)
				}
				ir := mod.String()
				if strings.Contains(ir, "module asm") || !strings.Contains(ir, "naked noinline") || !strings.Contains(ir, "~{memory}") {
					t.Fatal(ir)
				}
				harness := `extern unsigned long call_entry(const char *);
extern unsigned long call_mixedEntry(unsigned long,unsigned long);
unsigned long mixed(unsigned long x,unsigned long flags,double y){return flags==17 ? x+(unsigned long)y : 999;}
int main(void){return call_entry("native ABI")!=10 || call_mixedEntry(5,0x4000000000000000UL)!=7;}`
				for _, mode := range []string{"default<O2>", "lto-pre-link<O2>,lto<O2>"} {
					t.Run(mode, func(t *testing.T) {
						asm := nativeModuleAssembly(t, ir, mode)
						nativeTargetCompileRun(t, opts, asm, harness)
					})
				}
			})
		}
	}
}

func nativeModuleAssembly(t *testing.T, ir, pipeline string) string {
	t.Helper()
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "native.ll")
	optimized := filepath.Join(dir, "optimized.ll")
	out := filepath.Join(dir, "native.s")
	if err := os.WriteFile(src, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(opt, "-passes="+pipeline, "-verify-each", "-S", src, "-o", optimized).CombinedOutput(); err != nil {
		t.Fatalf("opt: %v\n%s\n%s", err, b, ir)
	}
	if b, err := exec.Command(llc, "-relocation-model=pic", optimized, "-o", out).CombinedOutput(); err != nil {
		t.Fatalf("llc: %v\n%s\n%s", err, b, ir)
	}
	asm, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(asm)
}

func TestNativeModuleToolPreflight(t *testing.T) {
	const ir = `target triple = "x86_64-unknown-linux-gnu"
define void @noop() {
  ret void
}
`
	assembly := nativeModuleAssembly(t, ir, "default<O2>")
	if !strings.Contains(assembly, "noop") {
		t.Fatalf("missing compiled function:\n%s", assembly)
	}
}

func TestNativeNakedModuleRequiresLLVM22(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(executable, "-test.run=^TestNativeModuleToolPreflight$", "-test.v")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(variable), "LLVM_CONFIG=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "LLVM_CONFIG="+filepath.Join(t.TempDir(), "missing-llvm-config"))

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("native module test passed without required LLVM 22 tools:\n%s", output)
	}
	if !strings.Contains(string(output), "LLVM 22 opt not found") {
		t.Fatalf("native module test did not fail for missing LLVM 22: %v\n%s", err, output)
	}
}

func TestNativeNakedLinkAndReachability(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			mod := ctx.NewModule("merged")
			defer mod.Dispose()
			for i := 0; i < 2; i++ {
				body := fmt.Sprintf("MOVQ $%d, AX\nCMPQ AX, $42\nJLT done\nMOVQ $99, AX\ndone:\nRET", 40+i)
				call := "SUBQ $8, SP\nCALL callee<>(SB)\nADDQ $8, SP\nRET"
				dead := "MOVQ $999, AX\nRET"
				if arch == "arm64" {
					body = fmt.Sprintf("MOVD $%d, R0\nCMP $42, R0\nBLT done\nMOVD $99, R0\ndone:\nRET", 40+i)
					call = "SUB $16, RSP\nMOVD R30, (RSP)\nCALL callee<>(SB)\nMOVD (RSP), R30\nADD $16, RSP\nRET"
					dead = "MOVD $999, R0\nRET"
				}
				src := fmt.Sprintf("TEXT caller<>(SB), NOSPLIT|NOFRAME, $0\n%s\nTEXT callee<>(SB), NOSPLIT, $0\n%s\nTEXT unused<>(SB), NOSPLIT, $0\n%s\nGLOBL ·entry(SB), RODATA, $8\nDATA ·entry(SB)/8, $caller<>(SB)\n", call, body, dead)
				src = strings.ReplaceAll(src, "·entry", fmt.Sprintf("·entry%d", i))
				part, err := TranslateNativeModule(ctx, []byte(src), NativeOptions{GOOS: "linux", GOARCH: arch, PackagePath: "probe"})
				if err != nil {
					t.Fatal(err)
				}
				mod.SetTarget(part.Target())
				if err := llvm.LinkModules(mod, part); err != nil {
					t.Fatal(err)
				}
			}
			asm := nativeModuleAssembly(t, mod.String(), "lto-pre-link<O2>,lto<O2>")
			if strings.Contains(asm, "999") {
				t.Fatal("unreachable carrier survived DCE")
			}
			nativeTargetCompileRun(t, NativeOptions{GOOS: "linux", GOARCH: arch}, asm, `extern void *a __asm("probe.entry0");extern void *b __asm("probe.entry1");int main(void){return ((int(*)(void))a)()!=40 || ((int(*)(void))b)()!=41;}`)
		})
	}
}

func TestNativeNakedModuleReject(t *testing.T) {
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	for _, src := range []string{"TEXT f<>(SB), NOSPLIT, $0\nBAD\n", "TEXT f<>(SB), NOSPLIT, $0\nMOVQ $1, AX\n", "TEXT f<>(SB), NOSPLIT, $0\nRET\nend:\n", "TEXT f<>(SB), NOSPLIT, $0\nJMP missing(SB)\n", "TEXT f<>(SB), NOSPLIT, $0\nRET\nGLOBL ·entry(SB), RODATA, $4\nDATA ·entry(SB)/8, $f<>(SB)\n"} {
		mod, err := TranslateNativeModule(ctx, []byte(src), NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe"})
		if err == nil {
			mod.Dispose()
			t.Fatal("accepted invalid source")
		}
		if mod != (llvm.Module{}) {
			t.Fatal("returned partial module")
		}
	}
}

func TestNativeNakedDataAndIRReferences(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			src := `TEXT f<>(SB), NOSPLIT, $0
 JMP imported(SB)
GLOBL ·record(SB), RODATA, $40
DATA ·record+1(SB)/1, $0x122
DATA ·record+8(SB)/8, $f<>(SB)
DATA ·record+16(SB)/8, $·storage(SB)
DATA ·record+24(SB)/8, $imported(SB)
GLOBL ·storage(SB), NOPTR, $8
DATA ·storage(SB)/8, $7
`
			opts := NativeOptions{GOOS: "linux", GOARCH: arch, PackagePath: "probe", Imports: map[string]string{"imported": "body"}}
			mod, err := TranslateNativeModule(ctx, []byte(src), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer mod.Dispose()
			// Resolve an untyped external address to a real, differently typed LLVM
			// function definition during module linking; do not hard-code its spelling.
			body := ctx.NewModule("body")
			body.SetTarget(mod.Target())
			fn := llvm.AddFunction(body, "body", llvm.FunctionType(ctx.Int64Type(), nil, false))
			b := ctx.NewBuilder()
			b.SetInsertPointAtEnd(ctx.AddBasicBlock(fn, "entry"))
			b.CreateRet(llvm.ConstInt(ctx.Int64Type(), 42, false))
			b.Dispose()
			if err := llvm.LinkModules(mod, body); err != nil {
				t.Fatal(err)
			}
			asm := nativeModuleAssembly(t, mod.String(), "lto-pre-link<O2>,lto<O2>")
			nativeTargetCompileRun(t, opts, asm, `#include <string.h>
extern unsigned char record[] __asm("probe.record");
int main(void){unsigned long (*entry)(void),(*body)(void);unsigned long *storage;
memcpy(&entry,record+8,8);memcpy(&storage,record+16,8);memcpy(&body,record+24,8);
if(record[0] || record[1]!=0x22 || record[2] || record[39] || *storage!=7 || entry()!=42 || body()!=42)return 1;
*storage=9;return *storage!=9;}`)
		})
	}
}

func TestNativeNakedFloatingReturn(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			move := "MOVQ DI, X0"
			if arch == "arm64" {
				move = "FMOVD R0, F0"
			}
			source := "TEXT fp<>(SB), NOSPLIT, $0\n" + move + "\nRET\nGLOBL ·entry(SB), RODATA, $8\nDATA ·entry(SB)/8, $fp<>(SB)\n"
			opts := NativeOptions{GOOS: "linux", GOARCH: arch, PackagePath: "probe"}
			mod, err := TranslateNativeModule(ctx, []byte(source), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer mod.Dispose()
			b := ctx.NewBuilder()
			defer b.Dispose()
			ty := llvm.FunctionType(ctx.DoubleType(), []llvm.Type{ctx.Int64Type()}, false)
			f := llvm.AddFunction(mod, "floating", ty)
			b.SetInsertPointAtEnd(ctx.AddBasicBlock(f, "entry"))
			ptr := b.CreateLoad(llvm.PointerType(ctx.Int8Type(), 0), mod.NamedGlobal("probe.entry"), "address")
			b.CreateRet(b.CreateCall(ty, ptr, []llvm.Value{f.Param(0)}, "result"))
			asm := nativeModuleAssembly(t, mod.String(), "lto-pre-link<O2>,lto<O2>")
			nativeTargetCompileRun(t, opts, asm, `extern double floating(unsigned long);int main(void){return floating(0x4004000000000000UL)!=2.5;}`)
		})
	}
}
