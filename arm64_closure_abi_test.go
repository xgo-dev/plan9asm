package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

const arm64ClosureEntrySource = `
TEXT ·Capture<ABIInternal>(SB),4,$0-16
	MOVD 8(R26), R0
	RET
`

func TestARM64ClosureRequiredEntry(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64) uint64\n")
	name := "test/closure.Capture"
	tr, err := TranslateGoModule(pkg, []byte(arm64ClosureEntrySource), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
		ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
		ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
	})
	if err != nil {
		t.Fatalf("required typed closure entry must translate: %v", err)
	}
	tr.Module.Dispose()
}

func TestARM64ClosureGoSourceIdentityForms(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64) uint64\n")
	name := "test/closure.Capture"
	for _, symbol := range []string{"·Capture", "test∕closure·Capture"} {
		source := strings.Replace(arm64ClosureEntrySource, "·Capture", symbol, 1)
		requireARM64ClosureGoObject(t, source)
		ctx := llvm.NewContext()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
			ResolveSym: func(sym string) string {
				sym = strings.ReplaceAll(goStripABISuffix(sym), "∕", "/")
				if strings.HasPrefix(sym, "·") {
					sym = pkg.Path + sym
				}
				return strings.ReplaceAll(sym, "·", ".")
			},
			ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
		})
		if err == nil {
			tr.Module.Dispose()
		}
		ctx.Dispose()
		if err != nil {
			t.Fatalf("actual Go source identity %q: %v", symbol, err)
		}
	}
}

func arm64TestClosureABI(name, triple string) ARM64ClosureABI {
	transport := ARM64ClosureNest
	if strings.Contains(triple, "apple") || strings.Contains(triple, "windows") {
		transport = ARM64ClosureSwiftSelf
	}
	return ARM64ClosureABI{
		ContextRegister: "R26", EntrySymbol: name,
		CodeOffset: 0, CodeType: Ptr, CaptureOffset: 8, CaptureType: I64,
		Transport: transport,
	}
}

func arm64ClosureSourceAndPackage(t *testing.T) (GoPackage, []byte) {
	t.Helper()
	root := runtime.GOROOT()
	decl, err := os.ReadFile(filepath.Join(root, "src/internal/bytealg/equal_native.go"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(root, "src/internal/bytealg/equal_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	// These are the selected toolchain's original declarations and full source,
	// including the genuine go:linkname identity and ABIInternal selectors.
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filepath.Join(root, "src/internal/bytealg/equal_native.go"), decl, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{Importer: importer.Default()}
	checked, err := conf.Check("internal/bytealg", fset, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: checked.Path(), Types: checked, Syntax: []*ast.File{parsed}}, source
}

func requireARM64ClosureOriginalGoObject(t *testing.T, source []byte) {
	t.Helper()
	dir := t.TempDir()
	// Generate go_asm.h from the original declaration file rather than altering
	// the selected source's includes or fabricating a macro/layout definition.
	decl := filepath.Join(runtime.GOROOT(), "src/internal/bytealg/equal_native.go")
	compile := exec.Command("go", "tool", "compile", "-p", "internal/bytealg", "-asmhdr", filepath.Join(dir, "go_asm.h"), "-o", filepath.Join(dir, "decl.o"), decl)
	compile.Env = append(os.Environ(), "GOARCH=arm64", "GOOS=linux")
	if out, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("actual Go declarations/header: %v\n%s", err, out)
	}
	asm := filepath.Join(dir, "equal_arm64.s")
	if err := os.WriteFile(asm, source, 0600); err != nil {
		t.Fatal(err)
	}
	args := append(arm64ClosureGoAsmArgs(t), "-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-I", dir, "-o", filepath.Join(dir, "equal.o"), asm)
	assemble := exec.Command("go", args...)
	assemble.Env = append(os.Environ(), "GOARCH=arm64", "GOOS=linux")
	if out, err := assemble.CombinedOutput(); err != nil {
		t.Fatalf("actual Go original assembly: %v\n%s", err, out)
	}
}

var arm64ClosureAsmFlags struct {
	once sync.Once
	args []string
	err  error
}

func arm64ClosureGoAsmArgs(t *testing.T) []string {
	t.Helper()
	arm64ClosureAsmFlags.once.Do(func() {
		help, err := exec.Command("go", "tool", "asm", "-h").CombinedOutput()
		if !strings.Contains(string(help), "usage: asm") {
			arm64ClosureAsmFlags.err = fmt.Errorf("selected Go assembler help is unavailable: %v\n%s", err, help)
			return
		}
		arm64ClosureAsmFlags.args = []string{"tool", "asm", "-p", "runtime"}
		// Go 1.20's actual parser uses this separate runtime flag. Current Go
		// derives AllowAsmABI from the package path instead. Query the selected
		// real tool, not the version used to compile this test or a host guess.
		if strings.Contains(string(help), "-compiling-runtime") {
			arm64ClosureAsmFlags.args = append(arm64ClosureAsmFlags.args, "-compiling-runtime")
		}
	})
	if arm64ClosureAsmFlags.err != nil {
		t.Fatal(arm64ClosureAsmFlags.err)
	}
	return append([]string(nil), arm64ClosureAsmFlags.args...)
}

func requireARM64ClosureGoObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	asm := filepath.Join(dir, "closure_arm64.s")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(arm64ClosureGoAsmArgs(t), "-o", filepath.Join(dir, "closure.o"), asm)
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go closure entry/form object: %v\n%s", err, out)
	}
}

func arm64ClosureResolve(symbol string) string {
	symbol = goStripABISuffix(symbol)
	if strings.HasPrefix(symbol, "·") {
		return "internal/bytealg." + strings.TrimPrefix(symbol, "·")
	}
	return strings.ReplaceAll(symbol, "·", ".")
}

func TestARM64ClosureOriginalSourceAllAPIsObjects(t *testing.T) {
	pkg, source := arm64ClosureSourceAndPackage(t)
	requireARM64ClosureOriginalGoObject(t, source)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			name := "runtime.memequal_varlen"
			opt := GoModuleOptions{
				GOARCH: "arm64", TargetTriple: triple, ResolveSym: arm64ClosureResolve,
				ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, triple)},
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			bound, err := translateGoModuleInContext(ctx, pkg, source, opt)
			if err != nil {
				t.Fatal(err)
			}
			defer bound.Module.Dispose()
			sig := bound.Signatures[name]
			if !reflect.DeepEqual(sig.Args, []LLVMType{Ptr, Ptr}) || sig.Ret != I1 || len(sig.ARM64GoRegisterABI.Params) != 2 {
				t.Fatalf("hidden input changed semantic signature: %+v", sig)
			}
			file, err := Parse(ArchARM64, string(source))
			if err != nil {
				t.Fatal(err)
			}
			lowOpt := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: arm64ClosureResolve, Sigs: bound.Signatures}
			text, err := Translate(file, lowOpt)
			if err != nil {
				t.Fatal(err)
			}
			moduleCtx := llvm.NewContext()
			defer moduleCtx.Dispose()
			module, err := TranslateModuleInContext(moduleCtx, file, lowOpt)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			if indirectMarkerComparableIR(text) != indirectMarkerComparableIR(bound.Module.String()) ||
				indirectMarkerComparableIR(text) != indirectMarkerComparableIR(module.String()) {
				t.Fatal("public translation APIs disagree on original typed closure source")
			}
			want := "ptr " + sig.ARM64ClosureABI.llvmAttribute()
			if !strings.Contains(text, want+" %closure") {
				t.Fatalf("required physical context missing %q", want)
			}
			compileLLVMToObject(t, llc, triple, "closure.ll", "closure.o", text)
		})
	}
}

func TestARM64ClosureCarrierMalformedAndMissingContexts(t *testing.T) {
	pkg, source := arm64ClosureSourceAndPackage(t)
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		for _, tc := range []struct {
			name string
			edit func(*ARM64ClosureABI)
		}{
			{"wrong_register", func(a *ARM64ClosureABI) { a.ContextRegister = "R25" }},
			{"wrong_identity", func(a *ARM64ClosureABI) { a.EntrySymbol = "runtime.memequal" }},
			{"wrong_code_offset", func(a *ARM64ClosureABI) { a.CodeOffset = 8 }},
			{"wrong_code_type", func(a *ARM64ClosureABI) { a.CodeType = I64 }},
			{"wrong_capture_offset", func(a *ARM64ClosureABI) { a.CaptureOffset = 16 }},
			{"wrong_capture_width", func(a *ARM64ClosureABI) { a.CaptureType = I32 }},
			{"absent_transport", func(a *ARM64ClosureABI) { a.Transport = 0 }},
			{"wrong_transport", func(a *ARM64ClosureABI) { a.Transport = 3 - a.Transport }},
			{"absent", nil},
		} {
			t.Run(triple+"/"+tc.name, func(t *testing.T) {
				name := "runtime.memequal_varlen"
				abi := arm64TestClosureABI(name, triple)
				opt := GoModuleOptions{GOARCH: "arm64", TargetTriple: triple, ResolveSym: arm64ClosureResolve}
				if tc.edit != nil {
					tc.edit(&abi)
					opt.ARM64ClosureABIs = map[string]ARM64ClosureABI{name: abi}
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				tr, err := translateGoModuleInContext(ctx, pkg, source, opt)
				if err == nil {
					tr.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved carrier accepted: %v", err)
				}
			})
		}
	}
}

func TestARM64ClosureSourceBoundReadOnlyCarrier(t *testing.T) {
	for _, source := range []string{
		"MOVD 0(R26),R0", "MOVD 16(R26),R0", "MOVWU 8(R26),R0",
		"MOVD.P 8(R26),R0", "MOVD.W 8(R26),R0", "MOVD 8(R26),R26",
		"MOVD R26,R3\nMOVD 8(R3),R0", "ADD $8,R26,R3\nMOVD (R3),R0",
		"MOVD R0,8(R26)\nMOVD 8(R26),R0", "MOVD R0,(R1)\nMOVD 8(R26),R0",
		"MOVD R0,saved(SB)\nMOVD 8(R26),R0", "MOVD saved(SB),R0\nMOVD 8(R26),R0",
		"MOVD R26,saved(SB)\nMOVD 8(R26),R0", "MOVD $8(R26),R3\nMOVD 8(R26),R0",
		"MOVD 8(R26),R0\nB done\ndead:\nMOVD R26,R3\ndone:",
		"WORD $0xf9400340", // raw MOVD 0(R26),R0: code word, not capture data.
		"WORD $0xffffffff\nMOVD 8(R26),R0",
	} {
		t.Run(strings.ReplaceAll(source, "\n", ";"), func(t *testing.T) {
			pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64, uint64) uint64\n")
			asm := "TEXT ·Capture<ABIInternal>(SB),4,$0-24\n" + source + "\nRET\n"
			// Raw WORD acceptance is syntax only, never a claim its bits are a
			// valid executable instruction. The unknown raw negative is retained.
			requireARM64ClosureGoObject(t, asm)
			name := "test/closure.Capture"
			opt := GoModuleOptions{
				GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
				ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
				ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			tr, err := translateGoModuleInContext(ctx, pkg, []byte(asm), opt)
			if err == nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("source without bounded immutable carrier read accepted: %v", err)
			}
		})
	}
}

func TestARM64ClosureDirectReferencesDoNotInventCarrier(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64) uint64\nfunc Caller(uint64) uint64\n")
	for _, edge := range []string{
		"CALL ·Capture<ABIInternal>(SB)", "BL ·Capture<ABIInternal>(SB)",
		"B ·Capture<ABIInternal>(SB)", "JMP ·Capture<ABIInternal>(SB)", "RET ·Capture<ABIInternal>(SB)",
		"MOVD $·Capture<ABIInternal>(SB),R0", "MOVD ·Capture<ABIInternal>(SB),R0",
	} {
		t.Run(edge, func(t *testing.T) {
			source := arm64ClosureEntrySource + "\nTEXT ·Caller<ABIInternal>(SB),4,$0-16\n" + edge + "\nRET\n"
			requireARM64ClosureGoObject(t, source)
			name := "test/closure.Capture"
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
				ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
				ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
			})
			if err == nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ordinary source edge invented required env: %v", err)
			}
		})
	}
}

func TestARM64ClosureDataAndExcludedSiblingDoNotInventCarrier(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64) uint64\nfunc Caller(uint64) uint64\n")
	for _, extra := range []string{
		"DATA holder<>(SB)/8,$·Capture<ABIInternal>(SB)\nGLOBL holder<>(SB),8,$8\n",
		"TEXT ·Caller<ABIInternal>(SB),4,$0-16\nMOVD $·Capture<ABIInternal>(SB),R0\nRET\n",
	} {
		source := arm64ClosureEntrySource + "\n" + extra
		requireARM64ClosureGoObject(t, source)
		name := "test/closure.Capture"
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
			ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
			KeepFunc:         func(_, resolved string) bool { return resolved == name },
			ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
		})
		if err == nil {
			tr.Module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("DATA or excluded sibling invented carrier: %v", err)
		}
	}
}

func TestARM64ClosureGoBindingRequiresActualDeclaration(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\n")
	name := "test/closure.Capture"
	sig := FuncSig{Name: name, Args: []LLVMType{I64}, Ret: I64}
	var err error
	sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	tr, err := translateGoModuleInContext(ctx, pkg, []byte(arm64ClosureEntrySource), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
		ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
		ManualSig:        func(string) (FuncSig, bool) { return sig, true },
		ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
	})
	if err == nil {
		tr.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("manual scalar signature fabricated a source declaration: %v", err)
	}
}

func TestARM64ClosureNeedsSourceSelectorAndReachingContext(t *testing.T) {
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(uint64) uint64\nfunc Compute()\n")
	name := "test/closure.Capture"
	for _, source := range []string{
		strings.Replace(arm64ClosureEntrySource, "<ABIInternal>", "", 1),
		strings.Replace(arm64ClosureEntrySource, "<ABIInternal>", "<ABI0>", 1),
		strings.Replace(arm64ClosureEntrySource, "MOVD 8(R26)", "CALL ·Compute<ABIInternal>(SB)\nMOVD 8(R26)", 1),
	} {
		requireARM64ClosureGoObject(t, source)
		ctx := llvm.NewContext()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: "aarch64-apple-darwin",
			ResolveSym:       func(sym string) string { return "test/closure." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
			ARM64ClosureABIs: map[string]ARM64ClosureABI{name: arm64TestClosureABI(name, "aarch64-apple-darwin")},
		})
		if err == nil {
			tr.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("missing source entry/reaching context accepted: %v", err)
		}
		if strings.Contains(source, "CALL") && !strings.Contains(err.Error(), "R26 read") {
			t.Fatalf("a call must invalidate the hidden input, not just hit another guard: %v", err)
		}
	}
}

func TestARM64ClosureArchitectureAllAPIsFailClosed(t *testing.T) {
	for _, arch := range []struct {
		arch           Arch
		goarch, triple string
	}{
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown"},
	} {
		sig := FuncSig{Name: "Capture", Args: []LLVMType{I64}, Ret: I64}
		var err error
		sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
		if err != nil {
			t.Fatal(err)
		}
		abi := arm64TestClosureABI(sig.Name, "aarch64-unknown-linux-gnu")
		sig.ARM64ClosureABI = &abi
		file, err := Parse(arch.arch, "TEXT Capture(SB),$0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		assertARM64ClosureAllAPIsContext(t, file, Options{
			Goarch: arch.goarch, TargetTriple: arch.triple,
			Sigs: map[string]FuncSig{sig.Name: sig},
		})
	}
}

func assertARM64ClosureAllAPIsContext(t *testing.T, file *File, opt Options) {
	t.Helper()
	if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("text API accepted unproved carrier: %v", err)
	}
	if module, err := TranslateModule(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
		if err == nil {
			module.Dispose()
		}
		t.Fatalf("module API accepted unproved carrier: %v", err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if module, err := TranslateModuleInContext(ctx, file, opt); !errors.Is(err, ErrProbeNeedsContext) {
		if err == nil {
			module.Dispose()
		}
		t.Fatalf("owned-context API accepted unproved carrier: %v", err)
	}
}

func TestCrossLinuxRuntimeMatrixARM64ClosureOriginalSource(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg, source := arm64ClosureSourceAndPackage(t)
	name := "runtime.memequal_varlen"
	abi := arm64TestClosureABI(name, triple)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	tr, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: arm64ClosureResolve,
		ARM64ClosureABIs: map[string]ARM64ClosureABI{name: abi},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	// The immutable LLVM-side producer owns the exact {entry,size} lifetime.
	// It transports the whole carrier through Nest/SwiftSelf, not an ordinary
	// third Go argument, a descriptor env or a synthesized R26 zero.
	shim := fmt.Sprintf(`
define i1 @invoke(ptr %%a, ptr %%b, i64 %%size) {
  %%carrier = alloca {ptr, i64}, align 8
  store {ptr, i64} {ptr @runtime.memequal_varlen, i64 0}, ptr %%carrier
  %%sizeptr = getelementptr {ptr, i64}, ptr %%carrier, i64 0, i32 1
  store i64 %%size, ptr %%sizeptr
  %%result = call i1 @runtime.memequal_varlen(ptr %s %%carrier, ptr %%a, ptr %%b)
  ret i1 %%result
}
`, abi.llvmAttribute())
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "closure_original", triple, tr.Module.String()+shim, arm64ClosureRuntimeDriver, runner)
	// Independent actual Go exercises the selected compiler's real interface
	// equality closure producer and original runtime entry, without importing
	// unsafe addresses or changing any caller's stack/return link.
	runARM64GoInternalOracle(t, "#include \"textflag.h\"\nTEXT ·Unused<ABIInternal>(SB),NOSPLIT,$0-0\nRET\n", arm64ClosureGoOracle, len(runner) != 0)
}

const arm64ClosureRuntimeDriver = `#include <stdbool.h>
#include <stdint.h>
#include <string.h>
extern bool invoke(const unsigned char *, const unsigned char *, uint64_t);
int main(void) {
  unsigned char a[264], b[264];
  uint64_t sizes[] = {0,1,2,3,4,7,8,15,16,17,23,24,31,32,37,63,64,65,127,128,129,255,256};
  for (int i=0; i<264; i++) a[i]=b[i]=(unsigned char)(i*131+17);
  for (int offset=0; offset<4; offset++) {
    for (unsigned j=0; j<sizeof(sizes)/sizeof(sizes[0]); j++) {
      uint64_t n=sizes[j];
      if (!invoke(a+offset,b+offset,n) || !invoke(a+offset,a+offset,n)) return 1;
      for (uint64_t k=0; k<n; k++) {
        b[offset+k]^=0x80;
        if (invoke(a+offset,b+offset,n) || invoke(b+offset,a+offset,n)) return 2;
        b[offset+k]^=0x80;
      }
      if (invoke(a+offset,b+offset,n)!=(memcmp(a+offset,b+offset,n)==0)) return 3;
    }
  }
  return 0;
}
`

const arm64ClosureGoOracle = `package main
func Unused()
type Bytes24 [24]byte
func main() {
  var a,b Bytes24
  for i:=range a { a[i]=byte(i*131+17); b[i]=a[i] }
  var x any=a
  if x!=any(b) { panic("actual Go closure equality") }
  for i:=range b {
    b[i]^=0x80
    if x==any(b) || any(b)==x { panic("actual Go closure inequality") }
    b[i]^=0x80
  }
  if x!=any(b) { panic("actual Go closure restoration") }
}
`
