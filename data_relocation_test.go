package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var dataRelocationTargets = []struct {
	arch                 Arch
	goos, goarch, triple string
	width                int
}{
	{ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu", 8},
	{ArchAMD64, "darwin", "amd64", "x86_64-apple-darwin", 8},
	{ArchAMD64, "windows", "amd64", "x86_64-pc-windows-msvc", 8},
	{ArchAMD64, "linux", "386", "i386-unknown-linux-gnu", 4},
	{ArchAMD64, "windows", "386", "i686-pc-windows-msvc", 4},
	{ArchARM, "linux", "arm", "armv7-unknown-linux-gnueabihf", 4},
	{ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu", 8},
	{ArchARM64, "darwin", "arm64", "aarch64-apple-darwin", 8},
	{ArchARM64, "windows", "arm64", "aarch64-pc-windows-msvc", 8},
	{ArchWASM, "js", "wasm", "wasm32-unknown-unknown", 8},
}

func dataRelocationGoObject(t *testing.T, source, goos, goarch string, accepted bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-p", "test", "-o", filepath.Join(dir, "go.o"), path)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if (err == nil) != accepted {
		t.Fatalf("actual Go %s/%s, expected accepted=%v: %v\n%s", goos, goarch, accepted, err, out)
	}
}

func TestDataRelocationAllArchitectures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range dataRelocationTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := fmt.Sprintf(`DATA payload<>+0(SB)/8,$0x1122334455667788
GLOBL payload<>(SB),16,$16
DATA holder<>+0(SB)/1,$0xaa
DATA holder<>+1(SB)/%d,$payload<>+3(SB)
DATA holder<>+%d(SB)/%d,$external-1(SB)
GLOBL holder<>(SB),16,$%d
`, target.width, 1+target.width, target.width, 1+2*target.width+3)
			dataRelocationGoObject(t, source, target.goos, target.goarch, true)
			file, err := Parse(target.arch, source)
			if err != nil {
				t.Fatal(err)
			}
			opt := Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: testResolveSym("test")}
			ir, err := Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			expectedFragments := []string{"ptrtoint", "test.payload", "test.external", "i64 3", "i64 -1"}
			if target.arch == ArchWASM {
				expectedFragments = []string{"module asm", ".int64", "test.payload", "test.external", "+3", "-1", "@llvm.used"}
			}
			for _, expected := range expectedFragments {
				if !strings.Contains(ir, expected) {
					t.Errorf("DATA relocation lost %q, must not encode a zero placeholder:\n%s", expected, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "relocations.ll", "relocations.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			mod, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Fatal(err)
			}
			defer mod.Dispose()
			if !strings.Contains(mod.String(), expectedFragments[0]) {
				t.Fatal("direct/module route silently discarded DATA relocation")
			}
			compileLLVMToObject(t, llc, target.triple, "module.ll", "module.o", mod.String())
		})
	}
}

func TestDataRelocationWidthMatchesGo(t *testing.T) {
	for _, target := range dataRelocationTargets {
		for _, width := range []int{1, 2, 4, 8, 16} {
			if width == target.width {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", target.triple, width), func(t *testing.T) {
				source := fmt.Sprintf("DATA holder<>(SB)/%d,$payload<>(SB)\nGLOBL holder<>(SB),16,$%d\n", width, width)
				dataRelocationGoObject(t, source, target.goos, target.goarch, false)
				file, err := Parse(target.arch, source)
				if err != nil {
					return // A parser rejection also matches Go.
				}
				opt := Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: testResolveSym("test")}
				if _, err := Translate(file, opt); err == nil {
					t.Error("wrong-width address relocation accepted")
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					mod.Dispose()
					t.Error("module route accepted wrong-width address relocation")
				}
			})
		}
	}
}

func TestDataRelocationFunctionSymbolsAreTypedAndBound(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range dataRelocationTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := fmt.Sprintf("TEXT target(SB),4,$0-0\nRET\nDATA holder<>(SB)/%d,$target(SB)\nDATA holder<>+%d(SB)/%d,$·foreign(SB)\nGLOBL holder<>(SB),16,$%d\n", target.width, target.width, target.width, target.width*2)
			dataRelocationGoObject(t, source, target.goos, target.goarch, true)
			file, err := Parse(target.arch, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := testResolveSym("test")
			opt := Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: resolve,
				Sigs: map[string]FuncSig{
					resolve("target"):   {Name: resolve("target"), Ret: Void},
					resolve("·foreign"): {Name: "foreign_alias", Ret: Void},
				},
			}
			ir, err := Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "foreign_alias") || strings.Contains(ir, "@test.foreign = external global") {
				t.Fatalf("a typed function relocation was bound as data or lost its alias:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "function-relocations.ll", "function-relocations.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, target.triple, "module-function-relocations.ll", "module-function-relocations.o", module.String())
		})
	}
}

func TestDataRelocationRejectsAmbiguousAndOverlappingDescriptors(t *testing.T) {
	for name, data := range map[string][]DataStmt{
		"malformed offset": {{Sym: "holder", Width: 8, Addr: "target+bad(SB)"}},
		"wrong base":       {{Sym: "holder", Width: 8, Addr: "target(FP)"}},
		"empty target":     {{Sym: "holder", Width: 8, Addr: "(SB)"}},
		"mixed value":      {{Sym: "holder", Width: 8, Addr: "target(SB)", Value: 1}},
		"mixed bytes":      {{Sym: "holder", Width: 8, Addr: "target(SB)", Payload: []byte{1}}},
		"scalar overlap":   {{Sym: "holder", Width: 8, Addr: "target(SB)"}, {Sym: "holder", Off: 7, Width: 1, Value: 1}},
		"address overlap":  {{Sym: "holder", Width: 8}, {Sym: "holder", Off: 1, Width: 8, Addr: "target(SB)"}},
		"negative offset":  {{Sym: "holder", Off: -1, Width: 8, Addr: "target(SB)"}},
	} {
		t.Run(name, func(t *testing.T) {
			file := &File{Arch: ArchAMD64, Data: data}
			if _, err := Translate(file, Options{Goarch: "amd64"}); err == nil {
				t.Fatal("ambiguous DATA address descriptor accepted")
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, Options{Goarch: "amd64"})
			if err == nil {
				module.Dispose()
				t.Fatal("module accepted ambiguous DATA address descriptor")
			}
		})
	}
	file := &File{Arch: ArchAMD64, Data: []DataStmt{{Sym: "holder", Width: 8, Addr: "target(SB)"}}}
	if _, err := Translate(file, Options{Goarch: "invented"}); err == nil {
		t.Fatal("invented Go pointer-size contract accepted")
	}
	if _, err := dataStmtPayload(file.Data[0]); err == nil || errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("address descriptor was converted to bytes or mislabeled Context: %v", err)
	}
}

func TestDataRelocationUnqualifiedStandaloneFunctionAlias(t *testing.T) {
	file, err := Parse(ArchAMD64, "DATA holder<>(SB)/8,$foreign(SB)\nGLOBL holder<>(SB),16,$8\n")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"foreign": {Name: "foreign_alias", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "ptr @foreign_alias") || strings.Contains(ir, "foreign = external global") || strings.Contains(ir, "·foreign") {
		t.Fatalf("standalone address ignored the explicit typed function alias:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "standalone-function.ll", "standalone-function.o", ir)
}

func TestWASMDataRelocationPaddingIsCompact(t *testing.T) {
	const source = "DATA payload<>(SB)/8,$42\nGLOBL payload<>(SB),16,$8\nDATA holder<>(SB)/8,$payload<>(SB)\nGLOBL holder<>(SB),16,$65536\n"
	dataRelocationGoObject(t, source, "js", "wasm", true)
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: testResolveSym("test")}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, ".zero 65528") || len(ir) > 4096 {
		t.Fatalf("zero padding must not expand to one assembly directive per byte: %d IR bytes\n%s", len(ir), ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, options.TargetTriple, "compact-padding.ll", "compact-padding.o", ir)
}

func TestDataRelocationLoadsActualAddressAtRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var move, register string
	switch runtime.GOARCH {
	case "amd64":
		move, register = "MOVQ", "AX"
	case "arm64":
		move, register = "MOVD", "R0"
	default:
		t.Fatal("this host requires a matching runtime counterpart for the DATA relocation oracle")
	}
	source := fmt.Sprintf(`TEXT ·LoadPtr(SB),4,$0-8
%s holder<>+8(SB),%s
%s %s,ret+0(FP)
RET
TEXT ·PayloadPtr(SB),4,$0-8
%s $payload<>+3(SB),%s
%s %s,ret+0(FP)
RET
DATA payload<>(SB)/8,$0x1122334455667788
GLOBL payload<>(SB),16,$16
DATA holder<>(SB)/1,$0xaa
DATA holder<>+8(SB)/8,$payload<>+3(SB)
DATA holder<>+16(SB)/1,$0xbb
GLOBL holder<>(SB),16,$24
`, move, register, move, register, move, register, move, register)
	dataRelocationGoObject(t, source, runtime.GOOS, runtime.GOARCH, true)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module test/relocations\n\ngo 1.20\n",
		"data.s": source,
		"main.go": `package main
import "unsafe"
func LoadPtr() uintptr
func PayloadPtr() uintptr
func main() {
  p:=LoadPtr()
  if p==0 || p!=PayloadPtr() || *(*byte)(unsafe.Pointer(p))!=0x55 { panic("DATA relocation mismatch") }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goRun := exec.Command("go", "run", ".")
	goRun.Dir = dir
	goRun.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	if out, err := goRun.CombinedOutput(); err != nil {
		t.Fatalf("actual Go runtime relocation baseline: %v\n%s", err, out)
	}
	file, err := Parse(Arch(runtime.GOARCH), source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	resolve := func(symbol string) string {
		return strings.TrimSuffix(strings.TrimPrefix(symbol, "·"), "<>")
	}
	opt := Options{Goarch: runtime.GOARCH, TargetTriple: triple, ResolveSym: resolve,
		Sigs: map[string]FuncSig{
			"LoadPtr":    {Name: "LoadPtr", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Field: -1}}}},
			"PayloadPtr": {Name: "PayloadPtr", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Field: -1}}}},
		},
	}
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	const driver = `#include <stdint.h>
extern uintptr_t LoadPtr(void), PayloadPtr(void);
int main(void) {
  uintptr_t loaded=LoadPtr(), expected=PayloadPtr();
  if (!loaded || loaded!=expected) return 1;
  if (*(unsigned char*)loaded!=0x55) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "data_relocation_load", triple, ir, driver, nil)
	pkg := mustGoPackage(t, "test/relocations", "package relocations\nfunc LoadPtr() uintptr\nfunc PayloadPtr() uintptr\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: runtime.GOARCH, TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	compileAndRunRuntimeTestForTarget(t, llc, clang, "data_relocation_go_binding", triple, translation.Module.String(), driver, nil)
}
