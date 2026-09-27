package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestImplicitZeroReturnTypesCompileAcrossArchitectures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch           Arch
		goarch, triple string
	}{
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu"},
	} {
		for _, ret := range []LLVMType{Void, I1, I8, I16, I32, I64, Ptr, "float", "double", "{ i64, double }"} {
			t.Run(target.goarch+"/"+string(ret), func(t *testing.T) {
				// Generated assembly may leave a final unreachable block with
				// no RET. Its synthetic terminator still needs well-typed IR.
				file, err := Parse(target.arch, "TEXT zero(SB),4,$0-0\nNOP\n")
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{
					Goarch: target.goarch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"zero": {Name: "zero", Ret: ret}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "zero.ll", "zero.o", ir)
			})
		}
	}
}

func TestImplicitZeroReturnRuntime(t *testing.T) {
	arch := ArchARM64
	if runtime.GOARCH == "amd64" {
		arch = ArchAMD64
	} else if runtime.GOARCH != "arm64" {
		t.Skip("native amd64/arm64 execution; other architectures run in the required cross-runtime matrix")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	ir, main := implicitZeroReturnRuntimeFixture(t, arch, runtime.GOARCH, testTargetTriple(runtime.GOOS, runtime.GOARCH))
	compileAndRunRuntimeTest(t, llc, clang, "zero-return", ir, main)
}

// The required CI cross-runtime job selects the TestCrossLinuxRuntimeMatrix prefix.
func TestCrossLinuxRuntimeMatrixImplicitZeroReturn(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}

	for _, target := range []struct {
		arch                                 Arch
		goarch, triple, compiler, qemu, root string
	}{
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "i686-linux-gnu-gcc", "qemu-i386", "/usr/i686-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "arm-linux-gnueabihf-gcc", "qemu-arm", "/usr/arm-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "aarch64-linux-gnu-gcc", "qemu-aarch64", "/usr/aarch64-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			ir, main := implicitZeroReturnRuntimeFixture(t, target.arch, target.goarch, target.triple)
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{target.compiler}, "zero-return-"+target.goarch,
				target.triple, ir, main, []string{target.qemu, "-L", target.root})
		})
	}
}

func implicitZeroReturnRuntimeFixture(t *testing.T, arch Arch, goarch, triple string) (string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for i, ret := range []struct {
		llvm  LLVMType
		ctype string
	}{
		{I1, "_Bool"}, {I8, "int8_t"}, {I16, "int16_t"}, {I32, "int32_t"},
		{I64, "int64_t"}, {Ptr, "void*"}, {"float", "float"}, {"double", "double"},
	} {
		name := fmt.Sprintf("zero%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nNOP\n", name)
		sigs[name] = FuncSig{Name: name, Ret: ret.llvm}
		fmt.Fprintf(&declarations, "extern %s %s(void);\n", ret.ctype, name)
		fmt.Fprintf(&checks, "    if (%s() != 0) return %d;\n", name, i+1)
	}
	file, err := Parse(arch, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: goarch, TargetTriple: triple, Sigs: sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "    return 0;\n}\n"
	return ir, main
}

func TestWASMMissingReturnRemainsAnError(t *testing.T) {
	// Wasm uses a typed value stack, not this register-architecture fallback.
	// Do not silently replace its missing results or introduce blockaddress.
	file, err := Parse(ArchWASM, "TEXT missing(SB),4,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown",
		Sigs: map[string]FuncSig{"missing": {Name: "missing", Ret: "double"}},
	})
	if err == nil || !strings.Contains(err.Error(), "missing double return value") {
		t.Fatalf("missing wasm return: %v", err)
	}
}
