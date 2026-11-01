package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This fixture is synthetic LLVM, not original Go assembly or an ABI0
// declaration. Exercise the existing typed terminator without inventing a
// source function, native frame, incoming bytes or result-storage permission.
func implicitZeroReturnFunctionIR(t *testing.T, arch Arch, name string, ret LLVMType) string {
	t.Helper()
	var output strings.Builder
	fmt.Fprintf(&output, "define %s %s() {\nentry:\n", ret, llvmGlobal(name))
	sig := FuncSig{Ret: ret}
	switch arch {
	case ArchAMD64:
		(&amd64Ctx{b: &output, sig: sig}).lowerRetZero()
	case ArchARM:
		(&armCtx{b: &output, sig: sig}).lowerRetZero()
	case ArchARM64:
		(&arm64Ctx{b: &output, sig: sig}).lowerRetZero()
	default:
		t.Fatal("no register-architecture synthetic zero terminator", arch)
	}
	output.WriteString("}\n")
	return output.String()
}

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
				ir := fmt.Sprintf("target triple = %q\n", target.triple) +
					implicitZeroReturnFunctionIR(t, target.arch, "zero", ret)
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
	ir, main := implicitZeroReturnRuntimeFixture(t, arch, testTargetTriple(runtime.GOOS, runtime.GOARCH))
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
			ir, main := implicitZeroReturnRuntimeFixture(t, target.arch, target.triple)
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{target.compiler}, "zero-return-"+target.goarch,
				target.triple, ir, main, []string{target.qemu, "-L", target.root})
		})
	}
}

func implicitZeroReturnRuntimeFixture(t *testing.T, arch Arch, triple string) (string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	fmt.Fprintf(&source, "target triple = %q\n", triple)
	for i, ret := range []struct {
		llvm  LLVMType
		ctype string
	}{
		{I1, "_Bool"}, {I8, "int8_t"}, {I16, "int16_t"}, {I32, "int32_t"},
		{I64, "int64_t"}, {Ptr, "void*"}, {"float", "float"}, {"double", "double"},
	} {
		name := fmt.Sprintf("zero%d", i)
		source.WriteString(implicitZeroReturnFunctionIR(t, arch, name, ret.llvm))
		fmt.Fprintf(&declarations, "extern %s %s(void);\n", ret.ctype, name)
		fmt.Fprintf(&checks, "    if (%s() != 0) return %d;\n", name, i+1)
	}
	main := "#include <stdint.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "    return 0;\n}\n"
	return source.String(), main
}

func TestImplicitZeroReturnTypedEmittersRemainSynthetic(t *testing.T) {
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64} {
		for _, row := range []struct {
			ret  LLVMType
			want string
		}{
			{Void, "ret void"}, {I1, "ret i1 false"}, {I8, "ret i8 0"},
			{I16, "ret i16 0"}, {I32, "ret i32 0"}, {I64, "ret i64 0"},
			{Ptr, "ret ptr null"}, {"float", "ret float 0.000000e+00"},
			{"double", "ret double 0.000000e+00"}, {"{ i64, double }", "ret { i64, double } zeroinitializer"},
		} {
			t.Run(string(arch)+"/"+string(row.ret), func(t *testing.T) {
				ir := implicitZeroReturnFunctionIR(t, arch, "zero", row.ret)
				if !strings.Contains(ir, "  "+row.want+"\n") || strings.Contains(ir, "alloca") || strings.Contains(ir, "blockaddress") {
					t.Fatalf("synthetic typed terminator borrowed storage or has the wrong value:\n%s", ir)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := parseIRModuleInContext(ctx, ir)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestImplicitZeroReturnRuntimeFixtureRemainsSynthetic(t *testing.T) {
	for _, target := range []struct {
		arch         Arch
		name, triple string
	}{
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ir, driver := implicitZeroReturnRuntimeFixture(t, target.arch, target.triple)
			if strings.Count(ir, "define ") != 8 || strings.Count(driver, "extern ") != 8 ||
				strings.Count(driver, "() != 0") != 8 || !strings.Contains(ir, target.triple) ||
				strings.Contains(ir, "alloca") || strings.Contains(ir, "blockaddress") {
				t.Fatal("complete synthetic runtime type/target inventory or source-free boundary changed")
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := parseIRModuleInContext(ctx, ir)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImplicitZeroReturnDoesNotAuthorizeOrdinaryABI0Bool(t *testing.T) {
	t.Run("original-manual-386-I1", func(t *testing.T) {
		file, err := Parse(ArchAMD64, "TEXT zero(SB),4,$0-0\nNOP\n")
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"zero": {Name: "zero", Ret: I1}}}
		if ir, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Fatalf("synthetic emitter fixture acquired an ordinary ABI0 permission: %v", err)
		}
	})
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"no source RET", "NOP", false},
		{"unwritten result", "NOP\nRET", false},
		{"noncanonical result", "MOVB $2,ret+0(FP)\nRET", false},
		{"raw context", "BYTE $0x90\nRET", false},
		{"actual canonical result", "MOVB $1,ret+0(FP)\nRET", true},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-1\n" + row.body + "\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view() bool", "386", "i386-unknown-linux-gnu", api)
				if row.valid && (err != nil || ir == "") || !row.valid && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatalf("ordinary canonical/missing result boundary changed: %v", err)
				}
			})
		}
	}
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
