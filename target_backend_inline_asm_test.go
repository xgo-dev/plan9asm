package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestTargetBackendInitializedCPUQueryRequiresNativeTarget(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, arch := range []string{"amd64", "386"} {
		native := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			native = "i386-unknown-linux-gnu"
		}
		for _, opcode := range []string{"CPUID", "XGETBV"} {
			// All implicit dword inputs are initialized. Neither a missing
			// leaf nor Void/result proof can mask the backend counterexample.
			source := "TEXT ·Query(SB),4,$0-0\nMOVL $0,AX\nMOVL $0,CX\n" + opcode + "\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+opcode+"/"+api+"/native", func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Query()", arch, native, api)
					if err != nil || !strings.Contains(ir, "asm sideeffect \""+strings.ToLower(opcode)+"\"") {
						t.Fatal("initialized native CPU-query control rejected or lost its real asm", err)
					}
					x86ResultInitializationObject(t, llc, native, ir, "cpu-query")
				})
				for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					t.Run(arch+"/"+opcode+"/"+api+"/"+triple, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Query()", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("initialized CPU-query inline asm escaped to an unspecified or foreign backend", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestTargetBackendInlineAsmGuardUsesActualValuesAndConstraints(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, row := range []struct {
		name, body string
		native     bool
	}{
		{"another-opcode", `define void @ordinary() {
  call void asm sideeffect "pause", "~{memory}"()
  ret void
}`, true},
		{"value-producing-asm", `define i32 @ordinary() {
  %value = call i32 asm "bswapl $0", "=r,0"(i32 7)
  ret i32 %value
}`, true},
		{"empty-fixed-register", `define i32 @ordinary() {
  %value = call i32 asm sideeffect "", "={ax}"()
  ret i32 %value
}`, true},
		{"empty-memory-barrier", `define void @ordinary() {
  call void asm sideeffect "", "~{memory}"()
  ret void
}`, false},
		{"empty-generic-register-use", `define void @ordinary() {
  call void asm sideeffect "", "r"(i32 7)
  ret void
}`, false},
		{"empty-generic-passthrough", `define i32 @ordinary() {
  %value = call i32 asm sideeffect "", "=r,0"(i32 7)
  ret i32 %value
}`, false},
		{"ordinary-name-and-string", `@annotation = private constant [6 x i8] c"cpuid\00"
define i32 @CPUID() { ret i32 7 }`, false},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			t.Run(row.name+"/"+triple, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := parseIRModuleInContext(ctx, fmt.Sprintf("target triple = %q\n%s\n", triple, row.body))
				if err != nil {
					t.Fatal("backend regression has malformed LLVM IR", err)
				}
				defer module.Dispose()
				// A detached, unused InlineAsm constant in this same context is
				// not a module requirement. Source spelling alone is not one,
				// either: the guard must follow actual module uses.
				_ = llvm.InlineAsm(llvm.FunctionType(ctx.VoidType(), nil, false), "cpuid", "~{memory}",
					true, false, llvm.InlineAsmDialectATT, false)
				file := &File{Arch: ArchAMD64}
				if row.name == "ordinary-name-and-string" {
					file.Funcs = []Func{{Sym: "CPUID", Instrs: []Instr{{Op: OpCPUID}}}}
				}
				err = validateTranslatedBackend(file, Options{Goarch: "amd64"}, module)
				if row.native && triple != "x86_64-unknown-linux-gnu" {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("used native inline asm or fixed-register constraints escaped the shared backend guard", err)
					}
				} else if err != nil {
					t.Fatal("portable IR, compiler barrier or matching native target was rejected", err)
				} else if !row.native && triple != "" {
					x86ResultInitializationObject(t, llc, triple, module.String(), "portable-barrier")
				}
			})
		}
	}
}

func TestTargetBackendInlineAsmSourceFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, source := range []struct {
		arch           Arch
		goarch, native string
	}{
		{ArchAMD64, "", "x86_64-unknown-linux-gnu"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown"},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "i386-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", ""} {
			t.Run(string(source.arch)+"/"+source.goarch+"/"+triple, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := parseIRModuleInContext(ctx, fmt.Sprintf(`target triple = %q
define void @ordinary() {
  call void asm sideeffect "nop", "~{memory}"()
  ret void
}
`, triple))
				if err != nil {
					t.Fatal(err)
				}
				defer module.Dispose()
				err = validateTranslatedBackend(&File{Arch: source.arch}, Options{Goarch: source.goarch}, module)
				if source.native != "" && triple == source.native {
					if err != nil {
						t.Fatal("matching source backend rejected native asm", err)
					}
					x86ResultInitializationObject(t, llc, triple, module.String(), "source-native-asm")
				} else if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("source-specific asm escaped its matching backend", err)
				}
			})
		}
	}
}
