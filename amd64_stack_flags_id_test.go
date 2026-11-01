package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86StackIDSource(goarch string) string {
	// Go 1.27's asm6.go gives PUSHF/POPF six zero-operand W/L/Q forms.
	// Intel SDM Volume 2B's POPF description preserves the upper flags on
	// a 16-bit operand; the CPUID ID bit belongs to EFLAGS/RFLAGS bit 21.
	// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf
	width, flags := "Q", "Q"
	if goarch == "386" {
		width, flags = "L", "L"
	}
	return fmt.Sprintf(`TEXT idroundtrip(SB),4,$0-8
	MOV%s out+0(FP), DI
	PUSHF%s
	POP%s AX
	MOV%s AX, CX
	XOR%s $0x200000, AX
	PUSH%s AX
	POPF%s
	PUSHF%s
	POP%s AX
	PUSH%s CX
	POPF%s
	XOR%s CX, AX
	AND%s $0x200000, AX
	MOVL AX, 0(DI)
	PUSHF%s
	POP%s AX
	OR%s $0x200000, AX
	PUSH%s AX
	POPF%s
	PUSHW $2
	POPFW
	PUSHF%s
	POP%s AX
	AND%s $0x200000, AX
	MOVL AX, 4(DI)
	LAHF
	SAHF
	STC
	PUSHFW
	CLC
	POPFW
	SETCS 12(DI)
	PUSHF%s
	POP%s AX
	AND%s $0x200000, AX
	MOVL AX, 8(DI)
	PUSH%s CX
	POPF%s
	RET
`, width, flags, width, width, width, width, flags, flags, width,
		width, flags, width, width, flags, width, width, width, flags,
		flags, width, width, flags, width, width, width, flags)
}

func x86StackIDInitializedSource(t *testing.T, arch string) string {
	t.Helper()
	width := "Q"
	if arch == "386" {
		width = "L"
	}
	source := x86StackIDSource(arch)
	entry := "\tMOV" + width + " out+0(FP), DI"
	if strings.Count(source, entry) != 1 || strings.Count(source, "\tLAHF\n") != 1 {
		t.Fatal("initialized ID fixture lost its unique original entry/AH boundaries")
	}
	// Define every arithmetic flag, DF and ID explicitly, rather than borrowing
	// the emitter's default slots. CMP repairs only the later AND's undefined AF;
	// neither seed changes the original ID toggle/upper-preservation checks.
	source = strings.Replace(source, entry, "\tPUSH"+width+" $2\n\tPOPF"+width+"\n"+entry, 1)
	// Full snapshots transport complete numerical words. Define the status
	// bits before each; the original checks observe only ID there. Do not
	// touch PUSHFW: its later CF roundtrip intentionally follows STC.
	source = strings.ReplaceAll(source, "\tPUSHF"+width+"\n", "\tCMP"+width+" AX, AX\n\tPUSHF"+width+"\n")
	source = strings.Replace(source, "\tLAHF\n", "\tCMP"+width+" AX, AX\n\tLAHF\n", 1)
	if arch == "386" {
		source = strings.Replace(source, "$0-8", "$0-4", 1)
	}
	return source
}

func TestX86StackFlagsIDObjects(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source := x86StackIDSource(target.arch)
			if target.arch == "386" {
				source = strings.Replace(source, "$0-8", "$0-4", 1)
			}
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := x86StackIDOptions(target.arch, target.triple)
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original unknown entry/AF state became numerical FLAGS input", err)
			}
			initialized := x86StackIDInitializedSource(t, target.arch)
			requireX86GoAssemblerResult(t, target.arch, initialized, true)
			file, err = Parse(ArchAMD64, initialized)
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := x86PackedFloatStorageAPI(api, file, options)
				if err != nil {
					t.Fatal("initialized complete ID program rejected", api, err)
				}
				if !strings.Contains(ir, "%flags_id = alloca i1") {
					t.Fatal("stack flags cannot silently omit the CPUID ID bit")
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

func x86StackIDOptions(arch, triple string) Options {
	return Options{Goarch: arch, TargetTriple: triple,
		Sigs: map[string]FuncSig{"idroundtrip": {
			Name: "idroundtrip", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	}
}

func TestAMD64StackFlagsIDRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	// This executes translated numerical FLAGS/stack state, not original Go
	// bytes or physical ID. No native x86 opcode or Rosetta is required.
	file, err := Parse(ArchAMD64, x86StackIDInitializedSource(t, "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, x86StackIDOptions("amd64", triple))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "asm ") {
		t.Fatal("portable ID oracle acquired a native opcode")
	}
	const oracle = `
#include <stdint.h>
extern void idroundtrip(uint32_t *);
int main(void) {
  uint32_t out[4] = {0};
  idroundtrip(out);
  if (out[0] != 0x200000) return 10;
  if (out[1] != 0x200000) return 11;
  if (out[2] != 0x200000) return 12;
  if (out[3] != 1) return 13;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "stack_flags_id", triple, ir, oracle, nil)
}
