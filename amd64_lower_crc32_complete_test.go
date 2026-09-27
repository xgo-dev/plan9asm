package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86CRC32CompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA crc32data+0(SB)/8, $1\n")
	source.WriteString("GLOBL crc32data(SB), $8\n")
	source.WriteString("TEXT crc32forms(SB),$0-0\n")
	for _, width := range []string{"B", "W", "L"} {
		op := "CRC32" + width
		sourceRegister := "AX"
		if width == "B" {
			sourceRegister = "AL"
		}
		fmt.Fprintf(&source, "\t%s %s, BX\n", op, sourceRegister)
		fmt.Fprintf(&source, "\t%s 8(BX), CX\n", op)
		fmt.Fprintf(&source, "\t%s crc32data(SB), DX\n", op)
		if width == "B" {
			fmt.Fprintf(&source, "\t%s AX, DI\n", op)
		}
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\t%s R11, R12\n", op)
		} else {
			fmt.Fprintf(&source, "\t%s %s, SP\n", op, sourceRegister)
		}
	}
	if goarch == "amd64" {
		for _, form := range []string{
			"CRC32Q AX, BX",
			"CRC32Q 8(BX), CX",
			"CRC32Q crc32data(SB), DX",
			"CRC32Q R11, R12",
		} {
			fmt.Fprintf(&source, "\t%s\n", form)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86CRC32CompleteGo127FormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			source := x86CRC32CompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"crc32forms": {Name: "crc32forms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.x86.sse42.crc32.32.8",
				"@llvm.x86.sse42.crc32.32.16",
				"@llvm.x86.sse42.crc32.32.32",
				`"target-features"="+crc32,+sse4.2"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("CRC32 lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "@llvm.x86.sse42.crc32.64.64") {
				t.Fatalf("CRC32Q lowering omitted i64 intrinsic:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "crc32-"+target.name+".ll", "crc32-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86CRC32RejectsFormsOutsideGo127Optabs(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "CRC32B $1, AX"},
		{goarch: "amd64", instruction: "CRC32W AL, AX"},
		{goarch: "amd64", instruction: "CRC32L X0, AX"},
		{goarch: "amd64", instruction: "CRC32Q AX, 0(BX)"},
		{goarch: "amd64", instruction: "CRC32L AX, X0"},
		{goarch: "amd64", instruction: "CRC32L AX, AL"},
		{goarch: "amd64", instruction: "CRC32L AX"},
		{goarch: "amd64", instruction: "CRC32L.Z AX, BX"},
		{goarch: "386", instruction: "CRC32Q AX, BX"},
		{goarch: "386", instruction: "CRC32L R8, AX"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ycrc32b/ycrc32l tables", test.instruction)
			}
		})
	}
}

func TestAMD64CRC32RuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT crc32semantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI

	MOVL $0x12345678, BX
	MOVL $0xab00, AX
	CRC32B AH, BX
	MOVQ BX, 0(DI)

	MOVL $0x23456789, BX
	MOVL $0xcdef, AX
	CRC32W AX, BX
	MOVQ BX, 8(DI)

	MOVL $0x3456789a, BX
	MOVL $0x89abcdef, 40(DI)
	CRC32L 40(DI), BX
	MOVQ BX, 16(DI)

	MOVL $0x456789ab, BX
	MOVQ $0x0123456789abcdef, 48(DI)
	CRC32Q 48(DI), BX
	MOVQ BX, 24(DI)

	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVL $0, BX
	CRC32B AL, BX
	SETCS 32(DI)
	SETOS 33(DI)
	SETEQ 34(DI)
	SETMI 35(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"crc32semantics": {
				Name:  "crc32semantics",
				Args:  []LLVMType{Ptr},
				Ret:   Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void crc32semantics(uint8_t *);
static uint32_t crc32c(uint32_t crc, uint64_t value, unsigned bytes) {
  for (unsigned i = 0; i < bytes; i++) {
    crc ^= (uint8_t)value;
    value >>= 8;
    for (unsigned bit = 0; bit < 8; bit++)
      crc = (crc >> 1) ^ (UINT32_C(0x82f63b78) & (uint32_t)-(int32_t)(crc & 1));
  }
  return crc;
}
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[64] = {0};
  crc32semantics(out);
  if (load64(out + 0) != crc32c(UINT32_C(0x12345678), UINT64_C(0xab), 1)) return 10;
  if (load64(out + 8) != crc32c(UINT32_C(0x23456789), UINT64_C(0xcdef), 2)) return 11;
  if (load64(out + 16) != crc32c(UINT32_C(0x3456789a), UINT64_C(0x89abcdef), 4)) return 12;
  if (load64(out + 24) != crc32c(UINT32_C(0x456789ab), UINT64_C(0x0123456789abcdef), 8)) return 13;
  if (out[32] != 1 || out[33] != 1 || out[34] != 0 || out[35] != 1) return 14;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "crc32_semantics", triple, ir, mainC, runPrefix)
}
