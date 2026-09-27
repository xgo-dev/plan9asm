package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86XADDCompleteGo127FormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
		source string
	}{
		{
			name:   "darwin-amd64",
			goarch: "amd64",
			triple: "x86_64-apple-darwin",
			source: `
DATA xadddata+0(SB)/8, $0
GLOBL xadddata(SB), $8
TEXT xaddforms(SB),$0-0
	XADDB AH, BL
	XADDB R11, R12
	XADDB DL, 8(BX)
	XADDB R11, xadddata(SB)
	XADDW DX, BX
	XADDW R11, R12
	XADDW DX, 8(BX)
	XADDW R11, xadddata(SB)
	XADDL DX, BX
	XADDL R11, R12
	XADDL DX, 8(BX)
	XADDL R11, xadddata(SB)
	XADDQ DX, BX
	XADDQ R11, R12
	XADDQ DX, 8(BX)
	XADDQ R11, xadddata(SB)
	RET
`,
		},
		{
			name:   "linux-amd64",
			goarch: "amd64",
			triple: "x86_64-unknown-linux-gnu",
			source: `
DATA xadddata+0(SB)/8, $0
GLOBL xadddata(SB), $8
TEXT xaddforms(SB),$0-0
	XADDB AH, BL
	XADDB R11, R12
	XADDB DL, 8(BX)
	XADDB R11, xadddata(SB)
	XADDW DX, BX
	XADDW R11, R12
	XADDW DX, 8(BX)
	XADDW R11, xadddata(SB)
	XADDL DX, BX
	XADDL R11, R12
	XADDL DX, 8(BX)
	XADDL R11, xadddata(SB)
	XADDQ DX, BX
	XADDQ R11, R12
	XADDQ DX, 8(BX)
	XADDQ R11, xadddata(SB)
	RET
`,
		},
		{
			name:   "windows-amd64",
			goarch: "amd64",
			triple: "x86_64-pc-windows-msvc",
			source: `
DATA xadddata+0(SB)/8, $0
GLOBL xadddata(SB), $8
TEXT xaddforms(SB),$0-0
	XADDB AH, BL
	XADDB R11, R12
	XADDB DL, 8(BX)
	XADDB R11, xadddata(SB)
	XADDW DX, BX
	XADDW R11, R12
	XADDW DX, 8(BX)
	XADDW R11, xadddata(SB)
	XADDL DX, BX
	XADDL R11, R12
	XADDL DX, 8(BX)
	XADDL R11, xadddata(SB)
	XADDQ DX, BX
	XADDQ R11, R12
	XADDQ DX, 8(BX)
	XADDQ R11, xadddata(SB)
	RET
`,
		},
		{
			name:   "linux-386",
			goarch: "386",
			triple: "i386-unknown-linux-gnu",
			source: `
DATA xadddata386+0(SB)/4, $0
GLOBL xadddata386(SB), $4
TEXT xaddforms(SB),$0-0
	XADDB AH, BL
	XADDB BP, DI
	XADDB DL, 8(BX)
	XADDB SI, xadddata386(SB)
	XADDW DX, BX
	XADDW SI, DI
	XADDW DX, 8(BX)
	XADDW SI, xadddata386(SB)
	XADDL DX, BX
	XADDL SI, DI
	XADDL DX, 8(BX)
	XADDL SI, xadddata386(SB)
	RET
`,
		},
		{
			name:   "windows-386",
			goarch: "386",
			triple: "i686-pc-windows-msvc",
			source: `
DATA xadddata386+0(SB)/4, $0
GLOBL xadddata386(SB), $4
TEXT xaddforms(SB),$0-0
	XADDB AH, BL
	XADDB BP, DI
	XADDB DL, 8(BX)
	XADDB SI, xadddata386(SB)
	XADDW DX, BX
	XADDW SI, DI
	XADDW DX, 8(BX)
	XADDW SI, xadddata386(SB)
	XADDL DX, BX
	XADDL SI, DI
	XADDL DX, 8(BX)
	XADDL SI, xadddata386(SB)
	RET
`,
		},
	} {
		t.Run(target.name, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, target.source, true)
			file, err := Parse(ArchAMD64, target.source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"xaddforms": {Name: "xaddforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"add i8", "add i16", "add i32", "store i1"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("XADD lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "add i64") {
				t.Fatalf("XADDQ lowering omitted add i64:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "xadd-"+target.name+".ll", "xadd-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86XADDRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "XADDB (BX), DL"},
		{goarch: "amd64", instruction: "XADDW $1, DX"},
		{goarch: "amd64", instruction: "XADDL X0, DX"},
		{goarch: "amd64", instruction: "XADDQ DX, $1"},
		{goarch: "amd64", instruction: "XADDQ DX"},
		{goarch: "amd64", instruction: "XADDL DX, BX, AX"},
		{goarch: "amd64", instruction: "XADDL.Z DX, BX"},
		{goarch: "386", instruction: "XADDB SP, (BX)"},
		{goarch: "386", instruction: "XADDL R8, (BX)"},
		{goarch: "386", instruction: "XADDL DX, 1(R8)"},
		{goarch: "386", instruction: "XADDQ DX, BX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's XADD optab", test.instruction)
			}
		})
	}
}

func TestAMD64XADDRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT xaddsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $5, AX
	MOVQ $7, BX
	XADDQ AX, BX
	MOVQ AX, 0(DI)
	MOVQ BX, 8(DI)
	MOVB $0xff, 16(DI)
	MOVB $1, CL
	XADDB CL, 16(DI)
	MOVB CL, 17(DI)
	SETCS 18(DI)
	SETEQ 19(DI)
	SETPS 20(DI)
	SETMI 21(DI)
	SETOS 22(DI)
	MOVQ $0x1122, AX
	XADDB AH, AL
	MOVQ AX, 24(DI)
	MOVQ $0x1122334455660001, AX
	MOVQ $0x887766554433ffff, BX
	XADDW AX, BX
	MOVQ AX, 32(DI)
	MOVQ BX, 40(DI)
	MOVQ $3, AX
	XADDQ AX, AX
	MOVQ AX, 48(DI)
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
	ll, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"xaddsemantics": {
				Name:  "xaddsemantics",
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
extern void xaddsemantics(uint8_t *);
int main(void) {
  uint8_t out[56] = {0};
  xaddsemantics(out);
  if (*(uint64_t *)(out+0) != 7 || *(uint64_t *)(out+8) != 12) return 10;
  if (out[16] != 0 || out[17] != 0xff) return 11;
  if (out[18] != 1 || out[19] != 1 || out[20] != 1) return 12;
  if (out[21] != 0 || out[22] != 0) return 13;
  if (*(uint64_t *)(out+24) != 0x2233) return 14;
  if (*(uint64_t *)(out+32) != UINT64_C(0x112233445566ffff)) return 15;
  if (*(uint64_t *)(out+40) != UINT64_C(0x8877665544330000)) return 16;
  if (*(uint64_t *)(out+48) != 6) return 17;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "xadd_semantics", triple, ll, mainC, runPrefix)
}
