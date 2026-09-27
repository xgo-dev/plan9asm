package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86MaskUnpackCompleteGo127FormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = `TEXT maskunpackforms(SB),$0-0
	KUNPCKBW K0, K7, K3
	KUNPCKBW K2, K4, K4
	KUNPCKWD K7, K5, K3
	KUNPCKDQ K1, K6, K0
	KUNPCKDQ K5, K5, K5
	RET
`
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
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"maskunpackforms": {Name: "maskunpackforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"shl i64", "or i64", "255", "65535", "4294967295"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("mask unpack lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "mask-unpack-"+target.name+".ll", "mask-unpack-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86MaskUnpackRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"KUNPCKBW K1, K2",
		"KUNPCKWD K1, K2, K3, K4",
		"KUNPCKDQ AX, K2, K3",
		"KUNPCKBW K1, K8, K3",
		"KUNPCKWD K1, K2, K8",
		"KUNPCKDQ.Z K1, K2, K3",
	} {
		for _, goarch := range []string{"amd64", "386"} {
			t.Run(goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(instruction), func(t *testing.T) {
				source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, goarch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				triple := "x86_64-unknown-linux-gnu"
				if goarch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{
					Goarch:       goarch,
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("Translate accepted %q outside Go 1.27's KUNPCK table for %s", instruction, goarch)
				}
			})
		}
	}
}

func TestAMD64MaskUnpackRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT maskunpacksemantics(SB),$0-24
	MOVQ out+0(FP), AX
	KMOVQ a+8(FP), K1
	KMOVQ b+16(FP), K2
	STC
	KUNPCKBW K1, K2, K3
	KMOVQ K3, 0(AX)
	SETCS 24(AX)
	KUNPCKWD K1, K2, K4
	KMOVQ K4, 8(AX)
	KUNPCKDQ K1, K2, K2
	KMOVQ K2, 16(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
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
			"maskunpacksemantics": {
				Name: "maskunpacksemantics", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void maskunpacksemantics(uint8_t *, uint64_t, uint64_t);
int main(void) {
  uint8_t storage[25] = {0};
  uint64_t *out = (uint64_t *)storage;
  uint64_t a = UINT64_C(0x0123456789abcdef);
  uint64_t b = UINT64_C(0xfedcba9876543210);
  maskunpacksemantics(storage, a, b);
  if (out[0] != ((b & 0xff) << 8 | (a & 0xff))) return 10;
  if (out[1] != ((b & 0xffff) << 16 | (a & 0xffff))) return 11;
  if (out[2] != ((b & UINT64_C(0xffffffff)) << 32 | (a & UINT64_C(0xffffffff)))) return 12;
  if (storage[24] != 1) return 13;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mask_unpack_semantics", triple, ir, mainC, runPrefix)
}
