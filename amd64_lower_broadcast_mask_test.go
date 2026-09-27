package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64MaskBroadcastGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64MaskBroadcastSpec{
		"VPBROADCASTMB2Q": {sourceBits: 8, laneBits: 64},
		"VPBROADCASTMW2D": {sourceBits: 16, laneBits: 32},
	}
	if len(amd64MaskBroadcastSpecs) != len(expected) {
		t.Fatalf("mask-broadcast grammar has %d entries, want %d", len(amd64MaskBroadcastSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64MaskBroadcastSpecs[op]; !ok {
			t.Errorf("mask-broadcast grammar omitted %s", op)
		} else if got != want {
			t.Errorf("mask-broadcast grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86MaskBroadcastCompleteFormsAcrossTargets(t *testing.T) {
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
			xyLast, zLast := 31, 31
			if target.goarch == "386" {
				zLast = 7
			}
			var source strings.Builder
			source.WriteString("TEXT maskbroadcastforms(SB),$0-0\n")
			for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
				fmt.Fprintf(&source, "\t%s K0, X%d\n", op, xyLast)
				fmt.Fprintf(&source, "\t%s K7, Y%d\n", op, xyLast)
				fmt.Fprintf(&source, "\t%s K1, Z%d\n", op, zLast)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"maskbroadcastforms": {Name: "maskbroadcastforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<2 x i64>", "<8 x i32>", "<8 x i64>", "<16 x i32>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("mask broadcast lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "mask-broadcast-"+target.name+".ll", "mask-broadcast-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86MaskBroadcastRejectsFormsOutsideGoTable(t *testing.T) {
	for _, instruction := range []string{
		"VPBROADCASTMB2Q AX, X0",
		"VPBROADCASTMW2D K8, X0",
		"VPBROADCASTMB2Q K1, K2",
		"VPBROADCASTMW2D.Z K1, X0",
		"VPBROADCASTMB2Q K1, K2, X0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvpbroadcastmb2q table", instruction)
			}
		})
	}
}

func TestAMD64MaskBroadcastRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT maskbroadcastsemantics(SB),$0-16
	MOVQ out+0(FP), CX
	MOVQ mask+8(FP), AX
	KMOVQ AX, K1
	STC
	VPBROADCASTMB2Q K1, X0
	MOVUPS X0, 0(CX)
	VPBROADCASTMW2D K1, X1
	MOVUPS X1, 16(CX)
	SETCS 32(CX)
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
		Sigs: map[string]FuncSig{"maskbroadcastsemantics": {
			Name: "maskbroadcastsemantics", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void maskbroadcastsemantics(uint8_t *, uint64_t);
int main(void) {
  uint8_t out[33] = {0};
  uint64_t q[2]; uint32_t d[4];
  maskbroadcastsemantics(out, UINT64_C(0x1234beefa5));
  memcpy(q, out, 16); memcpy(d, out + 16, 16);
  if (q[0] != UINT64_C(0xa5) || q[1] != UINT64_C(0xa5)) return 10;
  for (int i = 0; i < 4; i++) if (d[i] != UINT32_C(0xefa5)) return 11 + i;
  if (out[32] != 1) return 20;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "mask_broadcast_semantics", triple, ir, mainC, runPrefix)
}
