package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64ExplicitMaskMoveGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64ExplicitMaskMoveSpec{
		"VMASKMOVPS": {laneBits: 32},
		"VMASKMOVPD": {laneBits: 64},
		"VPMASKMOVD": {laneBits: 32},
		"VPMASKMOVQ": {laneBits: 64},
	}
	if len(amd64ExplicitMaskMoveSpecs) != len(expected) {
		t.Fatalf("explicit-mask-move grammar has %d entries, want %d", len(amd64ExplicitMaskMoveSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64ExplicitMaskMoveSpecs[op]; !ok {
			t.Errorf("explicit-mask-move grammar omitted %s", op)
		} else if got != want {
			t.Errorf("explicit-mask-move grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86ExplicitMaskMoveCompleteGoAssemblerForms(t *testing.T) {
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
			var source strings.Builder
			source.WriteString("TEXT explicitmaskmoveforms(SB),$0-0\n")
			for _, op := range []string{"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ"} {
				for _, width := range []string{"X", "Y"} {
					last := 15
					fmt.Fprintf(&source, "\t%s 8(AX), %s1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s %s%d, %s1, 16(AX)\n", op, width, last, width)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"explicitmaskmoveforms": {Name: "explicitmaskmoveforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.masked.load.v4i32", "@llvm.masked.store.v8i32", "@llvm.masked.load.v2i64", "@llvm.masked.store.v4i64"} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR omitted fault-suppressing intrinsic %s", want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "explicit-mask-move-"+target.name+".ll", "explicit-mask-move-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ExplicitMaskMoveRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPMASKMOVD (AX), X0"},
		{goarch: "amd64", instruction: "VPMASKMOVD X0, X1, X2"},
		{goarch: "amd64", instruction: "VPMASKMOVD (AX), X0, (BX)"},
		{goarch: "amd64", instruction: "VPMASKMOVD X0, (AX), X1"},
		{goarch: "amd64", instruction: "VPMASKMOVD (AX), X0, Y1"},
		{goarch: "amd64", instruction: "VPMASKMOVD (AX), Z0, Z1"},
		{goarch: "amd64", instruction: "VPMASKMOVD.Z (AX), X0, X1"},
		{goarch: "amd64", instruction: "VMASKMOVPD (AX), X0, AX"},
		{goarch: "386", instruction: "VPMASKMOVQ (AX), X16, X0"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's explicit-mask-move table", test.instruction)
			}
		})
	}
}

func TestAMD64ExplicitMaskMoveRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT explicitmaskmovesemantics(SB),$0-40
	MOVQ out+0(FP), AX
	MOVQ loadmem+8(FP), BX
	MOVQ data+16(FP), CX
	MOVQ mask+24(FP), DX
	MOVQ storemem+32(FP), R8
	VMOVDQU 0(CX), Y0
	VMOVDQU 0(DX), Y1
	STC
	VPMASKMOVD 0(BX), Y1, Y2
	VMOVDQU Y2, 0(AX)
	VPMASKMOVD Y0, Y1, 0(R8)
	VPMASKMOVQ 0(BX), Y1, Y3
	VMOVDQU Y3, 32(AX)
	VPMASKMOVQ Y0, Y1, 32(R8)
	VMASKMOVPS 0(BX), Y1, Y4
	VMOVDQU Y4, 64(AX)
	VMASKMOVPS Y0, Y1, 64(R8)
	VMASKMOVPD 0(BX), Y1, Y5
	VMOVDQU Y5, 96(AX)
	VMASKMOVPD Y0, Y1, 96(R8)
	SETCS 128(AX)
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
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"explicitmaskmovesemantics": {
			Name: "explicitmaskmovesemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void explicitmaskmovesemantics(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *);
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  uint32_t load32[8], data32[8], mask32[8];
  uint8_t out[129]={0}, store[128];
  for (int i=0;i<8;i++) {
    load32[i]=UINT32_C(0x10203040)+(uint32_t)i;
    data32[i]=UINT32_C(0xa0b0c000)+(uint32_t)i;
    mask32[i]=(i==1||i==2||i==5)?UINT32_C(0x80000000):UINT32_C(0x7fffffff);
  }
  memset(store,0x5a,sizeof(store));
  explicitmaskmovesemantics(out,(uint8_t*)load32,(uint8_t*)data32,(uint8_t*)mask32,store);
  for (int i=0;i<8;i++) {
    int enabled=(int32_t)mask32[i]<0;
    if (u32(out+4*i)!=(enabled?load32[i]:0)) return 10;
    if (u32(store+4*i)!=(enabled?data32[i]:UINT32_C(0x5a5a5a5a))) return 11;
    if (u32(out+64+4*i)!=(enabled?load32[i]:0)) return 12;
    if (u32(store+64+4*i)!=(enabled?data32[i]:UINT32_C(0x5a5a5a5a))) return 13;
  }
  for (int i=0;i<4;i++) {
    int enabled=(int64_t)u64((uint8_t*)mask32+8*i)<0;
    if (u64(out+32+8*i)!=(enabled?u64((uint8_t*)load32+8*i):0)) return 20;
    if (u64(store+32+8*i)!=(enabled?u64((uint8_t*)data32+8*i):UINT64_C(0x5a5a5a5a5a5a5a5a))) return 21;
    if (u64(out+96+8*i)!=(enabled?u64((uint8_t*)load32+8*i):0)) return 22;
    if (u64(store+96+8*i)!=(enabled?u64((uint8_t*)data32+8*i):UINT64_C(0x5a5a5a5a5a5a5a5a))) return 23;
  }
  if (out[128]!=1) return 30;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "explicit_mask_move_semantics", triple, ir, mainC, runPrefix)
}
