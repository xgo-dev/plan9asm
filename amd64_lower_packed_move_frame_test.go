package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedMoveFrameRejectsUndeclaredSlots(t *testing.T) {
	for _, op := range []string{"VMOVAPS", "VMOVAPD", "VMOVUPS", "VMOVUPD", "VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
		for _, reg := range []string{"X0", "Y0", "Z0"} {
			for _, instruction := range []string{fmt.Sprintf("%s %s,K7,out+0(FP)", op, reg), fmt.Sprintf("%s out+0(FP),K7,%s", op, reg)} {
				for _, arch := range []string{"386", "amd64"} {
					file, err := Parse(ArchAMD64, "TEXT framebounds(SB),4,$0-8\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					_, err = Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{
						"framebounds": {Name: "framebounds", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}},
					}})
					if err == nil {
						t.Errorf("%s accepted %s beyond a single 8-byte frame slot", arch, instruction)
					}
				}
			}
		}
	}
}

func TestX86PackedMoveFrameSlotsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for index, spec := range []struct {
		op   string
		bits int
	}{
		{"VMOVAPS", 32}, {"VMOVAPD", 64}, {"VMOVUPS", 32}, {"VMOVUPD", 64},
		{"VMOVDQA32", 32}, {"VMOVDQA64", 64}, {"VMOVDQU8", 8}, {"VMOVDQU16", 16}, {"VMOVDQU32", 32}, {"VMOVDQU64", 64},
	} {
		name := fmt.Sprintf("packedframe%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ mask+24(FP),BX\nKMOVQ BX,K7\nVMOVUPS (DI),X0\n%s a+8(FP),K7,X0\nVMOVUPS X0,(DI)\nVMOVUPS 16(DI),X1\n%s X1,K7,a+8(FP)\nMOVQ a+8(FP),AX\nMOVQ AX,16(DI)\nMOVQ b+16(FP),AX\nMOVQ AX,24(DI)\nRET\n", name, spec.op, spec.op)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64, I64, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}, {Offset: 16, Type: I64, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1}}}}
		fmt.Fprintf(&declarations, "extern void %s(void *,uint64_t,uint64_t,uint64_t);\n", name)
		fmt.Fprintf(&checks, "if(check(%s,%d)) return %d;\n", name, spec.bits/8, index+1)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "x86_64-w64-windows-gnu"} {
		ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "packed-frame.ll", "packed-frame.o", ir)
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; object compilation above is required on every host")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `#include <stdint.h>
#include <string.h>
#include <stdio.h>
` + declarations.String() + `
static int check(void (*fn)(void *,uint64_t,uint64_t,uint64_t),int lane) {
  uint64_t words[]={UINT64_C(0x123456789abcdef0),UINT64_C(0xfedcba9876543210)};
  uint64_t masks[]={0,1,UINT64_C(0xaaaa),UINT64_MAX};
  uint8_t frame[16]; memcpy(frame,words,16);
  for(int m=0;m<4;m++) {
    _Alignas(64) uint8_t out[32],old[32];
    for(int i=0;i<32;i++) out[i]=old[i]=(uint8_t)(19+i*7);
    fn(out,words[0],words[1],masks[m]);
    for(int i=0;i<16;i++) {
      int active=(masks[m]>>(i/lane))&1;
      if(out[i]!=(active ? frame[i] : old[i]) || out[16+i]!=(active ? old[16+i] : frame[i])) {
        fprintf(stderr,"packed FP mismatch lane=%d mask=%d byte=%d\n",lane,m,i);return 1;
      }
    }
  }
  return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_move_frame", triple, ir, mainC, prefix)
}
