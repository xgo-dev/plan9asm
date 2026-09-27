package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedMoveMaskedMemoryRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; separate five-target object tests remain required")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, spec := range []struct {
		op   string
		bits int
	}{
		{"VMOVAPS", 32}, {"VMOVAPD", 64}, {"VMOVUPS", 32}, {"VMOVUPD", 64},
		{"VMOVDQA32", 32}, {"VMOVDQA64", 64}, {"VMOVDQU8", 8}, {"VMOVDQU16", 16}, {"VMOVDQU32", 32}, {"VMOVDQU64", 64},
	} {
		for width, reg := range []string{"X0", "Y0", "Z0"} {
			bytes := 16 << width
			name := fmt.Sprintf("packedmemory%d", index)
			index++
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ in+0(FP),BX\nMOVQ mem+8(FP),AX\nMOVQ out+16(FP),DI\nMOVQ mask+24(FP),CX\nKMOVQ CX,K7\nVMOVUPS (BX),%s\n%s (AX),K7,%s\nVMOVUPS %s,(DI)\nVMOVUPS (BX),%s\n%s.Z (AX),K7,%s\nVMOVUPS %s,%d(DI)\nVMOVUPS (BX),%s\n%s %s,K7,(AX)\nRET\n", name, reg, spec.op, reg, reg, reg, spec.op, reg, reg, bytes, reg, spec.op, reg)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(const void *,void *,void *,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if(check(%s,%d,%d)) return %d;\n", name, bytes, spec.bits/8, index)
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
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
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int check(void (*fn)(const void *,void *,void *,uint64_t),int bytes,int lane) {
  uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX};
  for (int m=0;m<4;m++) {
    _Alignas(64) uint8_t in[64],mem[64],out[128],old[64];
    for(int i=0;i<64;i++) { in[i]=(uint8_t)(17+i*3); mem[i]=old[i]=(uint8_t)(255-i*7); }
    fn(in,mem,out,masks[m]);
    for(int i=0;i<bytes;i++) {
      int active=(masks[m]>>(i/lane))&1;
      if(out[i]!=(active ? old[i] : in[i]) || out[bytes+i]!=(active ? old[i] : 0) || mem[i]!=(active ? in[i] : old[i])) {
        fprintf(stderr,"packed move bytes=%d lane=%d mask=%d byte=%d mismatch\n",bytes,lane,m,i);return 1;
      }
    }
    if(!masks[m]) { fn(in,0,out,0); if(memcmp(in,out,bytes)) return 1; for(int i=0;i<bytes;i++) if(out[bytes+i]) return 1; }
  }
  return 0;
}

int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_move_masked_memory", triple, ir, mainC, prefix)
}

func TestX86PackedMoveRegisterViewsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; separate five-target object tests remain required")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, spec := range []struct {
		op   string
		bits int
	}{
		{"VMOVAPS", 32}, {"VMOVAPD", 64}, {"VMOVUPS", 32}, {"VMOVUPD", 64},
		{"VMOVDQA32", 32}, {"VMOVDQA64", 64}, {"VMOVDQU8", 8}, {"VMOVDQU16", 16}, {"VMOVDQU32", 32}, {"VMOVDQU64", 64},
	} {
		for width, prefix := range []string{"X", "Y", "Z"} {
			for form := 0; form < 6; form++ {
				name := fmt.Sprintf("packedviews%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ in+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ out+16(FP),DI\nMOVQ mask+24(FP),CX\nKMOVQ CX,K7\n", name)
				for _, view := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&source, "VMOVUPS (AX),%s0\nVMOVUPS (BX),%s1\n", view, view)
				}
				input := "(BX)"
				if form >= 3 {
					input = prefix + "1"
				}
				op, mask := spec.op, ""
				if form%3 != 0 {
					mask = "K7,"
				}
				if form%3 == 2 {
					op += ".Z"
				}
				fmt.Fprintf(&source, "%s %s,%s%s0\nVMOVUPS Z0,(DI)\nVMOVUPS Y0,64(DI)\nVMOVUPS X0,96(DI)\nRET\n", op, input, mask, prefix)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1}}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *,uint64_t);\n", name)
				fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d)) return %d;\n", name, 16<<width, spec.bits/8, form%3, index)
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `#include <stdint.h>
#include <stdio.h>
` + declarations.String() + `
static int check(void (*fn)(const void *,const void *,void *,uint64_t),int bytes,int lane,int form) {
  uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX};
  for(int m=0;m<4;m++) {
    _Alignas(64) uint8_t in[64],old[64],out[112];
    for(int i=0;i<64;i++) {in[i]=(uint8_t)(17+i*3);old[i]=(uint8_t)(255-i*7);}
    fn(in,old,out,masks[m]);
    for(int view=0;view<3;view++) for(int i=0;i<(64>>view);i++) {
      int active=form==0 || ((masks[m]>>(i/lane))&1);
      uint8_t want=i>=bytes ? 0 : active ? in[i] : form==2 ? 0 : old[i];
      int offset=view==0 ? 0 : view==1 ? 64 : 96;
      if(out[offset+i]!=want) {fprintf(stderr,"packed views width=%d lane=%d form=%d mask=%d view=%d byte=%d got=%d want=%d\n",bytes,lane,form,m,view,i,out[offset+i],want);return 1;}
    }
  }
  return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_move_views", triple, ir, mainC, runPrefix)
}
