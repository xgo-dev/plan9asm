package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

const x86VMOVDQUAggregateFPOriginalSource = `TEXT vmovAggregateFP(SB),4,$0-24
MOVQ out+0(FP),AX
VMOVDQU key+8(FP),X0
VMOVDQU X0,(AX)
PXOR X0,X0
VMOVDQU X0,key+8(FP)
VMOVDQU key+8(FP),X1
VMOVDQU X1,16(AX)
RET
`

func TestX86VEXPackedMoveAggregateFPForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}

	for _, target := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			pointerBytes := 8
			if target.arch == "386" {
				pointerBytes = 4
			}
			for _, op := range []string{"VMOVDQA", "VMOVDQU"} {
				for _, width := range []struct {
					name, reg string
					bytes     int
				}{{"x", "X0", 16}, {"y", "Y0", 32}} {
					t.Run(op+"/"+width.name, func(t *testing.T) {
						name := "packedFrame"
						var slots []FrameSlot
						args := []LLVMType{Ptr}
						slots = append(slots, FrameSlot{Offset: 0, Type: Ptr, Index: 0, Field: -1})
						for i := 0; i < width.bytes/4; i++ {
							args = append(args, I32)
							slots = append(slots, FrameSlot{
								Offset: int64(pointerBytes + i*4),
								Type:   I32,
								Index:  i + 1,
								Field:  -1,
							})
						}
						mov := "MOVQ"
						if target.arch == "386" {
							mov = "MOVL"
						}
						source := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n%s out+0(FP),AX\n%s key+%d(FP),%s\n%s %s,(AX)\n%s (AX),%s\n%s %s,key+%d(FP)\nRET\n",
							name, pointerBytes+width.bytes, mov, op, pointerBytes, width.reg,
							op, width.reg, op, width.reg, op, width.reg, pointerBytes)
						requireX86GoAssemblerResult(t, target.arch, source, true)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						ir, err := Translate(file, Options{
							Goarch:       target.arch,
							TargetTriple: target.triple,
							Sigs: map[string]FuncSig{name: {
								Name: name, Args: args, Ret: Void,
								Frame: FrameLayout{Params: slots},
							}},
						})
						if op == "VMOVDQA" {
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("virtual aggregate acquired native alignment: %v", err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target.triple, "vmov-fp.ll", "vmov-fp.o", ir)
					})
				}
			}
		})
	}
}

func TestAMD64VMOVDQUAggregateFPBytesRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	file, err := Parse(ArchAMD64, x86VMOVDQUAggregateFPOriginalSource)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{
		Name: "vmovAggregateFP",
		Args: []LLVMType{Ptr, I32, I32, I32, I32},
		Ret:  Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: I32, Index: 1, Field: -1},
			{Offset: 12, Type: I32, Index: 2, Field: -1},
			{Offset: 16, Type: I32, Index: 3, Field: -1},
			{Offset: 20, Type: I32, Index: 4, Field: -1},
		}},
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if runtime.GOARCH != "amd64" {
		if runtime.GOOS != "darwin" || !rosettaAvailable() {
			t.Skip("execution requires amd64 or Rosetta; five-target object tests are separate")
		}
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs:         map[string]FuncSig{sig.Name: sig},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `#include <stdint.h>
#include <string.h>
#include <stdio.h>
extern void vmovAggregateFP(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t);
int main(void) {
  uint32_t key[4] = {0x12345678, 0x90abcdef, 0x13579bdf, 0x2468ace0};
  uint8_t out[32];
  memset(out, 0xa5, sizeof out);
  vmovAggregateFP(out, key[0], key[1], key[2], key[3]);
  for (int i = 0; i < 16; i++) {
    if (out[i] != ((uint8_t *)key)[i] || out[16+i] != 0) {
      fprintf(stderr, "VMOVDQU FP byte %d: got %u and %u\n", i, out[i], out[16+i]);
      return 1;
    }
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vmov_aggregate_fp", triple, ir, mainC, prefix)
}

func TestX86VEXPackedMoveAggregateFPRejectsInvalidForms(t *testing.T) {
	for _, target := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"386", "i386-unknown-linux-gnu"},
	} {
		for _, form := range []string{
			"VMOVDQU key+8(FP),X0",    // Four-byte slot cannot supply 16 bytes.
			"VMOVDQA key+8(FP),Y0",    // Four-byte slot cannot supply 32 bytes.
			"VMOVDQU key+8(FP),Z0",    // No Z form in Go's VEX table.
			"VMOVDQU.Z key+8(FP),X0",  // No VEX zeroing form.
			"VMOVDQU key+8(FP),K1,X0", // No VEX mask form.
		} {
			t.Run(target.arch+"/"+form, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT invalid(SB),4,$0-12\n"+form+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{
					Goarch:       target.arch,
					TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"invalid": {
						Name: "invalid", Args: []LLVMType{Ptr, I32}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1},
							{Offset: 8, Type: I32, Index: 1, Field: -1},
						}},
					}},
				})
				if err == nil {
					t.Fatalf("accepted unsupported form %q", form)
				}
			})
		}
	}
}
