package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86LEAFPAddressesRequireBoundStorage(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		widths := []string{"W", "L"}
		if target.arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, prefix := range []string{"", "$"} {
				for _, offset := range []int64{0, 1, 8, 9, 4, 12} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", target.triple, width, prefix, offset), func(t *testing.T) {
						// Storage-address validity is independent of result
						// initialization. The original unwritten-result source is
						// retained as a separate complete negative regression.
						source := fmt.Sprintf("TEXT Address(SB),4,$0-16\nMOVL $7,r+8(FP)\nLEA%s %sr+%d(FP),AX\nRET\n", width, prefix, offset)
						requireX86GoAssemblerResult(t, target.arch, source, prefix == "")
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						opt := Options{Goarch: target.arch, TargetTriple: target.triple,
							Sigs: map[string]FuncSig{"Address": {
								Name: "Address", Args: []LLVMType{I32}, Ret: I32,
								Frame: FrameLayout{
									Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
									Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1, Name: "r"}},
								},
							}},
						}
						ir, err := Translate(file, opt)
						if prefix == "$" {
							if err == nil {
								t.Fatal("accepted TYPE_ADDR outside Go's LEA Ym/Yrl row")
							}
							return
						}
						if offset == 4 || offset == 12 {
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("unbound FP address became success/zero: %v", err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						if !strings.Contains(ir, "ptrtoint ptr") {
							t.Fatalf("LEA used the parameter value instead of its storage:\n%s", ir)
						}
						compileLLVMToObject(t, llc, target.triple, "fp-address.ll", "fp-address.o", ir)
					})
				}
			}
		}
	}
}

func TestX86LEAFPAddressCannotInventScalarBacking(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		lea, triple := "LEAQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			lea, triple = "LEAL", "i386-unknown-linux-gnu"
		}
		for _, typ := range []LLVMType{"{ i8 }", "{}", "<8 x i8>"} {
			t.Run(arch+"/"+string(typ), func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Address(SB),4,$0-16\n"+lea+" x+0(FP),AX\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: arch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"Address": {
						Name: "Address", Args: []LLVMType{typ}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}}},
					}},
				})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("address lacks a scalar/canonical-byte contract, got %v", err)
				}
			})
		}
	}
}
