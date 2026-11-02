package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// An initialized machine address can arrive as uintptr or as loaded bits.
// This does not turn it into a logical pointer or prove any pointee bytes.
func TestX86InitializedNumericNativeAddressesThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := x86ResultPointerWord(target.arch), "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		input := move + " p+0(FP),AX\n"
		rows := []struct {
			name, declaration, body string
			accept                  bool
		}{
			{"uintptr-load", "func Value(p uintptr) uint32", input + "MOVL (AX),CX\n", true},
			{"loaded-address", "func Value(p *uintptr) uint32", input + move + " (AX),AX\nMOVL (AX),CX\n", true},
			{"uintptr-store", "func Value(p uintptr) uint32", input + "MOVL $42,(AX)\nMOVL $42,CX\n", true},
			{"loaded-address-store", "func Value(p *uintptr) uint32", input + move + " (AX),AX\nMOVL $42,(AX)\nMOVL $42,CX\n", true},
			{"known-null-load", "func Value(p uintptr) uint32", move + " $0,AX\nMOVL (AX),CX\n", true},
			{"unknown-base", "func Value(p uintptr) uint32", "MOVL (AX),CX\n", false},
			{"partial-base", "func Value(p uintptr) uint32", "MOVB p+0(FP),AX\nMOVL (AX),CX\n", false},
			{"unknown-store-value", "func Value(p uintptr) uint32", input + "MOVL DX,(AX)\nMOVL $42,CX\n", false},
		}
		for _, row := range rows {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				body := row.body + fmt.Sprintf("MOVL CX,ret0+%d(FP)\nRET", word)
				_, file, sig, source := x86ResultInitializationFixture(t, target.arch, row.declaration, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone query acquired a native-memory observation", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
						if !row.accept {
							if err == nil || ir != "" {
								t.Fatal("undefined address/value input accepted", err)
							}
							return
						}
						if err != nil || !strings.Contains(ir, "volatile") {
							t.Fatal("initialized machine address lost its native memory effect", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					})
				}
			})
		}
	}
}
