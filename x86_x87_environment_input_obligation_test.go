package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This is a separate mode32 counterpart, not the original amd64 literal with
// a partial uint64 store. The real Go result is uint32 at ABI0 offset four.
const x86X87ENV386BoundedSource = `TEXT ·Value(SB),4,$0-8
MOVL env+0(FP),BX
FLDENV (BX)
BYTE $0xdb; BYTE $0xe2
XORL AX,AX
FSTSW AX
MOVL AX,ret+4(FP)
FINIT
RET
`

func TestX86X87ENV386BoundedWholeSourceThreeAPIs(t *testing.T) {
	const declaration = "func Value(env *byte) uint32"
	_, _, sig, _ := x86ResultInitializationFixture(t, "386", declaration, "RET")
	if sig.Ret != I32 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 4 ||
		sig.Frame.Results[0].Type != I32 || len(sig.Frame.Params) != 1 || sig.Frame.Params[0].Type != Ptr {
		t.Fatal("mode32 counterpart lost its complete actual uint32 result layout", sig)
	}
	file, err := Parse(ArchAMD64, x86X87ENV386BoundedSource)
	if err != nil || len(file.Funcs) != 1 || file.Funcs[0].ArgSize != 8 || file.Funcs[0].FrameSize != 0 ||
		strings.Count(x86X87ENV386BoundedSource, "FINIT\n") != 1 ||
		!strings.Contains(x86X87ENV386BoundedSource, "FSTSW AX\nMOVL AX,ret+4(FP)\nFINIT\nRET\n") {
		t.Fatal("complete mode32 source/header/capture ordering changed", err)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, bounded := range []bool{true, false} {
			source, name := x86X87ENV386BoundedSource, "bounded-uint32"
			if !bounded {
				source, name = strings.Replace(source, "FINIT\n", "", 1), "unknown-shape-at-RET"
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(triple+"/"+name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declaration, "386", triple, api, X87Software)
					if bounded {
						if err != nil || ir == "" {
							t.Fatalf("bounded mode32 counterpart rejected before numerical observation: %v\n%s", err, source)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("mode32 return borrowed unknown Tag/TOP as an empty stack", err)
					} else {
						t.Logf("FIRST_CONTEXT unknown-shape-at-RET (later guard not inferred): %v", err)
					}
				})
			}
		}
	}
}

func x86X87ENVVoidSource(t *testing.T, arch, declaration, body string) string {
	t.Helper()
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
	if sig.Ret != Void || len(sig.Frame.Results) != 0 {
		t.Fatal("Void ENV fixture acquired a fabricated result")
	}
	var extent int64
	for _, slot := range sig.Frame.Params {
		if end := slot.Offset + x86FrameScalarBytes(slot.Type, arch); end > extent {
			extent = end
		}
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", extent, body)
}

// Only the actual-pointer and unknown-base pair is repeated through all APIs.
// Each additional row isolates one source/input obligation on a named API;
// there is no Cartesian object/native matrix or new memory-owner producer.
func TestX86X87ENVVoidSourceInputsCannotHideBehindNoResult(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, word, triple := "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		pointer := move + " env+0(FP),BX\n"
		readAndReset := "FLDENV (BX)\nFINIT\nRET\n"
		branch := fmt.Sprintf("MOVL gate+%d(FP),AX\nTESTL AX,AX\nJE joined\n", word)
		for _, row := range []struct {
			name, declaration, body string
			good                    bool
			apis                    []string
		}{
			// FINIT discards both loaded words and restores a known empty
			// shape. The complete native read must still occur on both IR axes.
			{"actual-pointer-dead-read", "func Value(env *byte)", pointer + readAndReset, true, []string{"text", "module", "Go"}},
			{"unknown-base-dead-read", "func Value(env *byte)", readAndReset, false, []string{"text", "module", "Go"}},
			{"NUM-is-not-native-address", "func Value(env *byte)", move + " $32,BX\n" + readAndReset, false, []string{"text"}},
			{"partial-base", "func Value(env *byte)", "MOVW $32,BX\n" + readAndReset, false, []string{"module"}},
			{"revoked-pointer", "func Value(env *byte)", pointer + "MOVB $0,BL\n" + readAndReset, false, []string{"Go"}},
			{"pointer-NUM-join", "func Value(env *byte,gate uint32)", pointer + branch + move + " $32,BX\njoined:\n" + readAndReset, false, []string{"module"}},
			{"two-actual-pointers-join", "func Value(env,other *byte,gate uint32)", pointer + fmt.Sprintf("MOVL gate+%d(FP),AX\nTESTL AX,AX\nJE joined\n", 2*word) +
				fmt.Sprintf("%s other+%d(FP),BX\njoined:\n", move, word) + readAndReset, true, []string{"text"}},
			{"missing-final-reset", "func Value(env *byte)", pointer + "FLDENV (BX)\nRET\n", false, []string{"Go"}},
		} {
			source := x86X87ENVVoidSource(t, arch, row.declaration, row.body)
			for _, api := range row.apis {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, row.declaration, arch, triple, api, X87Software)
					if !row.good {
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("Void source/input obligation bypassed: output=%t error=%v\n%s", ir != "", err, source)
						}
						t.Logf("FIRST_CONTEXT %s (later guard not inferred): %v", row.name, err)
						return
					}
					if err != nil || ir == "" {
						t.Fatalf("actual pointer source rejected before its dead-read observation: %v\n%s", err, source)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						if err := x86X87ENVReadFootprintOf(input, 0, "Value"); err != nil {
							t.Fatalf("Void ENV dead read O2=%t: %v", optimized, err)
						}
					}
				})
			}
		}
	}
}
