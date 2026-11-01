package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86COMIWholeFileNativeTargetAndDefinedFlags(t *testing.T) {
	for _, name := range x86COMIOracleNames() {
		for _, api := range []string{"text", "module", "Go"} {
			for _, dead := range []bool{false, true} {
				before := ""
				if dead {
					before = "RET\n"
				}
				for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", "i386-unknown-linux-gnu", "x86_64madeup-unknown-linux-gnu"} {
					source := "TEXT ·view(SB),4,$0-0\n" + before + name + " X0,X1\nRET\n"
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", "amd64", triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("missing native target accepted", name, api, dead, triple, err)
					}
					malformed := strings.Replace(source, "X0,X1", "X0,Y1", 1)
					if _, err := x86ScalarFPBitViewAPI(t, malformed, "func view()\n", "amd64", triple, api); err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native-target context hid malformed/dead source", name, api, dead, triple, err)
					}
				}
			}
			for _, missing := range []int{-1, 0, 1} {
				var setup strings.Builder
				for input := 0; input < 2; input++ {
					if input != missing {
						fmt.Fprintf(&setup, "XORPS X%d,X%d\n", input, input)
					}
				}
				source := "TEXT ·view(SB),4,$0-4\n" + setup.String() + "XORL AX,AX\n" + name + " X0,X1\nSETEQ AL\nMOVL AX,X2\nPEXTRD $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n"
				_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if missing == -1 && err != nil || missing != -1 && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("undefined input acquired public result permission", name, api, missing, err)
				}
			}
		}
	}
}

func TestX86COMIRuntimePartitionCompleteAndOriginalInventory(t *testing.T) {
	remaining := make(map[string]bool)
	for _, row := range x86ScalarCompareAFCases("amd64", true) {
		remaining[row.name] = true
	}
	var counts [3]int
	for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareSSE, x86FloatCompareVEX, x86FloatCompareEVEX} {
		cases := x86ScalarCompareAFRuntimeCases(axis)
		for _, row := range cases {
			if !remaining[row.name] {
				t.Fatal("duplicate runtime kernel", row)
			}
			delete(remaining, row.name)
			counts[axis-1]++
		}
		goAssemblerOracleOutput(t, "amd64", x86ScalarCompareAFAssembly("amd64", cases), "", true)
	}
	if len(remaining) != 0 || counts != [3]int{48, 48, 48} {
		t.Fatal("complete runtime partition changed", remaining, counts)
	}
}
