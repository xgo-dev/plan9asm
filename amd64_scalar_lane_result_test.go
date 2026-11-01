package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarLanePublicResultUsesSelectedBytesAndMustJoin(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		result := 8
		if arch == "386" {
			result = 4
		}
		for _, tc := range []struct {
			name, body string
			good       bool
		}{
			{"selected", "MOVL k+0(FP),AX\nPINSRD $1,AX,X0\nPEXTRD $1,X0,AX\n", true},
			{"unwritten", "MOVL k+0(FP),AX\nPINSRD $1,AX,X0\nPEXTRD $0,X0,AX\n", false},
			{"unknown-GP-unused-output", "PINSRD $1,BX,X0\nMOVL k+0(FP),AX\n", false},
			{"partial-join", "MOVL k+0(FP),AX\nCMPL AX,$0\nJE missing\nPINSRD $1,AX,X0\nmissing:\nPEXTRD $1,X0,AX\n", false},
			{"unknown-AES", "MOVL k+0(FP),AX\nPINSRD $1,AX,X0\nAESENC X0,X0\nPEXTRD $1,X0,AX\n", false},
		} {
			t.Run(arch+"/"+tc.name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(k uint32) uint32", tc.body+fmt.Sprintf("MOVL AX,ret+%d(FP)\nRET", result))
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); (err == nil) != tc.good {
					t.Fatalf("public byte observer granted whole vector/unused input/unknown effect: %v", err)
				}
			})
		}
	}
}

func TestX86ScalarLaneRawResultCannotReuseStaleGPInitialization(t *testing.T) {
	count := 0
	for _, target := range x86RawReturnTargets {
		for _, prefix := range []string{"", "V"} {
			for _, kind := range []struct{ suffix, typ, move string }{
				{"B", "uint8", "MOVB"}, {"W", "uint16", "MOVW"}, {"D", "uint32", "MOVL"}, {"Q", "uint64", "MOVQ"},
			} {
				// These are explicitly the already-admitted physical forms.
				// Mode32 four-operand/Q inserts retain their existing boundary.
				if target.arch == "386" && (prefix == "V" || kind.suffix == "Q") {
					continue
				}
				count++
				t.Run(target.triple+"/"+prefix+kind.suffix, func(t *testing.T) {
					load, argument := "MOVL", "uint32"
					bits := map[string]int{"B": 8, "W": 16, "D": 32, "Q": 64}[kind.suffix]
					if bits == 64 {
						load, argument = "MOVQ", "uint64"
					}
					lane, result := 128/bits-1, 8
					if target.arch == "386" {
						result = 4
					}
					for _, good := range []bool{true, false} {
						selected := lane
						if !good {
							selected = 0
						}
						rows := fmt.Sprintf("%sPINSR%s $%d,AX,X0", prefix, kind.suffix, lane)
						if prefix != "" {
							rows += ",X0"
						}
						rows += fmt.Sprintf("\n%sPEXTR%s $%d,X0,AX\n", prefix, kind.suffix, selected)
						code := assembleX87ControlBytes(t, target.arch, "TEXT f(SB),4,$0-0\n"+rows+"RET\n")
						if len(code) < 2 || code[len(code)-1] != 0xc3 {
							t.Fatalf("actual original Go scalar pair lacks exact terminal RET: %x", code)
						}
						var raw strings.Builder
						for _, value := range code[:len(code)-1] {
							fmt.Fprintf(&raw, "BYTE $%#02x\n", value)
						}
						decl := fmt.Sprintf("func view(k %s) %s\n", argument, kind.typ)
						source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s k+0(FP),AX\n%s%s AX,ret+%d(FP)\nRET\n", result+bits/8, load, raw.String(), kind.move, result)
						goAssemblerOracleOutput(t, target.arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, decl, target.arch, target.triple, api)
							if (err == nil) != good || !good && ir != "" {
								t.Fatalf("%s original raw pair used stale GP bytes instead of selected source lane: good=%t err=%v", api, good, err)
							}
							if good {
								compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "raw-lane.ll", "raw-lane.o", ir)
							}
						}
					}
				})
			}
		}
	}
	if count != 30 {
		t.Fatalf("physical source-result matrix changed: %d / 30", count)
	}
}
