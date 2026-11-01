package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarLaneExtractAllDeclaredWidthsThreeAPIObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, prefix := range []string{"", "V"} {
			for _, size := range []struct {
				suffix, typ string
				width       int
			}{{"B", "uint8", 1}, {"W", "uint16", 2}, {"D", "uint32", 4}, {"Q", "uint64", 8}} {
				if target.arch == "386" && prefix == "" && size.suffix == "Q" {
					continue
				} // Go absent legacy Q; explicit rejection root remains.
				op := prefix + "PEXTR" + size.suffix
				t.Run(target.triple+"/"+op, func(t *testing.T) {
					width, typ := size.width, size.typ
					if target.arch == "386" && op == "VPEXTRQ" {
						width, typ = 4, "uint32" // Actual non-64-bit WIG effect.
					}
					source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVQ h+8(FP),X0\n%s $255,X0,ret+16(FP)\nRET\n", 16+width, op)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k,h uint64) "+typ+"\n", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatalf("%s independent typed result bytes: %v", api, err)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "extract.ll", "extract.o", ir)
					}
				})
			}
		}
	}
}

func TestX86ScalarLaneNativeWidthsVolatileFiveTargets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ", "PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ"} {
			insert := strings.Contains(op, "INSR")
			if target.arch == "386" && (op == "PINSRQ" || op == "PEXTRQ" || insert && op[0] == 'V') {
				continue
			}
			bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
			if target.arch == "386" && op == "VPEXTRQ" {
				bits = 32
			}
			for _, mem := range []string{"3(AX)", "8(AX)(BX*2)", "0(FS)", "0(GS)"} {
				t.Run(target.triple+"/"+op+"/"+mem, func(t *testing.T) {
					row := op + " $255," + mem + ",X0"
					if !insert {
						row = op + " $255,X0," + mem
					} else if op[0] == 'V' {
						row += ",X1"
					}
					source := "TEXT ·view(SB),4,$0-0\n" + row + "\nRET\n"
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					if !insert {
						// Keep every original native/segment spelling and width.
						// Unknown source bytes/addresses are Context, not a public
						// initialized store; the independent matrix owns that axis.
						ir := x86UnboundVoidScalarFormatObject(t, source, "view", target.arch, target.triple)
						if !strings.Contains(ir, fmt.Sprintf("store volatile i%d", bits)) {
							t.Fatal("original extraction format lost its exact native write")
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "native-width.ll", "native-width.o", ir)
						return
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", target.arch, target.triple, api)
						if err != nil {
							t.Fatalf("%s native memory grammar: %v", api, err)
						}
						effect := "load volatile"
						if !insert {
							effect = "store volatile"
						}
						if !strings.Contains(ir, fmt.Sprintf("%s i%d", effect, bits)) {
							t.Fatal("lost original physical width/dead side effect", api, op)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "native-width.ll", "native-width.o", ir)
					}
				})
			}
		}
	}
}

func TestX86ScalarLaneMode32HighBanksAndNamedQKeepContext(t *testing.T) {
	for _, op := range []string{"VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ"} {
		for _, index := range []int{8, 15, 16, 31} {
			source := fmt.Sprintf("TEXT ·view(SB),4,$0-0\n%s $1,X%d,AX\nRET\n", op, index)
			goAssemblerOracleOutput(t, "386", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", "386", "i386-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("named Go bytes granted impossible physical mode32 bank: %s %v", api, err)
				}
			}
		}
	}
}

func TestX86ScalarLaneFPDoesNotGrantPointerPaddingOrPartialResults(t *testing.T) {
	for _, tc := range []struct{ decl, body string }{
		{"func view(k *byte) uint32\n", "PINSRB $0,k+0(FP),X0\nMOVL X0,ret+8(FP)\n"},
		{"func view(a byte,b uint32) uint32\n", "PINSRW $0,hole+1(FP),X0\nMOVL X0,ret+8(FP)\n"},
		{"func view(k uint64) uint64\n", "MOVQ k+0(FP),X0\nPEXTRB $0,X0,ret+8(FP)\n"},
		{"func view(k uint32) uint32\n", "PINSRD $1,k+0(FP),X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+8(FP)\n"},
		{"func view(k uint32) uint32\n", "PINSRD $0,BX,X0\nMOVL k+0(FP),AX\nMOVL AX,ret+8(FP)\n"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-24\n"+tc.body+"RET\n", tc.decl, "amd64", "x86_64-unknown-linux-gnu", api)
			if err == nil || ir != "" {
				t.Fatalf("unproved FP/mixed/unused input acquired initialization: %s %v", api, err)
			}
		}
	}
}
