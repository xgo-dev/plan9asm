package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86CRC32ResultCase struct {
	op    string
	width int
}

func x86CRC32ResultCases(arch string) []x86CRC32ResultCase {
	rows := []x86CRC32ResultCase{{"CRC32B", 1}, {"CRC32W", 2}, {"CRC32L", 4}}
	if arch == "amd64" {
		rows = append(rows, x86CRC32ResultCase{"CRC32Q", 8})
	}
	return rows
}

func TestX86CRC32WholeResultNUMThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86CRC32ResultCases(target.arch) {
			for _, scenario := range []string{"known", "unknown-accumulator", "unknown-source", "missing-result", "unused-bool", "unused-address"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.op+"/"+scenario+"/"+api, func(t *testing.T) {
						result, params, body := 0, "", ""
						if scenario == "unused-bool" {
							result, params = goWordSize(target.arch), "flag bool"
						}
						if scenario != "unknown-accumulator" && scenario != "unused-bool" && scenario != "unused-address" {
							body += "MOVL $0x76543210,AX\n"
						}
						if scenario != "unknown-source" {
							body += "MOVL $0x12345678,BX\n"
						}
						if scenario == "unused-address" {
							lea := "LEAQ"
							if target.arch == "386" {
								lea = "LEAL"
							}
							body += lea + " ret+0(FP),SI\n"
						}
						body += row.op + " BX,AX\n"
						if scenario != "missing-result" {
							body += fmt.Sprintf("MOVL AX,ret+%d(FP)\n", result)
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", result+4, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value("+params+") uint32", target.arch, target.triple, api)
						if scenario != "known" {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("CRC source/result obligation bypassed: output=%t error=%v", ir != "", err)
							}
						} else if err != nil || ir == "" {
							t.Fatal("complete initialized CRC result rejected", err)
						}
					})
				}
			}
		}
	}
}

func TestX86CRC32PairedNativeReadVolatile(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, row := range x86CRC32ResultCases(target.arch) {
			for _, dead := range []bool{false, true} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/dead=%t/%s", target.triple, row.op, dead, api), func(t *testing.T) {
						body := fmt.Sprintf("MOVL crc+0(FP),AX\n%s p+%d(FP),SI\n%s (SI),AX\n", move, word, row.op)
						if dead {
							body += "MOVL $7,AX\n"
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOVL AX,ret+%d(FP)\nRET\n", 2*word+4, body, 2*word)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(crc uint32,p *byte) uint32", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("paired native read rejected", err)
						}
						for _, candidate := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							if !strings.Contains(candidate, fmt.Sprintf("load volatile i%d,", row.width*8)) {
								t.Fatal("exact CRC native read disappeared or became nonvolatile")
							}
						}
					})
				}
			}
		}
	}
}

func TestX86CRC32FPExactSourceBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86CRC32ResultCases(target.arch) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.op+"/"+api, func(t *testing.T) {
					// All bytes have actual independent typed result fields. The
					// CRC source starts inside field zero and may cross fields.
					source := "TEXT ·Value(SB),4,$0-20\nMOVL $0x04030201,ret+0(FP)\nMOVL $0x08070605,ret+4(FP)\nMOVL $0x0c0b0a09,ret+8(FP)\nMOVL $0,AX\n" + row.op + " ret+1(FP),AX\nMOVL AX,ret+12(FP)\nMOVL $0,ret+16(FP)\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() (uint32,uint32,uint32,uint32,uint32)", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete typed interior CRC read rejected", err)
					}
					optimized := x86MulDivRoundOptimize(t, ir)
					value := uint64(0x0908070605040302)
					if row.width < 8 {
						value &= uint64(1)<<uint(row.width*8) - 1
					}
					// This inspects the independent source-byte transport, not
					// a claim that LLVM constant-folded or executed CRC itself.
					if !strings.Contains(optimized, fmt.Sprintf("i%d %d)", row.width*8, value)) {
						t.Fatalf("CRC lost exact interior source bytes, want %#x:\n%s", value, optimized)
					}
				})
			}
		}
	}
}
