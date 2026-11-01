package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarRMWPartialByteDependenciesCompleteFamily(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, width := range []struct {
			suffix string
			bytes  int
		}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
			if arch == "386" && width.bytes == 8 {
				continue
			}
			for _, stem := range strings.Fields("ADD ADC SUB SBB INC DEC NEG NOT AND OR XOR") {
				unary := stem == "INC" || stem == "DEC" || stem == "NEG" || stem == "NOT"
				for _, input := range []string{"destination", "source"} {
					if unary && input == "source" {
						continue
					}
					for missing := 0; missing < width.bytes; missing++ {
						for _, carry := range []bool{false, true} {
							name := fmt.Sprintf("%s/%s%s/%s/%d/CF=%t", arch, stem, width.suffix, input, missing, carry)
							t.Run(name, func(t *testing.T) {
								body := stem + width.suffix + " BX,DX"
								if unary {
									body = stem + width.suffix + " DX"
								}
								state := x86ResultState{flags: x86ByteFlagsAll}
								if !carry {
									state.flags &^= x86ByteFlagCF
								}
								state.gp[2], state.gp[3] = 0xff, 0xff
								register := 2
								if input == "source" {
									register = 3
								}
								state.gp[register] &^= 1 << uint(missing)
								before := state.gp
								mask := uint8((uint16(1) << uint(width.bytes)) - 1)
								known := mask & before[2]
								if !unary {
									known &= before[3]
								}
								if stem != "AND" && stem != "OR" && stem != "XOR" && stem != "NOT" {
									// Carry/borrow can propagate only upward from a
									// missing byte. Lower output bytes stay defined.
									prefix := uint8(0)
									for b := 0; b < width.bytes && known&(1<<uint(b)) != 0; b++ {
										prefix |= 1 << uint(b)
									}
									known = prefix
								}
								if (stem == "ADC" || stem == "SBB") && !carry {
									known = 0
								}
								want := before[2]&^mask | known
								if width.bytes == 4 {
									want |= 0xf0
								}
								if !x86LoweredPureGPUnknownTransfer(x86PureGPUnknownInstruction(t, body), &state, arch) || state.gp[2] != want {
									t.Fatalf("partial-byte output lost exact data dependence: got=%x want=%x", state.gp[2], want)
								}
							})
						}
					}
				}
			}
		}
	}
}

func x86ScalarPartialAddSource(arch string) string {
	word, suffix := 8, "Q"
	if arch == "386" {
		word, suffix = 4, "L"
	}
	return fmt.Sprintf("TEXT ·PartialAdd(SB),4,$0-%d\nMOVB x+0(FP),AX\nADD%s $7,AX\nMOVB AX,ret+%d(FP)\nRET\n", word+1, suffix, word)
}

func TestX86ScalarPartialAddThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := x86ScalarPartialAddSource(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func PartialAdd(x byte) byte", target.arch, target.triple, api)
				if err != nil {
					t.Fatal("unknown upper scratch bytes hid an independently defined low result", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86ScalarPartialRMWCannotSupplyUpperBytesOrWholeFlags(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix, typ := 8, "Q", "uint64"
		if target.arch == "386" {
			word, suffix, typ = 4, "L", "uint32"
		}
		prefix := "MOVB x+0(FP),AX\nADD" + suffix + " $7,AX\n"
		rows := []struct {
			name, declaration, body string
			args                    int
		}{
			{"upper-result", "func Value(x byte) " + typ,
				prefix + fmt.Sprintf("MOV%s AX,ret+%d(FP)", suffix, word), 2 * word},
			{"wide-native-store", "func Value(p *uint64,x byte) byte",
				fmt.Sprintf("MOV%s p+0(FP),DX\nMOVB x+%d(FP),AX\nADD%s $7,AX\nMOV%s AX,(DX)\nMOVB AX,ret+%d(FP)",
					suffix, word, suffix, suffix, 2*word), 2*word + 1},
		}
		for _, condition := range []string{"EQ", "CS", "OS"} {
			rows = append(rows, struct {
				name, declaration, body string
				args                    int
			}{"unknown-" + condition, "func Value(x byte) byte",
				prefix + fmt.Sprintf("SET%s BL\nMOVB BL,ret+%d(FP)", condition, word), word + 1})
		}
		for _, row := range rows {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\nRET\n", row.args, row.body)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("known low bytes supplied unknown upper data or native-width FLAGS", err)
					}
				})
			}
		}
	}
}

func TestX86ScalarPartialAddPortableAllByteValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t PartialAddByteOracle(uint32_t);
int main(void) {
    for (unsigned input=0;input<256;++input) {
        unsigned got=PartialAddByteOracle(input);
        if (got!=(uint8_t)(input+7)) {
            fprintf(stderr,"partial add input=%u got=%u\n",input,got);
            return 1;
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"386", "amd64"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, x86ScalarPartialAddSource(arch), "func PartialAdd(x byte) byte", arch, triple, api)
				if err != nil {
					t.Fatal(err)
				}
				// The translator exposes LLVM's i8 ABI, not C's stronger
				// zeroext return convention on targets such as Darwin ARM64.
				// Observe the original low byte through an explicit LLVM
				// trunc/zext adapter; both sides of the C boundary use i32.
				ir += `
define i32 @PartialAddByteOracle(i32 %input) {
    %byte = trunc i32 %input to i8
    %value = call i8 @PartialAdd(i8 %byte)
    %result = zext i8 %value to i32
    ret i32 %result
}
`
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []int{0, 2} {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "partial-add-byte-values", triple, text, driver, nil, level)
					}
				}
			})
		}
	}
}
