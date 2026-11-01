package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86CRC32CompleteOriginalGoRegisterBanks(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var bank strings.Builder
		bank.WriteString("TEXT bank(SB),4,$0-32\n")
		gp := strings.Fields("AX CX DX BX SP BP SI DI")
		if arch == "amd64" {
			gp = append(gp, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15")...)
		}
		for _, row := range x86CRC32ResultCases(arch) {
			sources := append([]string(nil), gp...)
			if row.width == 1 {
				sources = append(sources, strings.Fields("AL AH BL BH CL CH DL DH")...)
				if arch == "amd64" {
					sources = append(sources, strings.Fields("BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B")...)
				}
			}
			for _, source := range sources {
				if arch == "386" && row.width == 1 && source == "SP" {
					continue // The actual Go bad-byte fallback has no direct SP row.
				}
				fmt.Fprintf(&bank, "%s %s,AX\n", row.op, source)
			}
			for _, destination := range gp {
				fmt.Fprintf(&bank, "%s BX,%s\n", row.op, destination)
			}
			for _, source := range []string{"x+0(FP)", "x+1(FP)", "slot-8(SP)", "table(SB)", "-1(DX)(SI*2)"} {
				fmt.Fprintf(&bank, "%s %s,AX\n", row.op, source)
			}
		}
		bank.WriteString("RET\n")
		t.Run(arch+"/complete-bank", func(t *testing.T) {
			goAssemblerOracleOutput(t, arch, bank.String(), "", true)
		})
		for _, instruction := range []string{"CRC32B SPB,AX", "CRC32B X0,AX", "CRC32W AL,AX", "CRC32L AX,AL", "CRC32L AX,(BX)", "CRC32L $1,AX", "CRC32L $x(SB),AX", "CRC32L (BX)(SI*3),AX"} {
			t.Run(arch+"/invalid/"+instruction, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT bad(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
			})
		}
		if arch == "386" {
			for _, instruction := range []string{"CRC32Q BX,AX", "CRC32B SP,AX", "CRC32B R8B,AX", "CRC32L BX,R8"} {
				t.Run(arch+"/invalid/"+instruction, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT bad(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
				})
			}
		}
	}
}

func x86CRC32TypedFixture(arch string, row x86CRC32ResultCase, kind string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	declaration, body, frame, args := "func Value() uint32", "", 0, 4
	switch kind {
	case "register":
		body = "MOVL $0x76543210,AX\nMOVL $0x12345678,BX\n" + row.op + " BX,AX\nMOVL AX,ret+0(FP)\n"
	case "FP":
		declaration, args = "func Value() (uint32,uint32,uint32,uint32,uint32)", 20
		body = "MOVL $0x04030201,ret+0(FP)\nMOVL $0x08070605,ret+4(FP)\nMOVL $0x0c0b0a09,ret+8(FP)\nMOVL $0,AX\n" + row.op + " ret+1(FP),AX\nMOVL AX,ret+12(FP)\nMOVL $0,ret+16(FP)\n"
	case "AUTO":
		frame = 8
		body = "MOVL $0x04030201,slot-8(SP)\nMOVL $0x08070605,slot-4(SP)\nMOVL $0,AX\n" + row.op + " slot-8(SP),AX\nMOVL AX,ret+0(FP)\n"
	case "native", "dead-native":
		declaration, args = "func Value(crc uint32,p *byte) uint32", 2*word+4
		body = fmt.Sprintf("MOVL crc+0(FP),AX\n%s p+%d(FP),SI\n%s (SI),AX\n", move, word, row.op)
		if kind == "dead-native" {
			body += "MOVL $7,AX\n"
		}
		body += fmt.Sprintf("MOVL AX,ret+%d(FP)\n", 2*word)
	default:
		panic("unknown complete CRC fixture role")
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$%d-%d\n%sRET\n", frame, args, body), declaration
}

func TestX86CRC32FiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete CRC32 objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86CRC32ResultCases(target.arch) {
				for _, kind := range []string{"register", "FP", "AUTO", "native", "dead-native"} {
					body, declaration := x86CRC32TypedFixture(target.arch, row, kind)
					name := fmt.Sprintf("CRC%d", count)
					source.WriteString(strings.ReplaceAll(body, "Value", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
					count++
				}
			}
			want := 20
			if target.arch == "386" {
				want = 15
			}
			if count != want || strings.Count(source.String(), "TEXT ·") != want {
				t.Fatal("complete CRC NUM/storage inventory changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != want {
						t.Fatal("complete CRC source did not retain every function", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}
