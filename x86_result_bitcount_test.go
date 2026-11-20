package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ABI0ResultBitCountCompleteByteEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move := 8, "uint64", "MOVQ"
		if arch == "386" {
			word, typ, move = 4, "uint32", "MOVL"
		}
		for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			for _, suffix := range []string{"W", "L", "Q"} {
				for _, input := range []string{"AX", "x+0(FP)", "local-16(SP)"} {
					op := family + suffix
					t.Run(arch+"/"+op+"/"+input, func(t *testing.T) {
						body := fmt.Sprintf("%s x+0(FP),AX\n%s $0,BX\n%s AX,local-16(SP)\n%s %s,BX\n%s BX,ret0+%d(FP)\nRET",
							move, move, move, op, input, move, word)
						_, _, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x "+typ+") "+typ, body)
						source = strings.Replace(source, ",$0-", ",$32-", 1)
						rejected := arch == "386" && suffix == "Q"
						goAssemblerOracleOutput(t, arch, source, "", !rejected)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
						if rejected {
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("mode32 acquired Q-width result bytes: %v", err)
							}
						} else if err != nil {
							t.Fatalf("Go-accepted bit count has no numerical byte effect: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ABI0ResultBitCountFlagsAndUnknownBytes(t *testing.T) {
	for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
		t.Run(family+"/opaque-pointer-is-not-numerical", func(t *testing.T) {
			body := "MOVQ x+0(FP),AX\n" + family + "Q AX,BX\nMOVQ BX,ret0+8(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x *byte) uint64", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("opaque pointer became countable numerical bytes: %v", err)
			}
		})
		for _, condition := range []string{"CC", "CS", "EQ", "NE", "HI", "LS", "GE", "LT", "GT", "LE", "MI", "PL", "OC", "OS", "PC", "PS"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				body := "MOVL $3,AX\nCMPL AX,$0\n" + family + "L AX,BX\nSET" + condition + " ret0+0(FP)\nRET"
				_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint8", body)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
				defined := family == "POPCNT" || condition == "CC" || condition == "CS" ||
					condition == "EQ" || condition == "NE" || condition == "HI" || condition == "LS"
				if defined && err != nil || !defined && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("wrong count FLAGS knowledge: defined=%t error=%v", defined, err)
				}
			})
		}
		for name, body := range map[string]string{
			"unknown source":       family + "Q AX,BX",
			"partial source":       "MOVB $1,AX\n" + family + "Q AX,BX",
			"word preserves upper": "MOVL $1,AX\n" + family + "W AX,BX",
			"unbound native read":  "MOVQ $0,AX\n" + family + "Q (AX),BX",
			"unknown AUTO":         "MOVB $1,local-16(SP)\n" + family + "Q local-16(SP),BX",
		} {
			t.Run(family+"/"+name, func(t *testing.T) {
				_, _, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", body+"\nMOVQ BX,ret0+0(FP)\nRET")
				source = strings.Replace(source, ",$0-", ",$32-", 1)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("bit count invented source, memory or upper result bytes: %v", err)
				}
			})
		}
	}
}
