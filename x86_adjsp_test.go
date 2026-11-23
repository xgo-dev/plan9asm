package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ADJSPCarrySource(name string, amount int) string {
	const form = "TEXT ·%s(SB),516,$0-4\nCLC\nADJSP $%d\nSETCS AL\n" +
		"ADJSP $-%d,SP\nSETCS CL\nMOVBLZX AL,AX\nMOVBLZX CL,CX\n" +
		"SHLL $1,CX\nORL CX,AX\nMOVL AX,ret+0(FP)\nRET\n"
	return fmt.Sprintf(form, name, amount, amount)
}

func TestX86ADJSPOrdinaryCarry(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []struct{ arch, triple, width string }{
		{"amd64", "x86_64-unknown-linux-gnu", "Q"},
		{"386", "i386-unknown-linux-gnu", "L"},
	} {
		for _, row := range []struct {
			amount, want int
			first, last  string
		}{
			{127, 0, "SUB", "ADD"},
			{128, 3, "ADD", "SUB"},
			{129, 0, "SUB", "ADD"},
		} {
			t.Run(fmt.Sprintf("%s/%d", target.arch, row.amount), func(t *testing.T) {
				source := x86ADJSPCarrySource("Value", row.amount)
				listing := x86InsertExtractGoListing(t, target.arch, source)
				imm := row.amount
				if imm == 128 {
					imm = -imm
				}
				for _, mnemonic := range []string{row.first, row.last} {
					want := fmt.Sprintf("%s%s\t$%d, SP", mnemonic, target.width, imm)
					if !strings.Contains(string(listing), want) {
						t.Fatalf("Go listing lacks %q:\n%s", want, listing)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s: %v", api, err)
					}
					optimized := x86MulDivRoundOptimize(t, ir)
					if !strings.Contains(optimized, fmt.Sprintf("ret i32 %d", row.want)) {
						t.Fatalf("%s changed the carry result:\n%s", api, optimized)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, api)
				}
			})
		}

		for _, row := range []struct{ name, body, want string }{
			{"address-dependent-flags", "ADJSP $128\nSETOS AL\nADJSP $-128\nMOVBLZX AL,AX\n", "undefined input"},
			{"physical-stack-read", "ADJSP $128\nMOVL (SP),AX\nADJSP $-128\n", ""},
			{"branch-skips-release", "ADJSP $128\nMOVL $8,AX\nJMP done\nADJSP $-128\ndone:\n", "control edge"},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·Value(SB),516,$0-4\n" + row.body + "MOVL AX,ret+0(FP)\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				_, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) || row.want != "" && !strings.Contains(err.Error(), row.want) {
					t.Fatalf("GOARCH=%s should require the original SP: %v", target.arch, err)
				}
			})
		}
	}
}
