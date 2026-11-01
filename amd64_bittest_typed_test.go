package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86BitTestOracleNames(arch string) []string {
	var names []string
	for _, stem := range []string{"BT", "BTC", "BTR", "BTS"} {
		for _, suffix := range "WLQ" {
			if arch != "386" || suffix != 'Q' {
				names = append(names, stem+string(suffix))
			}
		}
	}
	return names
}

func TestX86BitTestDeadReadSurvivesIROptimization(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, word, triple := "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for _, op := range x86BitTestOracleNames(arch) {
			t.Run(arch+"/"+op, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·dead(SB),4,$0-%d\n%s p+0(FP),AX\n%s $0,(AX)\nRET\n", word, move, op)
				goAssemblerOracleOutput(t, arch, source, "", true)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func dead(p *byte)", arch, triple, "text")
				if err != nil {
					t.Fatal(err)
				}
				optimized := x86MulDivRoundOptimize(t, ir)
				if !strings.Contains(optimized, "load volatile") {
					t.Fatalf("Go's required bit-string read/fault was removed by LLVM IR O2:\n%s", optimized)
				}
				if strings.HasPrefix(op, "BTC") || strings.HasPrefix(op, "BTR") || strings.HasPrefix(op, "BTS") {
					if !strings.Contains(optimized, "store volatile") {
						t.Fatal("native bit-string write is not independently observable")
					}
				}
			})
		}
	}
}

func TestX86BitTest386ImmediateClassification(t *testing.T) {
	for _, op := range x86BitTestOracleNames("386") {
		// Go mode32 classifies its int32 value before selecting Yi8. This
		// witness is legal despite the original source literal exceeding 32 bits.
		source := "TEXT ·value(SB),4,$0-0\n" + op + " $4294967295,AX\nRET\n"
		goAssemblerOracleOutput(t, "386", source, "", true)
		if _, err := x86ScalarFPBitViewAPI(t, source, "func value()", "386", "i386-unknown-linux-gnu", "text"); err != nil {
			t.Errorf("actual Go signed-Yi8 classification %s: %v", op, err)
		}
	}
}

func TestX86BitTestDynamicFPDoesNotBecomeModulo(t *testing.T) {
	for _, op := range x86BitTestOracleNames("amd64") {
		source := "TEXT ·value(SB),4,$0-16\nMOVQ index+8(FP),CX\n" + op + " CX,x+0(FP)\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		_, err := x86ScalarFPBitViewAPI(t, source, "func value(x uint64,index int64)", "amd64", "x86_64-unknown-linux-gnu", "text")
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("dynamic native bit string borrowed fixed FP slot/modulo: %s: %v", op, err)
		}
	}
}
