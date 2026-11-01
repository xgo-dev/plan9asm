package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ByteShuffleNativeResultRows(arch string) []string {
	rows := []string{"PSHUFB (DX),X0"}
	for _, bank := range []string{"X", "Y", "Z"} {
		rows = append(rows, "VPSHUFB (DX),"+bank+"0,"+bank+"1")
		if arch == "amd64" {
			rows = append(rows, "VPSHUFB (DX),"+bank+"0,K1,"+bank+"1",
				"VPSHUFB.Z (DX),"+bank+"0,K1,"+bank+"1")
		}
	}
	return rows
}

func TestX86ByteShuffleNativeResultsCompleteFamilyFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			var source, declarations strings.Builder
			for index, row := range x86ByteShuffleNativeResultRows(target.arch) {
				name, output := fmt.Sprint("ShuffleNative", index), "X1"
				if strings.HasPrefix(row, "PSHUFB ") {
					output = "X0"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DX\n"+
					"VPXORQ Z0,Z0,Z0\nVPXORQ Z1,Z1,Z1\nMOVL $1,AX\nKMOVW AX,K1\n%s\n"+
					"PEXTRD $0,%s,AX\nMOVL AX,ret+%d(FP)\nRET\n", name, word+4, move, row, output, word)
				fmt.Fprintf(&declarations, "func %s(p *[64]byte) uint32\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete initialized family lost its paired native read", api, err)
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

func TestX86ByteShuffleNativeContinuationCannotCreateAddressOrMaskFacts(t *testing.T) {
	for _, row := range x86ByteShuffleNativeResultRows("amd64") {
		for _, mutation := range []string{"unknown-base", "pointer-index", "missing-mask", "numerical-address"} {
			if mutation == "missing-mask" && !strings.Contains(row, "K1") {
				continue
			}
			t.Run(row+"/"+mutation, func(t *testing.T) {
				setup := "MOVQ p+0(FP),DX\nVPXORQ Z0,Z0,Z0\nVPXORQ Z1,Z1,Z1\nMOVL $1,AX\nKMOVW AX,K1\n"
				instruction := row
				switch mutation {
				case "unknown-base":
					setup = strings.Replace(setup, "MOVQ p+0(FP),DX\n", "", 1)
				case "pointer-index":
					instruction = strings.Replace(row, "(DX)", "(DX)(DX*1)", 1)
				case "missing-mask":
					setup = strings.Replace(setup, "KMOVW AX,K1\n", "", 1)
				case "numerical-address":
					setup += "MOVL $1,DX\n"
				}
				output := "X1"
				if strings.HasPrefix(row, "PSHUFB ") {
					output = "X0"
				}
				source := "TEXT ·Shuffle(SB),4,$0-12\n" + setup + instruction + "\nPEXTRD $0," + output + ",AX\nMOVL AX,ret+8(FP)\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Shuffle(p *[64]byte) uint32", "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("conditional native read manufactured independent facts", api, err)
					}
				}
			})
		}
	}
}
