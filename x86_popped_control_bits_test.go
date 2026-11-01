package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86PoppedPartialFlagsCannotInventUnmodeledControls(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			suffix, typ string
			width       int
		}{{"W", "uint16", 2}, {"L", "uint32", 4}, {"Q", "uint64", 8}} {
			if target.arch == "amd64" && row.suffix == "L" || target.arch == "386" && row.suffix == "Q" {
				continue
			}
			for _, producer := range []struct{ name, body string }{
				{"partial-both-bytes", "MOVL $1,DX\nCMPL DX,DX\nBTW $0,DX\n"},
				{"complete-high-byte", "MOVL $3,AX\nMULL AX\nCLD\n"},
			} {
				for _, control := range []struct {
					name string
					bit  uint
				}{{"TF", 8}, {"IF", 9}, {"IOPL", 12}, {"NT", 14}, {"RF", 16}, {"AC", 18}} {
					mask := uint64(1) << control.bit
					// Go's W immediate deliberately truncates high bits to zero.
					// That is a genuine defined zero, not a control-bit observation.
					zeroMask := control.bit >= uint(8*row.width)
					for _, numerical := range []bool{false, true} {
						push := "PUSHF" + row.suffix
						if numerical {
							push = "PUSH" + row.suffix + " $7" // Defined integer data is not ambient FLAGS.
						}
						want := zeroMask || numerical
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,ret+0(FP)\nRET\n", row.width, producer.body, push, row.suffix, row.suffix, mask, row.suffix)
						goAssemblerOracleOutput(t, target.arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(fmt.Sprintf("%s/%s/%s/%s/numerical=%t/%s", target.triple, row.suffix, producer.name, control.name, numerical, api), func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() "+row.typ, target.arch, target.triple, api)
								if want && (err != nil || ir == "") || !want && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
									t.Fatal("partial FLAGS acquired an unmodeled native control input or rejected actual NUM data", want, err)
								}
							})
						}
					}
				}
			}
		}
	}
}
