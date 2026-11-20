package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86RawVectorLiteralCase struct {
	name string
	code []byte
	mask int
}

func x86RawVectorLiteralSource(row x86RawVectorLiteralCase) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", row.name)
	source.WriteString("MOVL $5,AX\nKMOVD AX,K3\nKMOVD AX,K7\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n")
	for _, value := range row.code {
		fmt.Fprintf(&source, "BYTE $%#02x\n", value)
	}
	return source.String()
}

func x86RawVectorLiteralObjects(t *testing.T, triple string, rows []x86RawVectorLiteralCase) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for start := 0; start < len(rows); start += 64 {
		end := start + 64
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%d", start/64), func(t *testing.T) {
			var source, declarations strings.Builder
			for _, row := range rows[start:end] {
				source.WriteString(x86RawVectorLiteralSource(row))
				fmt.Fprintf(&declarations, "func %s()\n", row.name)
			}
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil {
						t.Fatal("exact vector literal/mask/source bytes lost", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				})
			}
		})
	}
}
