package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarLaneCallerCompleteBoundedRegions(t *testing.T) {
	for _, size := range []struct{ suffix, typ string }{{"B", "uint8"}, {"W", "uint16"}, {"D", "uint32"}, {"Q", "uint64"}} {
		for _, prefix := range []string{"", "V"} {
			for _, memory := range []bool{false, true} {
				name := prefix + size.suffix + fmt.Sprint(memory)
				t.Run(name, func(t *testing.T) {
					source := strings.ReplaceAll(x86CallerFixtureSource, "float32", size.typ)
					row := prefix + "PINSR" + size.suffix + " $0,AX,X0"
					if memory {
						row = strings.Replace(row, "AX", "(DI)", 1)
					}
					out := "X0"
					if prefix != "" {
						row += ",X1"
						out = "X1"
					}
					body := row + "\n" + prefix + "PEXTR" + size.suffix + " $0," + out + ",(DX)"
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
					goAssemblerOracleOutput(t, "amd64", assembly, "", true)
					pkg, _ := x86CallerCoreFixture(t, source, assembly)
					for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
						if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarLaneCallerRetainsUnknownAndPointerBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown-lane", "PINSRD $1,AX,X0\nPEXTRD $0,X0,(DX)"},
		{"unknown-GP", "PINSRD $0,BX,X0\nPEXTRD $0,X0,(DX)"},
		{"pointer-source", "PINSRD $0,DI,X0\nPEXTRD $0,X0,(DX)"},
		{"private-SP-source", "PINSRD $0,SP,X0\nPEXTRD $0,X0,(DX)"},
		{"input-write", "PINSRD $0,AX,X0\nPEXTRD $0,X0,(DI)"},
		{"out-of-result", "PINSRQ $0,AX,X0\nPEXTRQ $0,X0,(DX)"},
		{"local-length-crosses-bound", "PINSRQ $0,1(CX),X0\nPEXTRD $0,X0,(DX)"},
		{"unknown-address", "PINSRD $0,(BX),X0\nPEXTRD $0,X0,(DX)"},
		{"unknown-call", "PINSRD $0,AX,X0\nCALL unknown(SB)\nPEXTRD $0,X0,(DX)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", tc.body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed lane/caller role acquired continuation: %v", err)
			}
		})
	}
}
