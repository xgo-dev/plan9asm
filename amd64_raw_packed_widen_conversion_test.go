package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86RawPackedWidenConversionOps = []Op{
	"VCVTPS2QQ", "VCVTPS2UQQ", "VCVTTPS2QQ", "VCVTTPS2UQQ",
	"VCVTPD2QQ", "VCVTPD2UQQ", "VCVTTPD2QQ", "VCVTTPD2UQQ",
}

func x86RawPackedWidenConversionGoForms() string {
	var source strings.Builder
	source.WriteString("TEXT rawPackedWidenConversion(SB),4,$0-0\n")
	for _, op := range x86RawPackedWidenConversionOps {
		registers := []struct{ source, destination string }{
			{"X0", "X1"}, {"X0", "Y1"}, {"Y0", "Z1"},
		}
		if strings.Contains(string(op), "PD2") {
			registers = []struct{ source, destination string }{
				{"X0", "X1"}, {"Y0", "Y1"}, {"Z0", "Z1"},
			}
		}
		for _, registers := range registers {
			fmt.Fprintf(&source, "\t%s %s, %s\n", op, registers.source, registers.destination)
			fmt.Fprintf(&source, "\t%s 0(AX), %s\n", op, registers.destination)
			fmt.Fprintf(&source, "\t%s %s, K1, %s\n", op, registers.source, registers.destination)
			fmt.Fprintf(&source, "\t%s.Z 0(AX), K1, %s\n", op, registers.destination)
			fmt.Fprintf(&source, "\t%s.BCST 0(AX), %s\n", op, registers.destination)
		}
		roundingSource := "Y0"
		if strings.Contains(string(op), "PD2") {
			roundingSource = "Z0"
		}
		if strings.HasPrefix(string(op), "VCVTT") {
			fmt.Fprintf(&source, "\t%s.SAE %s, Z1\n", op, roundingSource)
		} else {
			fmt.Fprintf(&source, "\t%s.RN_SAE %s, Z1\n", op, roundingSource)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestDecodeX86RawPackedWidenConversionCompleteGoForms(t *testing.T) {
	source := x86RawPackedWidenConversionGoForms()
	code := assembleX87ControlBytes(t, "amd64", source)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
	}
	for index, got := range decoded.Instrs {
		if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
			t.Fatalf("instruction %d=%+v, want %+v", index, got, want[index])
		}
	}
}

func TestDecodeX86RawPackedWidenConversionSourceLocalRIPData(t *testing.T) {
	for _, double := range []bool{false, true} {
		ops := x86RawPackedWidenConversionByOpcode
		if double {
			ops = x86RawPackedDoubleConversionByOpcode
		}
		for opcode, op := range ops {
			for vectorLength := 0; vectorLength < 3; vectorLength++ {
				for _, broadcast := range []bool{false, true} {
					p2 := byte(0x08 | vectorLength<<5)
					width := 8 << vectorLength
					p1 := byte(0x7d)
					if double {
						p1 |= 0x80
						width *= 2
					}
					if broadcast {
						p2 |= 0x10
						width = 4
						if double {
							width = 8
						}
					}
					code := []byte{0x62, 0xf1, p1, p2, byte(opcode), 0x05, 1, 0, 0, 0, 0xc3}
					for value := 0; value < width; value++ {
						code = append(code, byte(value))
					}
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "packed widening conversion RIP", map[string]bool{})
					if err != nil {
						t.Fatalf("%s width %d broadcast=%t: %v", op, width, broadcast, err)
					}
					if len(decoded) != 2 || len(decoded[0].x86RIPLiteralData) != width ||
						decoded[0].Args[0].Kind != OpSym {
						t.Fatalf("%s width %d broadcast=%t: %#v", op, width, broadcast, decoded)
					}
				}
			}
		}
	}
}

func TestTranslateX86RawPackedWidenConversionLLVM22Objects(t *testing.T) {
	source := x86RawPackedWidenConversionGoForms()
	code := assembleX87ControlBytes(t, "amd64", source)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	file.Funcs[0].Instrs = append(file.Funcs[0].Instrs[:1], rawX86Function(code).Instrs...)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawPackedWidenConversion": {Name: "rawPackedWidenConversion", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-packed-widen.ll", "raw-packed-widen.o", ir)
		})
	}
}
