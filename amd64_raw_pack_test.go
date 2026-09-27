package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawPackedSaturatingNarrowGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawpackedforms(SB),4,$0-0\n")
			for _, op := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB"} {
				if arch == "amd64" && op != "PACKUSDW" {
					fmt.Fprintf(&source, "%s M1, M2\n%s (AX), M2\n", op, op)
				}
				fmt.Fprintf(&source, "%s X1, X2\n%s (AX), X2\n", op, op)
			}
			if arch == "amd64" {
				for _, op := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
					for _, width := range []string{"X", "Y"} {
						fmt.Fprintf(&source, "%s %s1, %s2, %s3\n", op, width, width, width)
						fmt.Fprintf(&source, "%s 32(AX), %s2, %s3\n", op, width, width)
						fmt.Fprintf(&source, "%s %s20, %s21, K1, %s22\n", op, width, width, width)
					}
					fmt.Fprintf(&source, "%s Z20, Z21, K7, Z22\n", op)
					fmt.Fprintf(&source, "%s.Z (AX), Z21, K7, Z22\n", op)
					if op == "VPACKSSDW" || op == "VPACKUSDW" {
						fmt.Fprintf(&source, "%s.BCST.Z 64(AX), Z21, K7, Z22\n", op)
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for index, got := range decoded.Instrs {
				if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
					t.Fatalf("instruction %d = %s %v, want %s %v", index, got.Op, got.Args, want[index].Op, want[index].Args)
				}
			}
			if len(code) == 0 || code[len(code)-1] != 0xc3 {
				t.Fatal("Go assembler did not end the fixture with RET")
			}
			var raw strings.Builder
			raw.WriteString("TEXT rawpackedforms(SB),4,$0-0\n")
			for _, value := range code[:len(code)-1] {
				fmt.Fprintf(&raw, "BYTE $%#02x\n", value)
			}
			raw.WriteString("RET\n")
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
			if arch == "386" {
				triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			for _, triple := range triples {
				ir, err := Translate(file, Options{
					Goarch:       arch,
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"rawpackedforms": {Name: "rawpackedforms", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-packed-saturating-narrow.ll", "raw-packed-saturating-narrow.o", ir)
			}
		})
	}
}

func TestX86RawPackedSaturatingNarrowRegisterAxes(t *testing.T) {
	for key, spec := range x86RawPackedNarrowOps {
		for _, width := range []string{"X", "Y", "Z"} {
			for _, regs := range [][3]int{{0, 1, 2}, {7, 15, 8}, {16, 20, 31}, {31, 30, 29}} {
				for _, evex := range []bool{false, true} {
					if !evex && (width == "Z" || regs[0] >= 16 || regs[1] >= 16 || regs[2] >= 16) {
						continue
					}
					var code []byte
					if evex {
						vectorBits := byte(strings.Index("XYZ", width))
						code = encodeX86EVEXPackedMultiplyLow(false, vectorBits, 7, true, regs[0], regs[1], regs[2])
						code[1] = code[1]&^0x0f | byte(key[0])
						code[4] = byte(key[1])
					} else {
						code = encodeX86VEXPackedMultiplyLow(width == "Y", regs[0], regs[1], regs[2])
						code[1] = code[1]&^0x1f | byte(key[0])
						code[3] = byte(key[1])
					}
					got, length, matched, err := decodedX86VectorPackedSaturatingNarrowInstruction(code, 64)
					if !matched || err != nil || length != len(code) {
						t.Fatalf("decode %x = %+v length=%d matched=%v err=%v", code, got, length, matched, err)
					}
					wantOp := spec.op
					wantArgs := []string{
						fmt.Sprintf("%s%d", width, regs[2]),
						fmt.Sprintf("%s%d", width, regs[1]),
					}
					if evex {
						wantOp += ".Z"
						wantArgs = append(wantArgs, "K7")
					}
					wantArgs = append(wantArgs, fmt.Sprintf("%s%d", width, regs[0]))
					if got.Op != wantOp || len(got.Args) != len(wantArgs) {
						t.Fatalf("decode %x = %+v, want %s %v", code, got, wantOp, wantArgs)
					}
					for index, arg := range got.Args {
						if arg.String() != wantArgs[index] {
							t.Fatalf("decode %x arg %d = %s, want %s", code, index, arg.String(), wantArgs[index])
						}
					}
				}
			}
		}
	}
}

func TestX86RawPackedSaturatingNarrowRejectsReservedForms(t *testing.T) {
	base := encodeX86EVEXPackedMultiplyLow(false, 2, 1, false, 2, 3, 4)
	base[1] = base[1]&^0x0f | 2
	base[4] = 0x2b
	bytePackBroadcast := append([]byte(nil), base...)
	bytePackBroadcast[1] = bytePackBroadcast[1]&^0x0f | 1
	bytePackBroadcast[3] |= 0x10
	bytePackBroadcast[4] = 0x63
	for _, test := range []struct {
		name string
		code []byte
	}{
		{name: "missing ModRM", code: base[:5]},
		{name: "address override", code: append([]byte{0x67}, base...)},
		{name: "wrong pp", code: replaceX86Byte(base, 2, base[2]&^3)},
		{name: "wrong W", code: replaceX86Byte(base, 2, base[2]|0x80)},
		{name: "missing fixed bit", code: replaceX86Byte(base, 2, base[2]&^4)},
		{name: "reserved vector length", code: replaceX86Byte(base, 3, base[3]&^0x60|0x60)},
		{name: "zero without mask", code: replaceX86Byte(base, 3, base[3]&^7|0x80)},
		{name: "broadcast register", code: replaceX86Byte(base, 3, base[3]|0x10)},
		{name: "byte pack broadcast", code: bytePackBroadcast},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, matched, err := decodedX86VectorPackedSaturatingNarrowInstruction(test.code, 64); !matched || err == nil {
				t.Fatalf("invalid %x matched=%v error=%v", test.code, matched, err)
			}
		})
	}
}

func replaceX86Byte(source []byte, index int, value byte) []byte {
	copyOfSource := append([]byte(nil), source...)
	copyOfSource[index] = value
	return copyOfSource
}
