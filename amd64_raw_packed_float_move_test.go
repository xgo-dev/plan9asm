package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawPackedMoveGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT packedmoves(SB),4,$0-0\n")
			for _, op := range []string{"VMOVAPS", "VMOVAPD", "VMOVUPS", "VMOVUPD", "VMOVDQA", "VMOVDQU", "VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
				vexInteger := op == "VMOVDQA" || op == "VMOVDQU"
				widths := []string{"X", "Y", "Z"}
				if vexInteger {
					widths = widths[:2]
				}
				for _, width := range widths {
					regs := []int{1, 7}
					if arch == "amd64" {
						regs = append(regs, 15, 16, 31)
					}
					if vexInteger && arch == "amd64" {
						regs = regs[:3]
					}
					for _, reg := range regs {
						masks := []string{"", "K1, ", "K7, "}
						if vexInteger {
							masks = masks[:1]
						}
						for _, mask := range masks {
							for _, zero := range []bool{false, true} {
								if zero && (mask == "" || vexInteger) {
									continue
								}
								suffix := ""
								if zero {
									suffix = ".Z"
								}
								fmt.Fprintf(&source, "%s%s %s0,%s%s%d\n", op, suffix, width, mask, width, reg)
								memories := []string{"(AX)", "64(BX)(CX*4)", "-4096(SI)"}
								if arch == "amd64" && vexInteger {
									memories = append(memories, "32(R8)(R9*2)")
								}
								for _, memory := range memories {
									fmt.Fprintf(&source, "%s%s %s,%s%s%d\n", op, suffix, memory, mask, width, reg)
									if !zero {
										fmt.Fprintf(&source, "%s %s%d,%s%s\n", op, width, reg, mask, memory)
									}
								}
							}
						}
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
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
			var raw strings.Builder
			sigs := make(map[string]FuncSig)
			mode := 64
			if arch == "386" {
				mode = 32
			}
			// Bound each function's optimizer graph without dropping any
			// encoding: thousands of moves in one function are unnecessarily
			// expensive once overlapping register views are kept coherent.
			for offset, index := 0, 0; offset < len(code)-1; index++ {
				if index%64 == 0 {
					if index != 0 {
						raw.WriteString("RET\n")
					}
					name := fmt.Sprintf("packedmoves%d", index/64)
					fmt.Fprintf(&raw, "TEXT %s(SB),4,$0-0\n", name)
					sigs[name] = FuncSig{Name: name, Ret: Void}
				}
				_, size, matched, err := decodedX86PackedMoveInstruction(code[offset:], mode)
				if !matched {
					_, size, matched, err = decodedX86EVEXPackedIntegerMoveInstruction(code[offset:], mode)
				}
				if !matched || err != nil || size <= 0 {
					t.Fatalf("instruction boundary at %d: matched=%v size=%d err=%v", offset, matched, size, err)
				}
				for _, b := range code[offset : offset+size] {
					fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
				}
				offset += size
			}
			raw.WriteString("RET\n")
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
			if arch == "386" {
				triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			for _, triple := range triples {
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: sigs})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-packed-float-moves.ll", "raw-packed-float-moves.o", ir)
			}
		})
	}
}

func TestX86RawPackedFloatMoveEncodingAxes(t *testing.T) {
	count := 0
	for _, evex := range []bool{false, true} {
		limit, widths := 16, 2
		if evex {
			limit, widths = 32, 3
		}
		for _, spec := range []struct {
			op         Op
			pp, opcode int
		}{{"VMOVAPS", 0, 0x28}, {"VMOVAPD", 1, 0x28}, {"VMOVUPS", 0, 0x10}, {"VMOVUPD", 1, 0x10}} {
			for width := 0; width < widths; width++ {
				for direction := 0; direction < 2; direction++ {
					for src := 0; src < limit; src++ {
						for dst := 0; dst < limit; dst++ {
							mask, zero := 0, false
							if evex {
								mask = (src + dst) & 7
								zero = mask != 0 && dst&1 != 0
							}
							code := encodeRawScalarMove(evex, spec.pp, 0x10+direction, src, 0, dst, mask, zero)
							if evex {
								code[2] |= byte(spec.pp) << 7
								code[3] |= byte(width) << 5
							} else {
								code[2] |= byte(width)<<2 | byte(dst&1)<<7 // VEX.W is ignored.
							}
							code[len(code)-2] = byte(spec.opcode + direction)
							got, size, ok, err := decodedX86PackedMoveInstruction(code, 64)
							op := spec.op
							if zero {
								op += ".Z"
							}
							prefix := []string{"X", "Y", "Z"}[width]
							want := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src))}}
							if mask != 0 {
								want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
							}
							want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, dst))})
							if err != nil || !ok || size != len(code) || got.Op != op || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x=%+v size=%d ok=%v err=%v; want %s %+v", code, got, size, ok, err, op, want)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 28672 {
		t.Fatalf("tested %d encodings, want 28672", count)
	}
}

func TestX86RawPackedFloatMoveRejectsReservedEncodings(t *testing.T) {
	for _, code := range [][]byte{
		{0xc5, 0xf8, 0x10},       // Missing ModRM.
		{0xc5, 0xf8, 0x10, 0x04}, // Missing SIB.
		{0xc5, 0xf8, 0x10, 0x45}, // Missing displacement.
		{0xc5, 0xf0, 0x10, 0xc0}, // Reserved vvvv.
		{0x67, 0xc5, 0xf8, 0x10, 0x00},
		{0x62, 0xf1, 0x78, 0x08, 0x10, 0xc0}, // Fixed bit.
		{0x62, 0xf1, 0xfc, 0x08, 0x10, 0xc0}, // PS W1.
		{0x62, 0xf1, 0x7d, 0x08, 0x10, 0xc0}, // PD W0.
		{0x62, 0xf1, 0x7c, 0x00, 0x10, 0xc0}, // Reserved V'.
		{0x62, 0xf1, 0x7c, 0x68, 0x10, 0xc0}, // Reserved length.
		{0x62, 0xf1, 0x7c, 0x18, 0x10, 0x00}, // Broadcast.
		{0x62, 0xf1, 0x7c, 0x88, 0x10, 0xc0}, // Zero mask K0.
		{0x62, 0xf1, 0x7c, 0x89, 0x11, 0x00}, // Zeroing memory store.
	} {
		if _, _, ok, err := decodedX86PackedMoveInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid %x: matched=%v err=%v", code, ok, err)
		}
	}
}
