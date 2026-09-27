package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawPackedTestMask(polarity, widthGroup, w, vectorBits, first, second, destination, writeMask int, memory, broadcast bool) []byte {
	if memory {
		first = 0
	}
	p0 := byte(1<<7 | (1-first/16)<<6 | (1-first/8&1)<<5 | 1<<4 | 2)
	p1 := byte(4 | (polarity + 1) | (^second&15)<<3)
	if w != 0 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | (1-second/16)<<3 | writeMask)
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | destination<<3 | first&7)
	if memory {
		modRM = byte(0x40 | destination<<3)
	}
	code := []byte{0x62, p0, p1, p2, byte(0x26 + widthGroup), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestTranslateRawPackedTestMaskGorseRegression(t *testing.T) {
	const source = `TEXT rawPackedTestMask(SB), $0-0
	LONG $0x4875f262
	WORD $0xc026
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawPackedTestMask": {Name: "rawPackedTestMask", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "icmp ne") {
		t.Fatalf("raw VPTESTMB omitted per-lane mask test:\n%s", ir)
	}
}

func TestDecodedX86RawPackedTestMaskCompleteGoRows(t *testing.T) {
	if len(amd64PackedTestMaskSpecs) != 8 {
		t.Fatalf("Go 1.27 packed test-mask family has %d members, want eight", len(amd64PackedTestMaskSpecs))
	}
	seen := make(map[Op]bool)
	for polarity, groups := range x86RawPackedTestMaskOps {
		for widthGroup, widths := range groups {
			for w, op := range widths {
				spec, ok := amd64PackedTestMaskSpecs[string(op)]
				if !ok || seen[op] || spec.testZero != (polarity != 0) ||
					spec.laneBits != (8<<(widthGroup*2+w)) {
					t.Fatalf("packed test-mask row %d/%d/%d = %s, spec %+v", polarity, widthGroup, w, op, spec)
				}
				seen[op] = true
				for vectorBits, prefix := range [...]string{"X", "Y", "Z"} {
					for _, memory := range []bool{false, true} {
						for _, writeMask := range []int{0, 3} {
							for _, broadcast := range []bool{false, true} {
								if broadcast && (!memory || widthGroup == 0) {
									continue
								}
								code := encodeX86RawPackedTestMask(polarity, widthGroup, w, vectorBits, 20, 21, 2, writeMask, memory, broadcast)
								got, length, recognized, err := decodedX86RawPackedTestMaskInstruction(code, 64)
								if err != nil || !recognized || length != len(code) {
									t.Fatalf("decode %x = %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
								}
								wantOp := op
								if broadcast {
									wantOp += ".BCST"
								}
								if got.Op != wantOp || got.Args[1].String() != fmt.Sprintf("%s21", prefix) ||
									got.Args[len(got.Args)-1].String() != "K2" {
									t.Fatalf("decode %x = %+v, want %s %s21, K2", code, got, wantOp, prefix)
								}
								if writeMask != 0 && (len(got.Args) != 4 || got.Args[2].String() != "K3") ||
									writeMask == 0 && len(got.Args) != 3 {
									t.Fatalf("decode %x = %+v, lost write mask", code, got)
								}
								first := got.Args[0]
								if memory {
									wantBytes := 16 << vectorBits
									if broadcast {
										wantBytes = spec.laneBits / 8
									}
									if first.Kind != OpMem || first.Mem.Base != AX || first.Mem.Off != int64(wantBytes) {
										t.Fatalf("decode %x = %+v, want compressed displacement %d", code, got, wantBytes)
									}
								} else if first.String() != fmt.Sprintf("%s20", prefix) {
									t.Fatalf("decode %x = %+v, want %s20", code, got, prefix)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(seen) != len(amd64PackedTestMaskSpecs) {
		t.Fatalf("decoded %d distinct packed test-mask ops, want %d", len(seen), len(amd64PackedTestMaskSpecs))
	}
}

func TestDecodedX86RawPackedTestMaskRejectsReservedBits(t *testing.T) {
	base := encodeX86RawPackedTestMask(0, 0, 0, 2, 1, 2, 3, 0, false, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"fixed bit", []byte{base[0], base[1], base[2] &^ 4, base[3], base[4], base[5]}},
		{"K register extension", []byte{base[0], base[1] &^ 0x80, base[2], base[3], base[4], base[5]}},
		{"reserved length", []byte{base[0], base[1], base[2], base[3] | 0x20, base[4], base[5]}},
		{"zeroing", []byte{base[0], base[1], base[2], base[3] | 0x80, base[4], base[5]}},
		{"register broadcast", []byte{base[0], base[1], base[2], base[3] | 0x10, base[4], base[5]}},
		{"missing ModRM", base[:5]},
		{"address override", append([]byte{0x67}, base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawPackedTestMaskInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted invalid encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
	byteBroadcast := encodeX86RawPackedTestMask(0, 0, 0, 2, 0, 1, 2, 0, true, true)
	if _, _, recognized, err := decodedX86RawPackedTestMaskInstruction(byteBroadcast, 64); !recognized || err == nil {
		t.Fatalf("accepted byte broadcast %x", byteBroadcast)
	}
}

func TestTranslateRawPackedTestMaskLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawPackedTestMaskFamily(SB), $0-0\n")
			for polarity, groups := range x86RawPackedTestMaskOps {
				for widthGroup, widths := range groups {
					for w := range widths {
						for vectorBits := 0; vectorBits < 3; vectorBits++ {
							for _, code := range [][]byte{
								encodeX86RawPackedTestMask(polarity, widthGroup, w, vectorBits, 1, 2, 3, 0, false, false),
								encodeX86RawPackedTestMask(polarity, widthGroup, w, vectorBits, 0, 2, 3, 4, true, widthGroup != 0),
							} {
								for _, value := range code {
									fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
								}
							}
						}
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawPackedTestMaskFamily": {Name: "rawPackedTestMaskFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-packed-test-mask.ll", "raw-packed-test-mask.o", ir)
		})
	}
}
