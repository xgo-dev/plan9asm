package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawSingleSourceNarrow(group, width, vectorBits, source, destination, mask int, zeroing, memory bool) []byte {
	if memory {
		destination = 0
	}
	p0 := byte((1-source/8&1)<<7 | (1-destination/16)<<6 |
		(1-destination/8&1)<<5 | (1-source/16)<<4 | 2)
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (source&7)<<3 | destination&7)
	if memory {
		modRM = byte(0x40 | (source&7)<<3)
	}
	code := []byte{0x62, p0, 0x7e, p2, byte((group+1)<<4 | width), modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestTranslateRawNarrowSingleSourceGorseRegression(t *testing.T) {
	const source = `TEXT rawNarrowSingleSource(SB), $0-0
	LONG $0x487ef262
	WORD $0x2c11
	BYTE $0x07
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawNarrowSingleSource": {Name: "rawNarrowSingleSource", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "icmp") {
		t.Fatalf("raw VPMOVUSDB omitted saturating conversion:\n%s", ir)
	}
}

func TestDecodedX86RawSingleSourceNarrowCompleteGoRows(t *testing.T) {
	if len(amd64SingleSourceNarrowSpecs) != 18 {
		t.Fatalf("Go 1.27 single-source narrowing grammar has %d members, want 18", len(amd64SingleSourceNarrowSpecs))
	}
	inputBits := [...]int{16, 32, 64, 32, 64, 64}
	outputBits := [...]int{8, 8, 8, 16, 16, 32}
	seen := make(map[Op]bool)
	for group, row := range x86RawSingleSourceNarrowOps {
		for width, op := range row {
			spec, ok := amd64SingleSourceNarrowSpecs[string(op)]
			if !ok || seen[op] || spec.inputBits != inputBits[width] || spec.outputBits != outputBits[width] || spec.saturating != (group != 2) {
				t.Fatalf("raw opcode row %d/%d = %s, spec %+v", group, width, op, spec)
			}
			seen[op] = true
			for vectorBits, prefix := range [...]string{"X", "Y", "Z"} {
				outputBytes := (16 << vectorBits) * spec.outputBits / spec.inputBits
				outputPrefix := "X"
				if outputBytes > 16 {
					outputPrefix = "Y"
				}
				for _, memory := range []bool{false, true} {
					for _, masked := range []bool{false, true} {
						mask := 0
						if masked {
							mask = 3
						}
						for _, zeroing := range []bool{false, true} {
							if zeroing && !masked {
								continue
							}
							code := encodeX86RawSingleSourceNarrow(group, width, vectorBits, 21, 20, mask, zeroing, memory)
							got, length, recognized, err := decodedX86SingleSourceNarrowInstruction(code, 64)
							if err != nil || !recognized || length != len(code) {
								t.Fatalf("decode %x = %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
							}
							wantOp := op
							if zeroing {
								wantOp += ".Z"
							}
							if got.Op != wantOp || got.Args[0].String() != fmt.Sprintf("%s21", prefix) {
								t.Fatalf("decode %x = %+v, want %s and %s21", code, got, wantOp, prefix)
							}
							if masked && (len(got.Args) != 3 || got.Args[1].String() != "K3") || !masked && len(got.Args) != 2 {
								t.Fatalf("decode %x = %+v, lost mask", code, got)
							}
							destination := got.Args[len(got.Args)-1]
							if memory {
								if destination.Kind != OpMem || destination.Mem.Base != AX || destination.Mem.Off != int64(outputBytes) {
									t.Fatalf("decode %x = %+v, want compressed displacement %d", code, got, outputBytes)
								}
							} else if destination.String() != fmt.Sprintf("%s20", outputPrefix) {
								t.Fatalf("decode %x = %+v, want %s20", code, got, outputPrefix)
							}
						}
					}
				}
			}
		}
	}
	if len(seen) != len(amd64SingleSourceNarrowSpecs) {
		t.Fatalf("raw grammar has %d distinct ops, named lowerer has %d", len(seen), len(amd64SingleSourceNarrowSpecs))
	}
}

func TestDecodedX86RawSingleSourceNarrowRejectsReservedBits(t *testing.T) {
	base := encodeX86RawSingleSourceNarrow(0, 1, 2, 2, 1, 3, true, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"W bit", []byte{base[0], base[1], base[2] | 0x80, base[3], base[4], base[5]}},
		{"fixed bit", []byte{base[0], base[1], base[2] &^ 4, base[3], base[4], base[5]}},
		{"vvvv", []byte{base[0], base[1], base[2] &^ 8, base[3], base[4], base[5]}},
		{"V prime", []byte{base[0], base[1], base[2], base[3] &^ 8, base[4], base[5]}},
		{"broadcast", []byte{base[0], base[1], base[2], base[3] | 0x10, base[4], base[5]}},
		{"reserved length", []byte{base[0], base[1], base[2], base[3] | 0x20, base[4], base[5]}},
		{"zero without mask", []byte{base[0], base[1], base[2], base[3] &^ 7, base[4], base[5]}},
		{"missing ModRM", base[:5]},
		{"address override", append([]byte{0x67}, base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86SingleSourceNarrowInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted reserved encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
	if _, _, recognized, err := decodedX86PerLaneVariableShiftInstruction(base, 64); recognized || err != nil {
		t.Fatalf("per-lane shift incorrectly owns F3 narrow opcode: recognized=%v err=%v", recognized, err)
	}
}

func TestTranslateRawSingleSourceNarrowLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawNarrowFamily(SB), $0-0\n")
			appendBytes := func(code []byte) {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			for group, row := range x86RawSingleSourceNarrowOps {
				for width := range row {
					appendBytes(encodeX86RawSingleSourceNarrow(group, width, 0, 2, 1, 0, false, false))
				}
				appendBytes(encodeX86RawSingleSourceNarrow(group, 5, 2, 2, 1, 2, true, false))
				appendBytes(encodeX86RawSingleSourceNarrow(group, 1, 1, 2, 0, 3, false, true))
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawNarrowFamily": {Name: "rawNarrowFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-single-source-narrow.ll", "raw-single-source-narrow.o", ir)
		})
	}
}
