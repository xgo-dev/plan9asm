package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawVPSHUFBLiteral(evex bool, width, mask int, zeroing bool) []byte {
	code := encodeRawScalarMove(evex, 1, 0, 0, 0, 0, mask, zeroing)
	code[1] = code[1]&0xf0 | 2
	if evex {
		code[3] |= byte(map[int]int{16: 0, 32: 1, 64: 2}[width]) << 5
	} else if width == 32 {
		code[2] |= 0x04
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*23+7))
	}
	return code
}

func TestDecodeX86RawVPSHUFBRIPDataCompleteFamily(t *testing.T) {
	for _, evex := range []bool{false, true} {
		widths := []int{16, 32}
		if evex {
			widths = append(widths, 64)
		}
		for _, width := range widths {
			masks := []int{0}
			if evex {
				masks = append(masks, 7)
			}
			for _, mask := range masks {
				name := fmt.Sprintf("evex%t/%d/mask%d", evex, width, mask)
				t.Run(name, func(t *testing.T) {
					code := x86RawVPSHUFBLiteral(evex, width, mask, mask != 0)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := Op("VPSHUFB")
					if mask != 0 {
						want += ".Z"
					}
					if len(decoded) != 2 || decoded[0].Op != want ||
						decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
						decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, want)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawVPSHUFBRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawVPSHUFBLiteral(true, 64, 7, true)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source": func(code []byte) []byte { return code[:len(code)-1] },
		"overlapping instruction": func(code []byte) []byte {
			code[6] = 0
			return code
		},
		"outside directive group": func(code []byte) []byte {
			code[6] = 127
			return code
		},
		"segment override": func(code []byte) []byte {
			return append([]byte{0x65}, code...)
		},
		"address override": func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawVPSHUFBRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, form := range []struct {
		evex  bool
		width int
		mask  int
	}{
		{false, 16, 0}, {false, 32, 0},
		{true, 16, 0}, {true, 32, 7}, {true, 64, 7},
	} {
		code := x86RawVPSHUFBLiteral(form.evex, form.width, form.mask, form.mask != 0)
		name := fmt.Sprintf("vpshufbLiteral%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		pools = append(pools, code[len(code)-form.width:])
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != len(pools) {
		t.Fatalf("materialized %d constants, want %d", len(normalized.Data), len(pools))
	}
	for index, datum := range normalized.Data {
		if !bytes.Equal(datum.Payload, pools[index]) {
			t.Fatalf("constant %d = %x, want %x", index, datum.Payload, pools[index])
		}
	}
	again, err := normalizeX86RawFile(normalized, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Data) != len(pools) {
		t.Fatalf("second normalization materialized %d constants, want %d", len(again.Data), len(pools))
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "<16 x i32> <i32 7, i32 14, i32 5, i32 12, i32 3, i32 10, i32 16, i32 16, i32 16, i32 16, i32 16, i32 4, i32 11, i32 2, i32 9, i32 0>") {
				t.Fatal("missing lane-local and high-bit-zero byte shuffle")
			}
			compileLLVMToObject(t, llc, triple, "vpshufb-literal.ll", "vpshufb-literal.o", ir)
		})
	}
}
