package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86RawKLogicalRow struct {
	opcode byte
	pp     byte
	w      bool
	name   Op
	ary    int
}

func x86RawKLogicalRows() []x86RawKLogicalRow {
	var rows []x86RawKLogicalRow
	for opcode, stem := range map[byte]string{
		0x4a: "KADD", 0x41: "KAND", 0x42: "KANDN", 0x45: "KOR",
		0x46: "KXNOR", 0x47: "KXOR", 0x44: "KNOT",
		0x98: "KORTEST", 0x99: "KTEST",
	} {
		arity := 3
		if opcode == 0x44 || opcode == 0x98 || opcode == 0x99 {
			arity = 2
		}
		for _, width := range []struct {
			pp     byte
			w      bool
			suffix string
		}{
			{pp: 1, suffix: "B"}, {pp: 0, suffix: "W"},
			{pp: 1, w: true, suffix: "D"}, {pp: 0, w: true, suffix: "Q"},
		} {
			rows = append(rows, x86RawKLogicalRow{opcode, width.pp, width.w, Op(stem + width.suffix), arity})
		}
	}
	rows = append(rows,
		x86RawKLogicalRow{0x4b, 1, false, "KUNPCKBW", 3},
		x86RawKLogicalRow{0x4b, 0, false, "KUNPCKWD", 3},
		x86RawKLogicalRow{0x4b, 0, true, "KUNPCKDQ", 3},
	)
	return rows
}

func encodeX86RawKLogical(row x86RawKLogicalRow, source1, source2, destination int) []byte {
	length := byte(0)
	if row.ary == 3 {
		length = 4
	}
	vvvv := 0
	if row.ary == 3 {
		vvvv = source2
	}
	p1 := byte((^vvvv&15)<<3) | length | row.pp
	modRM := byte(0xc0 | destination<<3 | source1)
	if row.w {
		return []byte{0xc4, 0xe1, p1 | 0x80, row.opcode, modRM}
	}
	return []byte{0xc5, p1 | 0x80, row.opcode, modRM}
}

func TestDecodedX86RawKLogicalCompleteGo127Family(t *testing.T) {
	rows := x86RawKLogicalRows()
	if len(rows) != 39 {
		t.Fatalf("modeled %d Go 1.27 K logical/arithmetic/unpack forms, want 39", len(rows))
	}
	for _, row := range rows {
		if _, ok := amd64MaskLogicalSpecs[row.name]; !ok {
			if _, ok := amd64MaskArithmeticSpecs[row.name]; !ok {
				if _, ok := amd64MaskUnpackBits[row.name]; !ok {
					t.Fatalf("%s has no lowering grammar", row.name)
				}
			}
		}
		for source1 := 0; source1 < 8; source1++ {
			for source2 := 0; source2 < 8; source2++ {
				if row.ary == 2 && source2 != 0 {
					continue
				}
				for destination := 0; destination < 8; destination++ {
					code := encodeX86RawKLogical(row, source1, source2, destination)
					got, length, ok, err := decodedX86RawKLogicalInstruction(code, 64)
					if err != nil || !ok || length != len(code) || got.Op != row.name || len(got.Args) != row.ary {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %s", code, got, length, ok, err, row.name)
					}
					want := fmt.Sprintf("%s K%d, K%d", row.name, source1, destination)
					if row.ary == 3 {
						want = fmt.Sprintf("%s K%d, K%d, K%d", row.name, source1, source2, destination)
					}
					if got.Raw != want {
						t.Fatalf("decode %x = %q, want %q", code, got.Raw, want)
					}
					if _, _, ok, err := decodedX86RawKLogicalInstruction(code, 32); !ok || err != nil {
						t.Fatalf("386 decode %x: ok=%v err=%v", code, ok, err)
					}
				}
			}
		}
	}
}

func TestTranslateRawKLogicalArgReduceAVX512Regression(t *testing.T) {
	const source = "TEXT rawKORW(SB),$0-0\n\tLONG $0xc945fcc5\n\tRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
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
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"rawKORW": {Name: "rawKORW", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "or i64") {
				t.Fatalf("KORW did not lower to mask OR:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "raw-korw.ll", "raw-korw.o", ir)
		})
	}
}

func TestTranslateRawKLogicalCompleteGo127FamilyObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawKLogicalFamily(SB),$0-0\n")
	for _, row := range x86RawKLogicalRows() {
		for _, value := range encodeX86RawKLogical(row, 1, 2, 3) {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
	}
	source.WriteString("\tRET\n")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawKLogicalFamily": {Name: "rawKLogicalFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-klogical-family.ll", "raw-klogical-family.o", ir)
		})
	}
}

func TestDecodedX86RawKLogicalRejectsReservedForms(t *testing.T) {
	row := x86RawKLogicalRow{0x45, 0, false, "KORW", 3}
	base := encodeX86RawKLogical(row, 1, 2, 3)
	for name, code := range map[string][]byte{
		"length":           {base[0], base[1] &^ 4, base[2], base[3]},
		"prefix":           {base[0], base[1] | 2, base[2], base[3]},
		"high vvvv":        {base[0], base[1] &^ 0x40, base[2], base[3]},
		"memory source":    {base[0], base[1], base[2], base[3] &^ 0xc0},
		"address override": append([]byte{0x67}, base...),
		"missing ModRM":    base[:3],
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok, err := decodedX86RawKLogicalInstruction(code, 64); !ok || err == nil {
				t.Fatalf("accepted reserved K encoding %x: ok=%v err=%v", code, ok, err)
			}
		})
	}
}
