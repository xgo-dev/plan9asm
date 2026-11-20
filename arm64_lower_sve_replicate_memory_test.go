package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEReplicateMemoryCompleteGo127Forms() string {
	var source strings.Builder
	source.WriteString("TEXT svereplicatememoryforms(SB),$0-0\n")
	for _, spec := range []struct {
		op           string
		arrangements []string
		maxOffset    int
	}{
		{op: "ZLD1RB", arrangements: []string{"B", "H", "S", "D"}, maxOffset: 63},
		{op: "ZLD1RH", arrangements: []string{"H", "S", "D"}, maxOffset: 126},
		{op: "ZLD1RW", arrangements: []string{"S", "D"}, maxOffset: 252},
		{op: "ZLD1RD", arrangements: []string{"D"}, maxOffset: 504},
		{op: "ZLD1RSB", arrangements: []string{"H", "S", "D"}, maxOffset: 63},
		{op: "ZLD1RSH", arrangements: []string{"S", "D"}, maxOffset: 126},
		{op: "ZLD1RSW", arrangements: []string{"D"}, maxOffset: 252},
	} {
		for i, arrangement := range spec.arrangements {
			offset := 0
			if i == len(spec.arrangements)-1 {
				offset = spec.maxOffset
			}
			fmt.Fprintf(&source, "\t%s %d(R14), P4.Z, [Z13.%s]\n", spec.op, offset, arrangement)
		}
	}
	for _, kind := range []string{"O", "Q"} {
		blockBytes := 32
		if kind == "Q" {
			blockBytes = 16
		}
		for _, width := range []struct {
			name        string
			arrangement string
			shift       int
		}{
			{name: "B", arrangement: "B"},
			{name: "H", arrangement: "H", shift: 1},
			{name: "W", arrangement: "S", shift: 2},
			{name: "D", arrangement: "D", shift: 3},
		} {
			op := "ZLD1R" + kind + width.name
			index := "R6"
			if width.shift != 0 {
				index = fmt.Sprintf("R6<<%d", width.shift)
			}
			fmt.Fprintf(&source, "\t%s (%s)(R14), P4.Z, [Z13.%s]\n", op, index, width.arrangement)
			fmt.Fprintf(&source, "\t%s %d(R14), P4.Z, [Z13.%s]\n", op, -8*blockBytes, width.arrangement)
		}
	}
	// Cover both ends of each signed immediate range.
	source.WriteString("\tZLD1ROB 224(R14), P4.Z, [Z13.B]\n")
	source.WriteString("\tZLD1RQB 112(R14), P4.Z, [Z13.B]\n")
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEReplicateMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVEReplicateMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svereplicatememoryforms": {Name: "svereplicatememoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+f64mm,+sve"`,
				"@llvm.aarch64.sve.ld1ro.nxv16i8",
				"@llvm.aarch64.sve.ld1ro.nxv8i16",
				"@llvm.aarch64.sve.ld1ro.nxv4i32",
				"@llvm.aarch64.sve.ld1ro.nxv2i64",
				"@llvm.aarch64.sve.ld1rq.nxv16i8",
				"@llvm.aarch64.sve.ld1rq.nxv8i16",
				"@llvm.aarch64.sve.ld1rq.nxv4i32",
				"@llvm.aarch64.sve.ld1rq.nxv2i64",
				"shufflevector <vscale x ",
				"select <vscale x ",
				" sext i",
				" zext i",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE replicate memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-replicate-memory.ll", "arm64-sve-replicate-memory.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEReplicateBlockCompleteFamily(t *testing.T) {
	// The RO and RQ families each have B/H/W/D and register/immediate
	// addressing rows. lightning emits RQB at 0xa40024e1.
	forms := []struct {
		regBase    uint32
		immBase    uint32
		blockBytes int
	}{
		{0xa4200000, 0xa4202000, 32},
		{0xa4a00000, 0xa4a02000, 32},
		{0xa5200000, 0xa5202000, 32},
		{0xa5a00000, 0xa5a02000, 32},
		{0xa4000000, 0xa4002000, 16},
		{0xa4800000, 0xa4802000, 16},
		{0xa5000000, 0xa5002000, 16},
		{0xa5800000, 0xa5802000, 16},
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEReplicateBlock(SB),$0-0\n")
	source.WriteString("\tWORD $0xa40024e1\n")
	for _, form := range forms {
		registers := uint32(6<<16 | 4<<10 | 14<<5 | 13)
		fmt.Fprintf(&source, "\tWORD $%#08x\n", form.regBase|registers)
		for _, offset := range []uint32{0, 7, 8} {
			word := form.immBase | offset<<16 | 4<<10 | 14<<5 | 13
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEReplicateBlock": {Name: "rawSVEReplicateBlock", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+f64mm,+sve"`,
				"@llvm.aarch64.sve.ld1ro.nxv16i8",
				"@llvm.aarch64.sve.ld1ro.nxv2i64",
				"@llvm.aarch64.sve.ld1rq.nxv16i8",
				"@llvm.aarch64.sve.ld1rq.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw replicate block IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-replicate-block.ll", "arm64-raw-sve-replicate-block.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEReplicateScalarCompleteFamily(t *testing.T) {
	// These are all sixteen immediate-address scalar replicate-load rows in
	// Go 1.27's ARM64 instruction table, including the go-highway LD1RW word.
	forms := []uint32{
		0x84408000, 0x8440a000, 0x8440c000, 0x8440e000, // LD1RB
		0x84c0a000, 0x84c0c000, 0x84c0e000, // LD1RH
		0x8540c000, 0x8540e000, // LD1RW
		0x85c0e000,                         // LD1RD
		0x85c0a000, 0x85c0c000, 0x85c08000, // LD1RSB
		0x8540a000, 0x85408000, // LD1RSH
		0x84c08000, // LD1RSW
	}
	for _, base := range forms {
		t.Run(fmt.Sprintf("encoding-%#08x", base), func(t *testing.T) {
			source := fmt.Sprintf("TEXT scalar(SB),$0-0\n\tWORD $%#08x\n\tRET\n", base|5<<10|14<<5|13)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"scalar": {Name: "scalar", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, `"target-features"="+sve"`) {
				t.Fatal("raw scalar replicate load omitted SVE target feature")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "scalar.ll", "scalar.o", ll)
		})
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEReplicateScalar(SB),$0-0\n")
	source.WriteString("\tWORD $0x8540c0c0\n")
	for _, base := range forms {
		for _, offset := range []uint32{0, 63} {
			word := base | offset<<16 | 5<<10 | 14<<5 | 13
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEReplicateScalar": {Name: "rawSVEReplicateScalar", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"shufflevector <vscale x ", "select <vscale x ", " sext i", " zext i"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw scalar replicate lowering omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-replicate-scalar.ll", "arm64-raw-sve-replicate-scalar.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEReplicateScalarBoundaries(t *testing.T) {
	tests := []struct {
		word        uint32
		op          Op
		base        Reg
		arrangement Reg
		offset      int64
	}{
		{0x8540c0c0, "ZLD1RW", "R6", "Z0.S", 0},
		{0x8540c000 | 63<<16 | 7<<10 | 31<<5 | 31, "ZLD1RW", SP, "Z31.S", 252},
		{0x85c0e000 | 63<<16 | 7<<10 | 31<<5 | 31, "ZLD1RD", SP, "Z31.D", 504},
		{0x84408000 | 63<<16 | 7<<10 | 31<<5 | 31, "ZLD1RB", SP, "Z31.B", 63},
		{0x84c08000 | 63<<16 | 7<<10 | 31<<5 | 31, "ZLD1RSW", SP, "Z31.D", 252},
	}
	for _, test := range tests {
		ins, ok := decodeARM64RawSVEReplicateScalar(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != 3 {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		predicate := Reg(fmt.Sprintf("P%d.Z", test.word>>10&7))
		if ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != test.base ||
			ins.Args[0].Mem.Off != test.offset || ins.Args[1].Reg != predicate ||
			ins.Args[2].RegList[0] != test.arrangement {
			t.Errorf("decoded %#08x operands = %+v", test.word, ins.Args)
		}
	}
	for _, word := range []uint32{
		0x8540c0c0 | 1<<25,
		0x8540c0c0 | 1<<27,
		0x8540c0c0 | 1<<29,
	} {
		if ins, ok := decodeARM64RawSVEReplicateScalar(word); ok {
			t.Errorf("decoded reserved scalar replicate load %#08x as %+v", word, ins)
		}
	}
}

func TestDecodeARM64RawSVEReplicateBlockBoundaries(t *testing.T) {
	observed, ok := decodeARM64RawSVEReplicateBlock(0xa40024e1)
	if !ok || observed.Op != "ZLD1RQB" || len(observed.Args) != 3 {
		t.Fatalf("decode lightning LD1RQB = %+v, %v", observed, ok)
	}
	if observed.Args[0].Kind != OpMem || observed.Args[0].Mem.Base != "R7" ||
		observed.Args[0].Mem.Off != 0 || observed.Args[1].Reg != "P1.Z" ||
		observed.Args[2].RegList[0] != "Z1.B" {
		t.Fatalf("lightning LD1RQB operands = %+v", observed.Args)
	}
	for _, test := range []struct {
		word  uint32
		op    Op
		base  Reg
		index Reg
		scale int64
		off   int64
	}{
		{0xa4200000 | 6<<16 | 4<<10 | 14<<5 | 13, "ZLD1ROB", "R6", "R14", 1, 0},
		{0xa4800000 | 6<<16 | 4<<10 | 14<<5 | 13, "ZLD1RQH", "R14", "R6", 2, 0},
		{0xa5802000 | 8<<16 | 4<<10 | 14<<5 | 13, "ZLD1RQD", "R14", "", 0, -128},
	} {
		ins, ok := decodeARM64RawSVEReplicateBlock(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		memory := ins.Args[0].Mem
		if memory.Base != test.base || memory.Index != test.index ||
			memory.Scale != test.scale || memory.Off != test.off {
			t.Errorf("%#08x memory = %+v", test.word, memory)
		}
	}
	for _, word := range []uint32{
		0xa40024e1 | (1 << 14),
		0xa40024e1 | (1 << 20),
	} {
		if ins, ok := decodeARM64RawSVEReplicateBlock(word); ok {
			t.Errorf("decoded reserved replicate load %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEReplicateMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLD1RB (R14), P8.Z, [Z13.B]",
		"ZLD1RB (R14), P4, [Z13.B]",
		"ZLD1RB (R14), P4.Z, [Z13.B, Z14.B]",
		"ZLD1RH (R14), P4.Z, [Z13.B]",
		"ZLD1RW (R14), P4.Z, [Z13.H]",
		"ZLD1RD (R14), P4.Z, [Z13.S]",
		"ZLD1RSB (R14), P4.Z, [Z13.B]",
		"ZLD1RSH (R14), P4.Z, [Z13.H]",
		"ZLD1RSW (R14), P4.Z, [Z13.S]",
		"ZLD1RB 64(R14), P4.Z, [Z13.B]",
		"ZLD1RH 127(R14), P4.Z, [Z13.H]",
		"ZLD1RW 254(R14), P4.Z, [Z13.S]",
		"ZLD1RD 512(R14), P4.Z, [Z13.D]",
		"ZLD1ROB -288(R14), P4.Z, [Z13.B]",
		"ZLD1ROB 256(R14), P4.Z, [Z13.B]",
		"ZLD1ROB 16(R14), P4.Z, [Z13.B]",
		"ZLD1RQB -144(R14), P4.Z, [Z13.B]",
		"ZLD1RQB 128(R14), P4.Z, [Z13.B]",
		"ZLD1RQB 8(R14), P4.Z, [Z13.B]",
		"ZLD1ROH (R6)(R14), P4.Z, [Z13.H]",
		"ZLD1RQD (R6<<2)(R14), P4.Z, [Z13.D]",
		"ZLD1ROB.Z (R6)(R14), P4.Z, [Z13.B]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvereplicatememory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvereplicatememory": {Name: "badsvereplicatememory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's replicate memory forms", instruction)
			}
		})
	}
}
