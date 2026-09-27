package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEOrdinaryMemoryCompleteGo127Forms() string {
	return `TEXT sveordinarymemoryforms(SB),$0-0
	ZLD1B (R6)(R14), P4.Z, [Z13.B]
	ZLD1B (R7)(RSP), P3.Z, [Z12.H]
	ZLD1B (R5)(R27), P2.Z, [Z6.S]
	ZLD1B (R2)(R3), P1.Z, [Z24.D]
	ZLD1B (-VL*8)(R14), P4.Z, [Z13.B]
	ZLD1B (VL*7)(R14), P4.Z, [Z13.H]
	ZLD1B (-VL*2)(R14), P4.Z, [Z13.S]
	ZLD1B (VL*3)(R14), P4.Z, [Z13.D]
	ZLD1B (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1B (Z6.D.SXTW)(R14), P4.Z, [Z13.D]
	ZLD1B (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLD1B (Z7.S), P4.Z, [Z13.S]
	ZLD1B 31(Z7.D), P4.Z, [Z13.D]
	ZLD1B (R5)(R27), PN12.Z, [Z6.B-Z7.B]
	ZLD1B (R2)(R3), PN10.Z, [Z24.B-Z27.B]
	ZLD1B (-VL*16)(R3), PN10.Z, [Z24.B-Z25.B]
	ZLD1B (VL*28)(RSP), PN10.Z, [Z16.B-Z19.B]

	ZLD1H (R6<<1)(R14), P4.Z, [Z13.H]
	ZLD1H (R7<<1)(RSP), P3.Z, [Z12.S]
	ZLD1H (R5<<1)(R27), P2.Z, [Z6.D]
	ZLD1H (-VL*8)(R14), P4.Z, [Z13.H]
	ZLD1H (VL*7)(R14), P4.Z, [Z13.S]
	ZLD1H (-VL*2)(R14), P4.Z, [Z13.D]
	ZLD1H (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1H (Z23.D<<1)(R24), P1.Z, [Z22.D]
	ZLD1H (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLD1H (Z5.D.SXTW<<1)(R12), P2.Z, [Z11.D]
	ZLD1H (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLD1H (Z9.S.SXTW<<1)(R8), P5.Z, [Z10.S]
	ZLD1H (Z7.S), P4.Z, [Z13.S]
	ZLD1H 62(Z7.D), P4.Z, [Z13.D]
	ZLD1H (R5<<1)(R27), PN12.Z, [Z6.H-Z7.H]
	ZLD1H (R2<<1)(R3), PN10.Z, [Z24.H-Z27.H]
	ZLD1H (-VL*16)(R3), PN10.Z, [Z24.H-Z25.H]
	ZLD1H (VL*28)(RSP), PN10.Z, [Z16.H-Z19.H]

	ZLD1W (R6<<2)(R14), P4.Z, [Z13.S]
	ZLD1W (R7<<2)(RSP), P3.Z, [Z12.D]
	ZLD1W (R5<<2)(R27), P2.Z, [Z6.Q]
	ZLD1W (-VL*8)(R14), P4.Z, [Z13.S]
	ZLD1W (VL*7)(R14), P4.Z, [Z13.D]
	ZLD1W (-VL*2)(R14), P4.Z, [Z13.Q]
	ZLD1W (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1W (Z23.D<<2)(R24), P1.Z, [Z22.D]
	ZLD1W (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLD1W (Z5.D.SXTW<<2)(R12), P2.Z, [Z11.D]
	ZLD1W (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLD1W (Z9.S.SXTW<<2)(R8), P5.Z, [Z10.S]
	ZLD1W (Z7.S), P4.Z, [Z13.S]
	ZLD1W 124(Z7.D), P4.Z, [Z13.D]
	ZLD1W (R5<<2)(R27), PN12.Z, [Z6.S-Z7.S]
	ZLD1W (R2<<2)(R3), PN10.Z, [Z24.S-Z27.S]
	ZLD1W (-VL*16)(R3), PN10.Z, [Z24.S-Z25.S]
	ZLD1W (VL*28)(RSP), PN10.Z, [Z16.S-Z19.S]

	ZLD1D (R6<<3)(R14), P4.Z, [Z13.D]
	ZLD1D (R7<<3)(RSP), P3.Z, [Z12.Q]
	ZLD1D (-VL*8)(R14), P4.Z, [Z13.D]
	ZLD1D (VL*7)(R14), P4.Z, [Z13.Q]
	ZLD1D (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1D (Z23.D<<3)(R24), P1.Z, [Z22.D]
	ZLD1D (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLD1D (Z5.D.SXTW<<3)(R12), P2.Z, [Z11.D]
	ZLD1D 248(Z7.D), P4.Z, [Z13.D]
	ZLD1D (R5<<3)(R27), PN12.Z, [Z6.D-Z7.D]
	ZLD1D (R2<<3)(R3), PN10.Z, [Z24.D-Z27.D]
	ZLD1D (-VL*16)(R3), PN10.Z, [Z24.D-Z25.D]
	ZLD1D (VL*28)(RSP), PN10.Z, [Z16.D-Z19.D]

	ZLD1SB (R6)(R14), P4.Z, [Z13.H]
	ZLD1SB (R7)(RSP), P3.Z, [Z12.S]
	ZLD1SB (R5)(R27), P2.Z, [Z6.D]
	ZLD1SB (-VL*8)(R14), P4.Z, [Z13.H]
	ZLD1SB (VL*7)(R14), P4.Z, [Z13.S]
	ZLD1SB (-VL*2)(R14), P4.Z, [Z13.D]
	ZLD1SB (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1SB (Z6.D.SXTW)(R14), P4.Z, [Z13.D]
	ZLD1SB (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLD1SB (Z7.S), P4.Z, [Z13.S]
	ZLD1SB 31(Z7.D), P4.Z, [Z13.D]

	ZLD1SH (R6<<1)(R14), P4.Z, [Z13.S]
	ZLD1SH (R7<<1)(RSP), P3.Z, [Z12.D]
	ZLD1SH (-VL*8)(R14), P4.Z, [Z13.S]
	ZLD1SH (VL*7)(R14), P4.Z, [Z13.D]
	ZLD1SH (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1SH (Z23.D<<1)(R24), P1.Z, [Z22.D]
	ZLD1SH (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLD1SH (Z5.D.SXTW<<1)(R12), P2.Z, [Z11.D]
	ZLD1SH (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLD1SH (Z9.S.SXTW<<1)(R8), P5.Z, [Z10.S]
	ZLD1SH (Z7.S), P4.Z, [Z13.S]
	ZLD1SH 62(Z7.D), P4.Z, [Z13.D]

	ZLD1SW (R6<<2)(R14), P4.Z, [Z13.D]
	ZLD1SW (-VL*8)(R14), P4.Z, [Z13.D]
	ZLD1SW (Z10.D)(R19), P3.Z, [Z15.D]
	ZLD1SW (Z23.D<<2)(R24), P1.Z, [Z22.D]
	ZLD1SW (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLD1SW (Z5.D.SXTW<<2)(R12), P2.Z, [Z11.D]
	ZLD1SW 124(Z7.D), P4.Z, [Z13.D]

	ZLD1Q (R6)(Z7.D), P4.Z, [Z13.Q]

	ZST1B [Z7.B], P4, (R21)(R7)
	ZST1B [Z8.H], P3, (R6)(RSP)
	ZST1B [Z9.S], P2, (R5)(R4)
	ZST1B [Z10.D], P1, (R3)(R2)
	ZST1B [Z6.D], P4, (Z21.D.UXTW)(R7)
	ZST1B [Z5.D], P3, (Z20.D.SXTW)(R8)
	ZST1B [Z4.S], P2, (Z19.S.UXTW)(R9)
	ZST1B [Z8.S], P3, (Z15.S)
	ZST1B [Z8.D], P3, 31(Z15.D)
	ZST1B [Z7.B], P4, (-VL*8)(R7)
	ZST1B [Z8.H], P3, (VL*7)(RSP)
	ZST1B [Z9.S], P2, (-VL*3)(R7)
	ZST1B [Z10.D], P1, (VL*4)(R7)
	ZST1B [Z14.B-Z15.B], PN12, (R20)(R17)
	ZST1B [Z4.B-Z7.B], PN12, (R12)(RSP)
	ZST1B [Z14.B-Z15.B], PN12, (-VL*16)(R17)
	ZST1B [Z4.B-Z7.B], PN12, (VL*28)(RSP)

	ZST1H [Z7.H], P4, (R21<<1)(R7)
	ZST1H [Z8.S], P3, (R6<<1)(RSP)
	ZST1H [Z9.D], P2, (R5<<1)(R4)
	ZST1H [Z6.D], P4, (Z21.D)(R7)
	ZST1H [Z5.D], P3, (Z20.D<<1)(R8)
	ZST1H [Z4.D], P2, (Z19.D.UXTW)(R9)
	ZST1H [Z3.D], P1, (Z18.D.SXTW<<1)(R10)
	ZST1H [Z2.S], P0, (Z17.S.UXTW)(R11)
	ZST1H [Z1.S], P7, (Z16.S.SXTW<<1)(R12)
	ZST1H [Z8.S], P3, (Z15.S)
	ZST1H [Z8.D], P3, 62(Z15.D)
	ZST1H [Z7.H], P4, (-VL*8)(R7)
	ZST1H [Z8.S], P3, (VL*7)(RSP)
	ZST1H [Z9.D], P2, (-VL*3)(R7)
	ZST1H [Z14.H-Z15.H], PN12, (R20<<1)(R17)
	ZST1H [Z4.H-Z7.H], PN12, (R12<<1)(RSP)
	ZST1H [Z14.H-Z15.H], PN12, (-VL*16)(R17)
	ZST1H [Z4.H-Z7.H], PN12, (VL*28)(RSP)

	ZST1W [Z7.S], P4, (R21<<2)(R7)
	ZST1W [Z8.D], P3, (R6<<2)(RSP)
	ZST1W [Z9.Q], P2, (R5<<2)(R4)
	ZST1W [Z6.D], P4, (Z21.D)(R7)
	ZST1W [Z5.D], P3, (Z20.D<<2)(R8)
	ZST1W [Z4.D], P2, (Z19.D.UXTW)(R9)
	ZST1W [Z3.D], P1, (Z18.D.SXTW<<2)(R10)
	ZST1W [Z2.S], P0, (Z17.S.UXTW)(R11)
	ZST1W [Z1.S], P7, (Z16.S.SXTW<<2)(R12)
	ZST1W [Z8.S], P3, (Z15.S)
	ZST1W [Z8.D], P3, 124(Z15.D)
	ZST1W [Z7.S], P4, (-VL*8)(R7)
	ZST1W [Z8.D], P3, (VL*7)(RSP)
	ZST1W [Z9.Q], P2, (-VL*3)(R7)
	ZST1W [Z14.S-Z15.S], PN12, (R20<<2)(R17)
	ZST1W [Z4.S-Z7.S], PN12, (R12<<2)(RSP)
	ZST1W [Z14.S-Z15.S], PN12, (-VL*16)(R17)
	ZST1W [Z4.S-Z7.S], PN12, (VL*28)(RSP)

	ZST1D [Z7.D], P4, (R21<<3)(R7)
	ZST1D [Z8.Q], P3, (R6<<3)(RSP)
	ZST1D [Z6.D], P4, (Z21.D)(R7)
	ZST1D [Z5.D], P3, (Z20.D<<3)(R8)
	ZST1D [Z4.D], P2, (Z19.D.UXTW)(R9)
	ZST1D [Z3.D], P1, (Z18.D.SXTW<<3)(R10)
	ZST1D [Z8.D], P3, (Z15.D)
	ZST1D [Z7.D], P4, (-VL*8)(R7)
	ZST1D [Z8.Q], P3, (VL*7)(RSP)
	ZST1D [Z14.D-Z15.D], PN12, (R20<<3)(R17)
	ZST1D [Z4.D-Z7.D], PN12, (R12<<3)(RSP)
	ZST1D [Z14.D-Z15.D], PN12, (-VL*16)(R17)
	ZST1D [Z4.D-Z7.D], PN12, (VL*28)(RSP)

	ZST1Q [Z8.Q], P3, (R6)(Z15.D)
	RET
`
}

func TestTranslateARM64SVEOrdinaryMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVEOrdinaryMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveordinarymemoryforms": {Name: "sveordinarymemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.ld1.nxv",
				"@llvm.aarch64.sve.ld1.gather.nxv",
				"@llvm.aarch64.sve.ld1.gather.index.nxv",
				"@llvm.aarch64.sve.ld1.gather.uxtw.nxv",
				"@llvm.aarch64.sve.ld1.gather.sxtw.index.nxv",
				"@llvm.aarch64.sve.ld1.gather.scalar.offset.",
				"@llvm.aarch64.sve.ld1.pn.x2.",
				"@llvm.aarch64.sve.ld1.pn.x4.",
				"@llvm.aarch64.sve.ld1udq.",
				"@llvm.aarch64.sve.ld1uwq.",
				"@llvm.aarch64.sve.ld1q.gather.scalar.offset.",
				"@llvm.aarch64.sve.st1.nxv",
				"@llvm.aarch64.sve.st1.scatter.nxv",
				"@llvm.aarch64.sve.st1.scatter.index.nxv",
				"@llvm.aarch64.sve.st1.scatter.uxtw.nxv",
				"@llvm.aarch64.sve.st1.scatter.sxtw.index.nxv",
				"@llvm.aarch64.sve.st1.scatter.scalar.offset.",
				"@llvm.aarch64.sve.st1.pn.x2.",
				"@llvm.aarch64.sve.st1.pn.x4.",
				"@llvm.aarch64.sve.st1dq.",
				"@llvm.aarch64.sve.st1wq.",
				"@llvm.aarch64.sve.st1q.scatter.scalar.offset.",
				" sext <vscale x ",
				" zext <vscale x ",
				" trunc <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE ordinary memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-ordinary-memory.ll", "arm64-sve-ordinary-memory.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEContiguousByteMemoryCompleteFamily(t *testing.T) {
	// The ordinary LD1B/ST1B scalar-base forms span B/H/S/D arrangements,
	// register offsets, and signed MUL VL immediates. lightning uses the
	// first observed load; gocc uses both observed stores.
	var source strings.Builder
	source.WriteString("TEXT rawSVEContiguousByteMemory(SB),$0-0\n")
	for _, observed := range []uint32{0xa400a400, 0xe42b4040, 0xe4084040} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", observed)
	}
	for size := uint32(0); size < 4; size++ {
		registers := uint32(11<<16 | 1<<10 | 2<<5 | 3)
		for _, base := range []uint32{0xa4004000, 0xe4004000} {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|size<<21|registers)
		}
		for _, base := range []uint32{0xa400a000, 0xe400e000} {
			for _, offset := range []uint32{0, 7, 8} {
				word := base | size<<21 | offset<<16 | 1<<10 | 2<<5 | 3
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
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
					"rawSVEContiguousByteMemory": {Name: "rawSVEContiguousByteMemory", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.masked.load.nxv",
				"@llvm.aarch64.sve.ld1.nxv",
				"@llvm.aarch64.sve.st1.nxv",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw byte memory IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-byte-memory.ll", "arm64-raw-sve-byte-memory.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEContiguousByteMemoryBoundaries(t *testing.T) {
	for _, test := range []struct {
		word      uint32
		op        Op
		base      Reg
		index     Reg
		offsetRaw string
		vector    Reg
	}{
		{0xa400a400, "ZLD1B", "R0", "", "", "Z0.B"},
		{0xe42b4040, "ZST1B", "R11", "R2", "", "Z0.H"},
		{0xe4084040, "ZST1B", "R8", "R2", "", "Z0.B"},
		{0xa408a443, "ZLD1B", "R2", "", "-VL*8", "Z3.B"},
	} {
		ins, ok := decodeARM64RawSVEContiguousMemory(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != 3 {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		memoryIndex, vectorIndex := 0, 2
		if test.op == "ZST1B" {
			memoryIndex, vectorIndex = 2, 0
		}
		memory := ins.Args[memoryIndex].Mem
		if memory.Base != test.base || memory.Index != test.index || memory.OffRaw != test.offsetRaw {
			t.Errorf("%#08x memory = %+v", test.word, memory)
		}
		if ins.Args[vectorIndex].Kind != OpRegList || ins.Args[vectorIndex].RegList[0] != test.vector {
			t.Errorf("%#08x vector = %+v", test.word, ins.Args[vectorIndex])
		}
	}
	for _, word := range []uint32{
		0xa400a400 | (1 << 14),
		0xe42b4040 | (1 << 13),
	} {
		if ins, ok := decodeARM64RawSVEContiguousMemory(word); ok {
			t.Errorf("decoded reserved byte memory %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEOrdinaryMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLD1B (R6)(R14), P8.Z, [Z13.B]",
		"ZLD1H (R6)(R14), P4.Z, [Z13.H]",
		"ZLD1W (R6<<1)(R14), P4.Z, [Z13.S]",
		"ZLD1D (R6<<2)(R14), P4.Z, [Z13.D]",
		"ZLD1SB (R6)(R14), P4.Z, [Z13.B]",
		"ZLD1SH (R6<<1)(R14), P4.Z, [Z13.H]",
		"ZLD1SW (R6<<2)(R14), P4.Z, [Z13.S]",
		"ZLD1B (Z4.S)(R3), P3.Z, [Z4.S]",
		"ZLD1H (Z4.S.UXTW<<2)(R3), P3.Z, [Z4.S]",
		"ZLD1W 128(Z7.S), P4.Z, [Z13.S]",
		"ZLD1D (VL*8)(R14), P4.Z, [Z13.D]",
		"ZLD1D (VL*3)(R3), PN10.Z, [Z24.D-Z25.D]",
		"ZLD1D (VL*2)(RSP), PN10.Z, [Z16.D-Z19.D]",
		"ZLD1Q (R6)(Z7.S), P4.Z, [Z13.Q]",
		"ZST1B [Z8.B], P8, (R6)(RSP)",
		"ZST1H [Z8.B], P3, (R6<<1)(RSP)",
		"ZST1W [Z8.H], P3, (R6<<2)(RSP)",
		"ZST1D [Z8.S], P3, (R6<<3)(RSP)",
		"ZST1H [Z8.S], P3, 3(Z15.S)",
		"ZST1D [Z8.D], P3, 256(Z15.D)",
		"ZST1D [Z8.D], P3, (VL*8)(RSP)",
		"ZST1D [Z14.D-Z16.D], PN12, (R20<<3)(R17)",
		"ZST1D [Z14.D-Z15.D], PN12, (VL*3)(R17)",
		"ZST1Q [Z8.D], P3, (R6)(Z15.D)",
		"ZLD1B.Z (R6)(R14), P4.Z, [Z13.B]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveordinarymemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveordinarymemory": {Name: "badsveordinarymemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ordinary SVE memory forms", instruction)
			}
		})
	}
}
