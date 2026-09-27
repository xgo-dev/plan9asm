package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVECompareCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svecompareforms(SB),$0-0\n")
	for _, op := range []string{"ZCMPEQ", "ZCMPGE", "ZCMPGT", "ZCMPHI", "ZCMPHS", "ZCMPNE"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			predicate := string(rune('0' + index))
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", P" + predicate + ".Z, P12." + width + "\n")
		}
		for index, width := range []string{"B", "H", "S"} {
			predicate := string(rune('4' + index))
			source.WriteString("\t" + op + " Z3.D, Z4." + width + ", P" + predicate + ".Z, P13." + width + "\n")
		}
		for index, width := range []string{"B", "H", "S", "D"} {
			predicate := string(rune('0' + index))
			immediate := "-16"
			if op == "ZCMPHI" || op == "ZCMPHS" {
				immediate = "127"
			}
			source.WriteString("\t" + op + " $" + immediate + ", Z5." + width + ", P" + predicate + ".Z, P14." + width + "\n")
		}
	}
	for _, op := range []string{"ZCMPLE", "ZCMPLO", "ZCMPLS", "ZCMPLT"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			predicate := string(rune('0' + index))
			if width != "D" {
				source.WriteString("\t" + op + " Z3.D, Z4." + width + ", P" + predicate + ".Z, P13." + width + "\n")
			}
			immediate := "-16"
			if op == "ZCMPLO" || op == "ZCMPLS" {
				immediate = "127"
			}
			source.WriteString("\t" + op + " $" + immediate + ", Z5." + width + ", P" + predicate + ".Z, P14." + width + "\n")
		}
	}
	for _, op := range []string{"ZFACGE", "ZFACGT", "ZFCMEQ", "ZFCMGE", "ZFCMGT", "ZFCMNE", "ZFCMUO"} {
		for index, width := range []string{"H", "S", "D"} {
			predicate := string(rune('0' + index))
			source.WriteString("\t" + op + " Z6." + width + ", Z7." + width + ", P" + predicate + ".Z, P15." + width + "\n")
		}
	}
	for _, op := range []string{"ZFCMEQ", "ZFCMGE", "ZFCMGT", "ZFCMLE", "ZFCMLT", "ZFCMNE"} {
		for index, width := range []string{"H", "S", "D"} {
			predicate := string(rune('4' + index))
			source.WriteString("\t" + op + " $(0.0), Z8." + width + ", P" + predicate + ".Z, P11." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVECompareCompleteGo127Family(t *testing.T) {
	source := arm64SVECompareCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecompareforms": {Name: "svecompareforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve"`, " icmp ", " fcmp ", "@llvm.aarch64.sve.cmpeq.wide.nxv", "@llvm.aarch64.sve.cmplo.wide.nxv", "@llvm.aarch64.sve.convert.to.svbool"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE compare lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-compare.ll", "arm64-sve-compare.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEReverseCompareCompleteFamily(t *testing.T) {
	forms := []struct {
		wideBase uint32
		immBase  uint32
		imm      uint32
	}{
		{0x24006010, 0x25002010, 16}, // LE: -16
		{0x2400e000, 0x24202000, 127},
		{0x2400e010, 0x24202010, 127},
		{0x24006000, 0x25002000, 16}, // LT: -16
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEReverseCompare(SB),$0-0\n")
	source.WriteString("\tWORD $0x24282403\n") // lightning: CMPLO P3.B, P1/Z, Z0.B, #32
	for _, form := range forms {
		for size := uint32(0); size < 4; size++ {
			var immediate uint32
			if form.immBase&0x00200000 != 0 {
				immediate = form.imm << 14
			} else {
				immediate = form.imm << 16
			}
			word := form.immBase | size<<22 | immediate | 1<<10 | 2<<5 | 3
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			if size < 3 {
				word = form.wideBase | size<<22 | 4<<16 | 1<<10 | 2<<5 | 3
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
					"rawSVEReverseCompare": {Name: "rawSVEReverseCompare", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.cmple.wide.nxv",
				"@llvm.aarch64.sve.cmplo.wide.nxv",
				"@llvm.aarch64.sve.cmpls.wide.nxv",
				"@llvm.aarch64.sve.cmplt.wide.nxv",
				" icmp sle ", " icmp slt ", " icmp ule ", " icmp ult ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw reverse compare IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-reverse-compare.ll", "arm64-raw-sve-reverse-compare.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEIntegerCompareCompleteFamily(t *testing.T) {
	// Six ordinary integer comparisons have regular-vector, wide-vector,
	// and immediate rows in Go 1.27. gocc emits CMPNE 0x2400a031;
	// lightning emits CMPHS immediate 0x24380483.
	forms := []struct {
		wideBase    uint32
		regularBase uint32
		immBase     uint32
		unsigned    bool
	}{
		{0x24002000, 0x2400a000, 0x25008000, false},
		{0x24004000, 0x24008000, 0x25000000, false},
		{0x24004010, 0x24008010, 0x25000010, false},
		{0x2400c010, 0x24000010, 0x24200010, true},
		{0x2400c000, 0x24000000, 0x24200000, true},
		{0x24002010, 0x2400a010, 0x25008010, false},
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEIntegerCompare(SB),$0-0\n")
	source.WriteString("\tWORD $0x2400a031\n")
	source.WriteString("\tWORD $0x24380483\n")
	for _, form := range forms {
		for size := uint32(0); size < 4; size++ {
			registers := size<<22 | 4<<16 | 1<<10 | 2<<5 | 3
			fmt.Fprintf(&source, "\tWORD $%#08x\n", form.regularBase|registers)
			if size < 3 {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", form.wideBase|registers)
			}
			immediate := uint32(16 << 16) // signed -16
			if form.unsigned {
				immediate = 127 << 14
			}
			word := form.immBase | size<<22 | immediate | 1<<10 | 2<<5 | 3
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
					"rawSVEIntegerCompare": {Name: "rawSVEIntegerCompare", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.cmpeq.wide.nxv",
				"@llvm.aarch64.sve.cmpne.wide.nxv",
				" icmp eq ", " icmp ne ", " icmp uge ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw integer compare IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-integer-compare.ll", "arm64-raw-sve-integer-compare.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEIntegerCompareBoundaries(t *testing.T) {
	observed, ok := decodeARM64RawSVEIntegerCompare(0x24282403)
	if !ok || observed.Op != "ZCMPLO" || len(observed.Args) != 4 {
		t.Fatalf("decode lightning CMPLO = %+v, %v", observed, ok)
	}
	if observed.Args[0].Kind != OpImm || observed.Args[0].Imm != 32 ||
		observed.Args[1].Reg != "Z0.B" || observed.Args[2].Reg != "P1.Z" ||
		observed.Args[3].Reg != "P3.B" {
		t.Fatalf("lightning CMPLO operands = %+v", observed.Args)
	}
	for _, test := range []struct {
		word uint32
		op   Op
		args []Reg
		imm  int64
	}{
		{0x2400a031, "ZCMPNE", []Reg{"Z0.B", "Z1.B", "P0.Z", "P1.B"}, 0},
		{0x24380483, "ZCMPHS", []Reg{"", "Z4.B", "P1.Z", "P3.B"}, 96},
	} {
		ins, ok := decodeARM64RawSVEIntegerCompare(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != 4 {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		for index, want := range test.args {
			if want == "" {
				if ins.Args[index].Kind != OpImm || ins.Args[index].Imm != test.imm {
					t.Errorf("%#08x operand %d = %+v, want immediate %d", test.word, index, ins.Args[index], test.imm)
				}
			} else if ins.Args[index].Kind != OpReg || ins.Args[index].Reg != want {
				t.Errorf("%#08x operand %d = %+v, want %s", test.word, index, ins.Args[index], want)
			}
		}
	}
	for _, word := range []uint32{
		0x2400e000 | 3<<22, // wide D form is rejected by Go
		0x24282403 ^ (1 << 25),
	} {
		if ins, ok := decodeARM64RawSVEIntegerCompare(word); ok {
			t.Errorf("decoded invalid reverse compare %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVECompareRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCMPEQ Z1.B, Z2.H, P0.Z, P1.H",
		"ZCMPGE $16, Z2.S, P0.Z, P1.S",
		"ZCMPHI $-1, Z2.S, P0.Z, P1.S",
		"ZCMPLO Z1.B, Z2.B, P0.Z, P1.B",
		"ZCMPLT $16, Z2.S, P0.Z, P1.S",
		"ZCMPLS $-1, Z2.S, P0.Z, P1.S",
		"ZCMPNE Z1.S, Z2.S, P8.Z, P1.S",
		"ZFCMEQ Z1.B, Z2.B, P0.Z, P1.B",
		"ZFCMGT $(1.0), Z2.D, P0.Z, P1.D",
		"ZFACGE Z1.S, Z2.S, P0.M, P1.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecompare(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecompare": {Name: "badsvecompare", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE compare forms", instruction)
			}
		})
	}
}
