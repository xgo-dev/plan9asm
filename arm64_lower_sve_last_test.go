package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVELastCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svelastforms(SB),$0-0\n")
	for _, selector := range []string{"A", "B"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\tZLAST%s Z1.%s, P0, R2\n", selector, width)
			fmt.Fprintf(&source, "\tZLAST%sW Z3.%s, P1, R4\n", selector, width)
			fmt.Fprintf(&source, "\tZLAST%sB Z5.%s, P2, V6\n", selector, width)
			fmt.Fprintf(&source, "\tZLAST%sH Z7.%s, P3, V8\n", selector, width)
			fmt.Fprintf(&source, "\tZLAST%sS Z9.%s, P4, V10\n", selector, width)
			fmt.Fprintf(&source, "\tZLAST%sD Z11.%s, P7, V12\n", selector, width)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVELastCompleteGo127Family(t *testing.T) {
	source := arm64SVELastCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svelastforms": {Name: "svelastforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.lasta.nxv16i8",
				"@llvm.aarch64.sve.lasta.nxv8i16",
				"@llvm.aarch64.sve.lastb.nxv4i32",
				"@llvm.aarch64.sve.lastb.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE LAST lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-last.ll", "arm64-sve-last.o", ll)
		})
	}
}

func TestTranslateARM64RawSVELastCompleteFamily(t *testing.T) {
	// The twelve Go 1.27 LAST[A/B] mnemonic rows collapse to four raw
	// opcode classes (scalar/vector destination for A/B) and four sizes.
	// gocc emits LASTA W8, P0, Z1.B at 0x0520a028.
	bases := []uint32{0x0520a000, 0x05228000, 0x0521a000, 0x05238000}
	var source strings.Builder
	source.WriteString("TEXT rawSVELast(SB),$0-0\n")
	for _, base := range bases {
		for size := uint32(0); size < 4; size++ {
			word := base | size<<22 | 1<<5 | 8
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
					"rawSVELast": {Name: "rawSVELast", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.lasta.nxv16i8",
				"@llvm.aarch64.sve.lasta.nxv8i16",
				"@llvm.aarch64.sve.lastb.nxv4i32",
				"@llvm.aarch64.sve.lastb.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw LAST IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-last.ll", "arm64-raw-sve-last.o", ll)
		})
	}
}

func TestDecodeARM64RawSVELastBoundaries(t *testing.T) {
	for _, test := range []struct {
		word uint32
		op   Op
		args []Reg
	}{
		{0x0520a028, "ZLASTAW", []Reg{"Z1.B", "P0", "R8"}},
		{0x05e28028, "ZLASTAB", []Reg{"Z1.D", "P0", "V8"}},
		{0x0521a028, "ZLASTBW", []Reg{"Z1.B", "P0", "R8"}},
	} {
		ins, ok := decodeARM64RawSVELast(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != len(test.args) {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		for index, want := range test.args {
			if ins.Args[index].Kind != OpReg || ins.Args[index].Reg != want {
				t.Errorf("%#08x operand %d = %+v, want %s", test.word, index, ins.Args[index], want)
			}
		}
	}
	for _, word := range []uint32{
		0x0520a028 | (1 << 14),
		0x0520a028 ^ (1 << 21),
	} {
		if ins, ok := decodeARM64RawSVELast(word); ok {
			t.Errorf("decoded reserved LAST %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVELastRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLASTA Z0.D, P8, R0",
		"ZLASTB Z0.D, P0.M, R0",
		"ZLASTAW Z0.S, P0, V0",
		"ZLASTBW Z0.S, P0, RSP",
		"ZLASTAB Z0.B, P0, R0",
		"ZLASTBH Z0.H, P0, R0",
		"ZLASTAS Z0.S, P0, R0",
		"ZLASTBD Z0.D, P0, R0",
		"ZLASTA Z0.Q, P0, R0",
		"ZLASTA.Z Z0.D, P0, R0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvelast(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvelast": {Name: "badsvelast", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE LAST forms", instruction)
			}
		})
	}
}
