package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMRawUndefinedInstructionEncodings(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, word := range []uint32{
		0xe7f000f0, // ARM UDF #0, used by wireguard-go's NEON tail guard.
		0xe7f001f0, // Runtime's GDB-recognized software breakpoint.
		0xe7f123f4, // ARM UDF #0x1234.
		0xe7ffffff, // ARM UDF #0xffff.
		0xf7f000f0, // Permanently undefined in the unconditional encoding space.
		0xf7fabcfd, // Encoding emitted by Go 1.27 for named UNDEF.
		0xf7ffffff, // Another immediate in the unconditional undefined encoding.
		0xff000000, // SVC space with the reserved condition field.
		0xff123456,
		0xffffffff, // Literal from Go's arm.s assembler corpus.
	} {
		t.Run(fmt.Sprintf("%08x", word), func(t *testing.T) {
			src := fmt.Sprintf("TEXT rawundef(SB),NOSPLIT,$0-0\n\tWORD $%#08x\n", word)
			file, err := Parse(ArchARM, src)
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			if form := DescribeInstruction(ArchARM, "arm", instruction).Form; form != "WORD immediate.a32-undefined" {
				t.Fatalf("raw A32 trap must be classified separately from other immediates: %s", form)
			}
			if err := ProbeInstruction(ArchARM, "arm", instruction); err != nil {
				t.Fatal("complete A32 trap form rejected by the single-instruction probe", err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "arm",
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{
					"rawundef": {Name: "rawundef", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{fmt.Sprintf(".inst %#08x", word), "unreachable"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw UNDEF IR missing %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-undef.ll", "arm-raw-undef.o", ir)
		})
	}
}

func TestTranslateARMRawUndefinedRejectsUnrelatedWord(t *testing.T) {
	src := "TEXT rawunknown(SB),NOSPLIT,$0-0\n\tWORD $0xaaaaaaaa\n\tRET\n"
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{
			"rawunknown": {Name: "rawunknown", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate unexpectedly accepted an unrelated ARM WORD")
	}
}

func TestTranslateARMRawUndefinedRequiresA32Target(t *testing.T) {
	const source = "TEXT conversion(SB),NOSPLIT,$0-0\nWORD $0xe7f001f0\n"
	for _, triple := range []string{"thumbv7-unknown-linux-gnueabihf", "armv7-pc-windows-msvc", "wasm32-unknown-unknown"} {
		for _, api := range []string{"text", "module", "Go"} {
			if err := armWordFloatBoundaryAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s changed the raw A32 trap's instruction state on %s: %v", api, triple, err)
			}
		}
	}
}

func TestARMRawUndefinedEncodingDoesNotMatchNeighbors(t *testing.T) {
	for _, word := range []uint32{0x07f000f0, 0xe7f000e0, 0xf7f000e0, 0xfe010f10, 0xef123456} {
		ins := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		if form := DescribeInstruction(ArchARM, "arm", ins).Form; form != "WORD immediate" {
			t.Fatalf("neighboring word %#08x was classified as %s", word, form)
		}
		decoded, err := decodeARMRawWordInstruction(ins)
		if err == nil && decoded.Op == "UNDEF" {
			t.Fatalf("neighboring word %#08x gained an unconditional trap", word)
		}
	}
}

func TestTranslateARMRawFPSCRTransferPair(t *testing.T) {
	src := `TEXT fpscr(SB),NOSPLIT,$0-0
	WORD $0xeef1ba10
	BIC $(1<<24), R11
	WORD $0xeee1ba10
	RET
`
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{
			Goarch:       "arm",
			TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"fpscr": {Name: "fpscr", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{`vmrs $0, fpscr`, `vmsr fpscr, $0`} {
			if !strings.Contains(ir, want) {
				t.Fatalf("%s raw FPSCR IR missing %q:\n%s", triple, want, ir)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm-raw-fpscr.ll", "arm-raw-fpscr.o", ir)
	}
}

func TestTranslateARMRawYieldHint(t *testing.T) {
	src := "TEXT yieldhint(SB),NOSPLIT,$0-0\n\tWORD $0xe320f001\n\tRET\n"
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{
			Goarch:       "arm",
			TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"yieldhint": {Name: "yieldhint", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		if !strings.Contains(ir, `.long 0xe320f001`) {
			t.Fatalf("%s raw YIELD encoding was not preserved:\n%s", triple, ir)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm-raw-yield.ll", "arm-raw-yield.o", ir)
	}
}
