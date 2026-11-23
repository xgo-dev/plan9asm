package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ARPLGo386Forms(t *testing.T) {
	// Go's yrl_ml row spans a word register and a word memory destination.
	for _, row := range []struct {
		name, setup, destination string
		modRM                    byte
	}{
		{"register", "MOVL $0xdead8fe0, BX", "BX", 0xc3},
		{"memory", "MOVL p+0(FP), BX", "(BX)", 0x03},
	} {
		t.Run(row.name, func(t *testing.T) {
			const prologue = "TEXT adjust(SB),4,$0-8\nMOVL $0xa5a54213, AX\n"
			const epilogue = "\nJEQ changed\nMOVL $0, ret+4(FP)\nRET\nchanged:\nMOVL $1, ret+4(FP)\nRET\n"
			prefix := prologue + row.setup + "\n"
			named := prefix + "ARPL AX, " + row.destination + epilogue
			raw := prefix + fmt.Sprintf("BYTE $0x63\nBYTE $0x%02x", row.modRM) + epilogue
			goAssemblerOracleOutput(t, "386", named, "", true)
			goAssemblerOracleOutput(t, "amd64", named, "", false)
			options := Options{
				Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
				Sigs: map[string]FuncSig{
					"adjust": {Name: "adjust", Args: []LLVMType{Ptr}, Ret: I32, Frame: FrameLayout{
						Params:  []FrameSlot{{Name: "p", Type: Ptr, Field: -1}},
						Results: []FrameSlot{{Name: "ret", Type: I32, Offset: 4, Field: -1}},
					}},
				},
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			var contents string
			for _, source := range []string{named, raw} {
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatalf("%s: %v", source, err)
				}
				_, body, _ := strings.Cut(ir, "\ntarget triple")
				if contents != "" && contents != body {
					t.Fatal("named and raw forms generated different module contents")
				}
				contents = body
				compileLLVMToObject(t, llc, options.TargetTriple, "selector.ll", "selector.o", ir)
			}
		})
	}
}

func TestX86ARPLRejectsUndefinedInputsAndInvalidMode(t *testing.T) {
	for _, body := range []string{
		"MOVW $3, AX\nARPL AX, BX",
		"MOVW $3, AX\nARPL AX, (BX)",
		"MOVW $3, AX\nMOVL $0x10000, BX\nLOCK\nARPL AX, (BX)",
		"MOVW $3, AX\nMOVW $1, BX\nBYTE $0xf0\nBYTE $0x63\nBYTE $0xc3",
	} {
		t.Run(body, func(t *testing.T) {
			source := "TEXT adjust(SB),4,$0-0\n" + body + "\nRET\n"
			ir, err := x86ScalarFPBitViewAPI(t, source, "func adjust()", "386", "i386-unknown-linux-gnu", "text")
			if ir != "" || err == nil {
				t.Fatalf("invalid instruction generated IR=%t, error=%v", ir != "", err)
			}
		})
	}
	for _, test := range []struct{ arch, body string }{
		{"386", "ARPL $3, AX"}, {"386", "ARPL AL, BX"}, {"386", "ARPL AX, BL"},
		{"amd64", "ARPL AX, BX"},
	} {
		file, err := Parse(ArchAMD64, "TEXT adjust(SB),4,$0-0\n"+test.body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		if ins.Op != "ARPL" {
			t.Fatal("missing ARPL fixture", ins)
		}
		if err := ProbeInstruction(ArchAMD64, test.arch, ins); err == nil || errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s rejected %q without a source diagnostic: %v", test.arch, test.body, err)
		}
	}
	const memory = "TEXT adjust(SB),4,$0-4\nMOVL p+0(FP), BX\nMOVW $3, AX\nARPL AX, (BX)\nRET\n"
	ir, err := x86ScalarFPBitViewAPI(t, memory, "func adjust(p *uint16)", "386", "aarch64-unknown-linux-gnu", "text")
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "native 386 target") {
		t.Fatalf("foreign memory backend generated IR=%t, error=%v", ir != "", err)
	}
}

func TestX86ARPLLogicalFrameWord(t *testing.T) {
	const source = `TEXT ·adjust(SB),4,$0-8
MOVL input+0(FP), AX
MOVL $0xdead8fe0, ret+4(FP)
ARPL AX, ret+4(FP)
RET
`
	const triple = "i386-unknown-linux-gnu"
	goAssemblerOracleOutput(t, "386", source, "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source, "func adjust(input uint32) uint32", "386", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "asm sideeffect") || strings.Count(ir, "store i8 ") != 2 {
		t.Fatal("logical FP write changed more than its two bytes")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arpl-frame.ll", "arpl-frame.o", ir)
}

const x86ARPLRuntimeDecl = `func AdjustReg(input, dst uint32) uint64
func AdjustMem(input uint32, dst *uint16) uint32
`

func x86ARPLRuntimeSource(raw bool) string {
	const setup = `MOVL $0x7fffffff, DX
ADDL $1, DX
MOVL $0xd700, AX
SAHF
MOVL $0, DX
MOVL input+0(FP), AX
MOVL dst+4(FP), BX
`
	const flags = `SETOS DL
LAHF
MOVBLZX AH, CX
SHLL $8, DX
ORL DX, CX
`
	register, memory := "ARPL AX, BX", "ARPL AX, (BX)"
	if raw {
		register, memory = "BYTE $0x63\nBYTE $0xc3", "BYTE $0x63\nBYTE $0x03"
	}
	return "TEXT ·AdjustReg(SB),4,$0-16\n" + setup + register + "\n" + flags +
		"MOVL BX, ret+8(FP)\nMOVL CX, ret+12(FP)\nRET\n" +
		"TEXT ·AdjustMem(SB),4,$0-12\n" + setup + memory + "\n" + flags +
		"MOVL CX, ret+8(FP)\nRET\n"
}

func TestX86ARPLAllPublicAPIs(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			for _, raw := range []bool{false, true} {
				ir, err := x86ScalarFPBitViewAPI(t, x86ARPLRuntimeSource(raw), x86ARPLRuntimeDecl, "386", triple, api)
				if err != nil {
					t.Fatalf("raw=%t: %v", raw, err)
				}
				compileLLVMToObject(t, llc, triple, "arpl.ll", "arpl.o", ir)
			}
		})
	}
}
