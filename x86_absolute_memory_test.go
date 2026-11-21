package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86AbsoluteMemoryExpressionsThroughPublicAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			addresses := []string{"0x7ffe000c", "(0x7ffe0008+4)", "((0x7ffe0000 | 8)+4)", "((1<<20) + 12)"}
			widths := []string{"B", "W", "L"}
			if target.arch == "amd64" {
				widths = append(widths, "Q")
			}
			var source, declarations strings.Builder
			for _, width := range widths {
				for i, address := range addresses {
					name := fmt.Sprintf("Memory%s%d", width, i)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nMOVL $4,BX\nCLC\n", name)
					fmt.Fprintf(&source, "MOV%s %s,AX\nADC%s %s,BX\nCMP%s %s,$4\nMOV%s BX,%s\nRET\n",
						width, address, width, address, width, address, width, address)
					fmt.Fprintf(&declarations, "func %s()\n", name)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, optimized := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						cases := len(addresses) * len(widths)
						if loads, stores := strings.Count(optimized, "load volatile "), strings.Count(optimized, "store volatile "); loads != 3*cases || stores != cases {
							t.Fatalf("absolute address effects changed: got %d reads and %d writes, want %d and %d", loads, stores, 3*cases, cases)
						}
						x86PackedStringCompileObject(t, llc, target.triple, optimized, "-O2")
					}
				})
			}
		})
	}
}

func TestX86AbsoluteMemoryExpressionsPreserveOtherOperandRoles(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT view(SB),4,$0-0\nMOVL $(0x1000+4),AX\nMOVL 4(AX),BX\nMOVL cell+4(SB),CX\nMOVL (0x1000 + 4),DX\nCMPPD (0x1000 + 4),X0,4\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	var got []Operand
	for _, ins := range file.Funcs[0].Instrs {
		switch ins.Op {
		case "MOVL":
			got = append(got, ins.Args[0])
		case "CMPPD":
			got = append(got, ins.Args[0], ins.Args[2])
		}
	}
	want := []Operand{
		{Kind: OpImm, Imm: 4100},
		{Kind: OpMem, Mem: MemRef{Base: AX, Off: 4}},
		{Kind: OpSym, Sym: "cell+4(SB)"},
		{Kind: OpMem, Mem: MemRef{Off: 4100}},
		{Kind: OpMem, Mem: MemRef{Off: 4100}},
		{Kind: OpSym, Sym: "4"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("operands = %#v, want %#v", got, want)
	}
}

func TestX86AbsoluteMemoryRetainsImmediateStoreAndChecksWidth(t *testing.T) {
	const bytes = "func Store()\n"
	header := "TEXT ·Store(SB),4,$0-0\n"
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := header + "MOVL $0xf1,0xf1\nRET\n"
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, bytes, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(err)
				}
				if result := x86DwordProductIROptimize(t, ir); !strings.Contains(result, "store volatile i32 241, ptr inttoptr (i64 241 to ptr)") {
					t.Fatalf("%s dropped the original volatile store to absolute address 241", api)
				}
				for _, invalid := range []string{"MOVL $1,$0xf1", "MOVL $1,(1<<32)", "MOVL $1,(-2147483648-1)"} {
					program := header + invalid + "\nRET\n"
					if ir, err := x86ScalarFPBitViewAPI(t, program, bytes, target.arch, target.triple, api); err == nil || ir != "" {
						t.Errorf("%s accepted invalid absolute destination %q: %v", api, invalid, err)
					}
				}
			}
		})
	}
}
