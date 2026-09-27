package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawLegacyScalarSourceLocalRIPData(t *testing.T) {
	for _, op := range []string{
		"MOVD", "UCOMISD", "UCOMISS", "COMISD", "COMISS",
		"CMPSS", "CMPSD",
		"ADDSS", "ADDSD", "SUBSS", "SUBSD", "MULSS", "MULSD",
		"DIVSS", "DIVSD", "MINSS", "MINSD", "MAXSS", "MAXSD",
		"SQRTSS", "SQRTSD",
	} {
		for _, destination := range []string{"X0", "X10"} {
			t.Run(op+"/"+destination, func(t *testing.T) {
				instruction := op + " pool(SB), " + destination
				if op == "CMPSS" || op == "CMPSD" {
					instruction += ", $1"
				}
				code := assembleX87ControlBytes(t, "amd64",
					"TEXT scalarRIP(SB),4,$0-0\n\t"+instruction+"\n\tRET\n")
				inst, err := x86asm.Decode(code, 64)
				if err != nil || inst.PCRel != 4 || inst.MemBytes <= 0 || inst.Len >= len(code) {
					t.Fatalf("Go assembler %s %s: %x, decode %+v, %v", op, destination, code, inst, err)
				}
				binary.LittleEndian.PutUint32(code[inst.PCRelOff:], 1)
				for value := 0; value < inst.MemBytes; value++ {
					code = append(code, byte(value))
				}
				decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "scalar RIP", map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded) != 2 || len(decoded[0].x86RIPLiteralData) != inst.MemBytes {
					t.Fatalf("%s %s decoded as %#v", op, destination, decoded)
				}
			})
		}
	}
}

func TestX86RawMOVD32PreservesPhysicalWidth(t *testing.T) {
	const source = "TEXT movd32(SB),4,$0-0\n\tMOVL pool(SB), X0\n\tRET\n"
	code := assembleX87ControlBytes(t, "amd64", source)
	physical, err := x86asm.Decode(code, 64)
	if err != nil || physical.Op != x86asm.MOVD || physical.MemBytes != 4 {
		t.Fatalf("Go MOVL to X0 encoding: %x, %+v, %v", code, physical, err)
	}
	binary.LittleEndian.PutUint32(code[physical.PCRelOff:], 1)
	code = append(code, 1, 2, 3, 4)
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "MOVD32 literal", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "MOVL" ||
		len(decoded[0].x86RIPLiteralData) != 4 {
		t.Fatalf("MOVD32 decoded as %#v", decoded)
	}
	var raw strings.Builder
	raw.WriteString("TEXT rawMovd32(SB),4,$0-0\n")
	for _, value := range code {
		fmt.Fprintf(&raw, "\tBYTE $0x%02x\n", value)
	}
	file, err := Parse(ArchAMD64, raw.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawMovd32": {Name: "rawMovd32", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "load i32, ptr") {
				t.Fatal("physical MOVD32 did not load exactly 32 bits")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "raw-movd32.ll", "raw-movd32.o", ir)
		})
	}
}
