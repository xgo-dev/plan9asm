package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86NativeDisp32Go386SpellingEquivalence(t *testing.T) {
	for _, operation := range []string{"MOVL %s,AX", "ADDL %s,AX"} {
		for _, address := range []string{"%d(AX)", "%d(AX)(CX*4)"} {
			for _, offset := range []int64{1 << 31, 1<<32 - 1} {
				assemble := func(displacement int64) []byte {
					instruction := fmt.Sprintf(operation, fmt.Sprintf(address, displacement))
					return x86OrderingHintGoBytes(t, "386", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
				}
				positive := assemble(offset)
				signed := assemble(int64(int32(offset)))
				if !bytes.Equal(positive, signed) {
					t.Fatalf("%s %s %d produced different 386 addresses: %x and %x", operation, address, offset, positive, signed)
				}
			}
		}
	}
}

func TestX86NativeDisp32Go386PointerRolesAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	rows := []struct {
		name, instructions string
	}{
		{"load", "MOVL ADDR,AX"},
		{"store", "MOVL BX,ADDR"},
		{"arithmetic", "ADCL ADDR,BX"},
		{"compare", "CMPL ADDR,$1"},
		{"conditional-store", "SETCC ADDR"},
		{"shift", "SHLL $1,ADDR"},
		{"packed", "MOVOU ADDR,X0"},
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range rows {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				var source, declarations strings.Builder
				for i, address := range []string{
					"-2147483648(AX)", "2147483647(AX)", "2147483648(AX)", "4294967295(AX)",
					"-2147483648(AX)(CX*4)", "2147483648(AX)(CX*4)", "4294967295(AX)(CX*4)",
				} {
					name := fmt.Sprintf("Address%d", i)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nMOVL p+0(FP),AX\nMOVL $3,CX\nMOVL $4,BX\nCLC\n%s\nRET\n",
						name, strings.ReplaceAll(row.instructions, "ADDR", address))
					fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Errorf("%s rejected a Go 386 disp32 address: %v", api, err)
						continue
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				}
			})
		}
	}
}

func TestX86NativeDisp32RespectsModeAndPointerInputs(t *testing.T) {
	for _, row := range []struct {
		arch, triple, move string
		word               int
		offsets            []int64
	}{
		{"386", "i386-unknown-linux-gnu", "MOVL", 4, []int64{-1<<31 - 1, 1 << 32}},
		{"amd64", "x86_64-unknown-linux-gnu", "MOVQ", 8, []int64{-1<<31 - 1, 1 << 31, 1<<32 - 1}},
	} {
		header := fmt.Sprintf("TEXT ·Read(SB),4,$0-%d\n", row.word)
		for _, offset := range row.offsets {
			t.Run(fmt.Sprintf("%s/%d", row.arch, offset), func(t *testing.T) {
				source := header + fmt.Sprintf("%s p+0(FP),AX\nMOVL %d(AX),BX\nRET\n", row.move, offset)
				goAssemblerOracleOutput(t, row.arch, source, "", false)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Read(p *byte)\n", row.arch, row.triple, api); err == nil || ir != "" {
						t.Errorf("%s accepted an out-of-mode displacement: %v", api, err)
					}
				}
			})
		}
	}
	const unbound = "TEXT ·Read(SB),4,$0-4\nMOVL 2147483648(AX),BX\nRET\n"
	goAssemblerOracleOutput(t, "386", unbound, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, unbound, "func Read(p *byte)\n", "386", "i386-unknown-linux-gnu", api)
		if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Errorf("%s changed the obligation for a reaching base register: %v", api, err)
		}
	}
}
