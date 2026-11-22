package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestARM64NumericPCAddressUsesOriginalGoInstruction(t *testing.T) {
	for _, row := range []struct {
		op   Op
		word uint32
	}{{"ADR", 0x1000000a}, {"ADRP", 0x9000000a}} {
		for _, offset := range []int{-99, -2, 0, 2, 99} {
			t.Run(fmt.Sprintf("%s/%d", row.op, offset), func(t *testing.T) {
				label := ""
				if offset == 2 {
					label = "addressHere:\n"
				}
				source := fmt.Sprintf("TEXT pcAddress(SB),516,$0-0\nMOVD $1,R7\n%s%s %d(PC),R10\nMOVD $2,R7\nRET\n",
					label, row.op, offset)
				actual := arm64ImmediateOriginalGoBytes(t, source, "linux")
				if len(actual) < 8 || binary.LittleEndian.Uint32(actual[4:8]) != row.word {
					t.Fatalf("original Go numeric PC address does not encode zero displacement: %x", actual)
				}
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				fn, err := normalizeARM64NamedPCRelative(file.Funcs[0])
				if err != nil {
					t.Fatal(err)
				}
				for index, ins := range fn.Instrs {
					if ins.Op != row.op {
						continue
					}
					if index == 0 || fn.Instrs[index-1].Op != OpLABEL ||
						ins.Args[0].Kind != OpIdent || fn.Instrs[index-1].Args[0].Sym != ins.Args[0].Ident {
						t.Fatalf("%q must bind to its own instruction, got %v", ins.Raw, ins.Args[0])
					}
					if label != "" && ins.Args[0].Ident != "addressHere" {
						t.Fatalf("numeric and explicit PC addresses use different labels: %v", ins.Args[0])
					}
					return
				}
				t.Fatal("numeric PC address disappeared")
			})
		}
	}
}

func TestTranslateARM64PCRelativeAddressCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT pcRelativeAddressForms(SB),$0-0
	MOVD R30, R19
	ADR target, R0
	ADRP target, R1
	ADR -2(PC), R2
	ADR 2(PC), R3
	ADRP -2(PC), R29
	ADRP 2(PC), R30
	ADR target, ZR
	ADRP target, ZR
target:
	MOVD R19, R30
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-arm64", triple: "arm64-apple-darwin"},
		{name: "linux-arm64", triple: "aarch64-unknown-linux-gnu"},
		{name: "windows-arm64", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"pcRelativeAddressForms": {Name: "pcRelativeAddressForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, "blockaddress("); got != 8 {
				t.Fatalf("emitted %d block addresses, want 8:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-pc-relative-"+target.name+".ll", "arm64-pc-relative-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64PCRelativeAddressRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"ADR R1, R2",
		"ADR $1, R2",
		"ADR target, RSP",
		"ADR target, V0",
		"ADR target",
		"ADR target, R1, R2",
		"ADRP 0(R1), R2",
		"ADRP.P target, R2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badPCRelativeAddress(SB),$0-0\n\t" + instruction + "\ntarget:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badPCRelativeAddress": {Name: "badPCRelativeAddress", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 ADR/ADRP table", instruction)
			}
		})
	}
}
