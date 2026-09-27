package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86RandomCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		goarch    string
		triple    string
		widths    []string
		registers []string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", widths: []string{"W", "L"}, registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}},
		{goarch: "386", triple: "i686-pc-windows-msvc", widths: []string{"W", "L"}, registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}},
		{goarch: "amd64", triple: "x86_64-apple-darwin", widths: []string{"W", "L", "Q"}, registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", widths: []string{"W", "L", "Q"}, registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc", widths: []string{"W", "L", "Q"}, registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
	} {
		t.Run(target.goarch+"/"+target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT randomforms(SB),$0-0\n")
			for _, family := range []string{"RDRAND", "RDSEED"} {
				for _, width := range target.widths {
					for _, register := range target.registers {
						fmt.Fprintf(&source, "\t%s%s %s\n", family, width, register)
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"randomforms": {Name: "randomforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.x86.rdrand.16()", "@llvm.x86.rdrand.32()",
				"@llvm.x86.rdseed.16()", "@llvm.x86.rdseed.32()",
				`"target-features"="+rdrnd,+rdseed"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("random lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" {
				for _, want := range []string{"@llvm.x86.rdrand.64()", "@llvm.x86.rdseed.64()"} {
					if !strings.Contains(ll, want) {
						t.Fatalf("random lowering omitted %q:\n%s", want, ll)
					}
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "x86-random.ll", "x86-random.o", ll)
		})
	}
}

func TestTranslateX86RandomRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "386", instruction: "RDRANDQ AX"},
		{goarch: "386", instruction: "RDSEEDQ AX"},
		{goarch: "386", instruction: "RDRANDL R8"},
		{goarch: "386", instruction: "RDSEEDW R8"},
		{goarch: "amd64", instruction: "RDRANDB AL"},
		{goarch: "amd64", instruction: "RDSEEDB AL"},
		{goarch: "amd64", instruction: "RDRANDQ 0(AX)"},
		{goarch: "amd64", instruction: "RDSEEDQ 0(AX)"},
		{goarch: "amd64", instruction: "RDRANDQ AX, DX"},
		{goarch: "amd64", instruction: "RDSEEDQ"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT badrandom(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs:         map[string]FuncSig{"badrandom": {Name: "badrandom", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go's RDRAND/RDSEED optab", test.instruction)
			}
		})
	}
}

func TestX86RawDecoderNormalizesCompleteRandomFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want Op
		reg  Reg
	}{
		{name: "rdrand word low", code: []byte{0x66, 0x0f, 0xc7, 0xf2}, want: "RDRANDW", reg: DX},
		{name: "rdrand word extended", code: []byte{0x66, 0x41, 0x0f, 0xc7, 0xf3}, want: "RDRANDW", reg: Reg("R11")},
		{name: "rdrand long low", code: []byte{0x0f, 0xc7, 0xf2}, want: "RDRANDL", reg: DX},
		{name: "rdrand long extended", code: []byte{0x41, 0x0f, 0xc7, 0xf3}, want: "RDRANDL", reg: Reg("R11")},
		{name: "rdrand quad low", code: []byte{0x48, 0x0f, 0xc7, 0xf2}, want: "RDRANDQ", reg: DX},
		{name: "rdrand quad extended", code: []byte{0x49, 0x0f, 0xc7, 0xf3}, want: "RDRANDQ", reg: Reg("R11")},
		{name: "rdseed word low", code: []byte{0x66, 0x0f, 0xc7, 0xfa}, want: "RDSEEDW", reg: DX},
		{name: "rdseed word extended", code: []byte{0x66, 0x41, 0x0f, 0xc7, 0xfb}, want: "RDSEEDW", reg: Reg("R11")},
		{name: "rdseed long low", code: []byte{0x0f, 0xc7, 0xfa}, want: "RDSEEDL", reg: DX},
		{name: "rdseed long extended", code: []byte{0x41, 0x0f, 0xc7, 0xfb}, want: "RDSEEDL", reg: Reg("R11")},
		{name: "rdseed quad low", code: []byte{0x48, 0x0f, 0xc7, 0xfa}, want: "RDSEEDQ", reg: DX},
		{name: "rdseed quad extended", code: []byte{0x49, 0x0f, 0xc7, 0xfb}, want: "RDSEEDQ", reg: Reg("R11")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != test.want || len(got.Instrs[0].Args) != 1 || got.Instrs[0].Args[0].Reg != test.reg {
				t.Fatalf("decoded %#x as %#v, want %s %s", test.code, got.Instrs, test.want, test.reg)
			}
		})
	}
}
