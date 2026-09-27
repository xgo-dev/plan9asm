package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86NonTemporalVectorMoveCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses _yvmovntdq for VMOVNTDQ/PD/PS register-to-memory
	// stores and _yvmovntdqa for the inverse aligned memory loads. Both
	// tables cover VEX/EVEX X, Y, and Z widths. The legacy table covers the
	// corresponding X-only forms (with MOVNTO as Go's MOVNTDQ spelling).
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			lastZ := 31
			if target.goarch == "386" {
				lastZ = 7
			}
			var source strings.Builder
			source.WriteString("TEXT nontemporalmoveforms(SB),$0-0\n")
			for index, op := range []string{"VMOVNTDQ", "VMOVNTPD", "VMOVNTPS"} {
				fmt.Fprintf(&source, "\t%s X%d, %d(AX)\n", op, 20+index, index*256)
				fmt.Fprintf(&source, "\t%s Y%d, %d(AX)\n", op, 20+index, index*256+64)
				fmt.Fprintf(&source, "\t%s Z%d, %d(AX)\n", op, lastZ, index*256+128)
			}
			source.WriteString("\tVMOVNTDQA 1024(AX), X20\n")
			source.WriteString("\tVMOVNTDQA 1088(AX), Y21\n")
			fmt.Fprintf(&source, "\tVMOVNTDQA 1152(AX), Z%d\n", lastZ)
			source.WriteString("\tMOVNTO X1, 1216(AX)\n")
			source.WriteString("\tMOVNTPD X2, 1280(AX)\n")
			source.WriteString("\tMOVNTPS X3, 1344(AX)\n")
			source.WriteString("\tMOVNTDQA 1408(AX), X4\n")
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"nontemporalmoveforms": {Name: "nontemporalmoveforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, vectorType := range []string{"<16 x i8>", "<32 x i8>", "<64 x i8>"} {
				if !strings.Contains(ir, "load "+vectorType) || !strings.Contains(ir, "store "+vectorType) {
					t.Fatalf("translation omitted %s load/store forms:\n%s", vectorType, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "non-temporal-move-"+target.name+".ll", "non-temporal-move-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86NonTemporalVectorMoveRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VMOVNTDQ 8(AX), X0"},
		{goarch: "amd64", instruction: "VMOVNTPD X0, X1"},
		{goarch: "amd64", instruction: "VMOVNTPS X0, K1, 8(AX)"},
		{goarch: "amd64", instruction: "VMOVNTDQ.Z Z0, 8(AX)"},
		{goarch: "amd64", instruction: "VMOVNTDQA X0, X1"},
		{goarch: "amd64", instruction: "VMOVNTDQA 8(AX), K1, X0"},
		{goarch: "amd64", instruction: "MOVNTPD 8(AX), X0"},
		{goarch: "amd64", instruction: "MOVNTPS X0, X1"},
		{goarch: "amd64", instruction: "MOVNTDQA X0, 8(AX)"},
		{goarch: "386", instruction: "VMOVNTDQ Z8, 8(AX)"},
		{goarch: "386", instruction: "VMOVNTDQA 8(AX), Z8"},
		{goarch: "386", instruction: "MOVNTO X8, 8(AX)"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
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
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's non-temporal vector-move tables for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestX86RawDecoderRecoversVEXNonTemporalVectorMoveWidths(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		op   Op
		from string
		to   string
	}{
		{name: "vmovntdq x store", code: []byte{0xc5, 0xf9, 0xe7, 0x03}, op: "VMOVNTDQ", from: "X0", to: "0(BX)"},
		{name: "vmovntdq y store", code: []byte{0xc5, 0xfd, 0xe7, 0x03}, op: "VMOVNTDQ", from: "Y0", to: "0(BX)"},
		{name: "vmovntdq y sib store", code: []byte{0xc4, 0xa1, 0x7d, 0xe7, 0x04, 0x03}, op: "VMOVNTDQ", from: "Y0", to: "0(BX)(R8*1)"},
		{name: "vmovntpd x store", code: []byte{0xc5, 0xf9, 0x2b, 0x03}, op: "VMOVNTPD", from: "X0", to: "0(BX)"},
		{name: "vmovntpd y store", code: []byte{0xc5, 0xfd, 0x2b, 0x03}, op: "VMOVNTPD", from: "Y0", to: "0(BX)"},
		{name: "vmovntps x store", code: []byte{0xc5, 0xf8, 0x2b, 0x03}, op: "VMOVNTPS", from: "X0", to: "0(BX)"},
		{name: "vmovntps y store", code: []byte{0xc5, 0xfc, 0x2b, 0x03}, op: "VMOVNTPS", from: "Y0", to: "0(BX)"},
		{name: "vmovntdqa x load", code: []byte{0xc4, 0xe2, 0x79, 0x2a, 0x03}, op: "VMOVNTDQA", from: "0(BX)", to: "X0"},
		{name: "vmovntdqa y load", code: []byte{0xc4, 0xe2, 0x7d, 0x2a, 0x03}, op: "VMOVNTDQA", from: "0(BX)", to: "Y0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != test.op || len(got.Instrs[0].Args) != 2 || got.Instrs[0].Args[0].String() != test.from || got.Instrs[0].Args[1].String() != test.to {
				t.Fatalf("decoded %#x as %#v, want %s %s, %s", test.code, got.Instrs, test.op, test.from, test.to)
			}
		})
	}
}
