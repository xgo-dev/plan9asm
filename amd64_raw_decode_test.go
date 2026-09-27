package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestAMD64RawDirectiveSequenceUsesSemanticLowering(t *testing.T) {
	source := `TEXT rawLoad(SB), NOSPLIT, $256-0
	MOVQ $0, R11
	BYTE $0x4e
	BYTE $0x0f
	BYTE $0xb7
	BYTE $0x7c
	BYTE $0x5c
	BYTE $0x78
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawLoad": {Name: "rawLoad", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if strings.Contains(ir, "module asm") {
		t.Fatalf("raw instructions bypassed semantic lowering:\n%s", ir)
	}
	if !strings.Contains(ir, "load i16") || !strings.Contains(ir, "zext i16") {
		t.Fatalf("decoded MOVWQZX semantics missing:\n%s", ir)
	}
}

func TestX86RawOnlyFunctionUsesSemanticLowering(t *testing.T) {
	for _, test := range []struct {
		name   string
		goarch string
		triple string
		source string
	}{
		{
			name:   "amd64",
			goarch: "amd64",
			triple: "x86_64-unknown-linux-gnu",
			source: "TEXT raw(SB), NOSPLIT, $0-0\nBYTE $0x90\nBYTE $0xc3\n",
		},
		{
			name:   "386",
			goarch: "386",
			triple: "i386-unknown-linux-gnu",
			source: "TEXT raw(SB), NOSPLIT, $0-0\nBYTE $0x90\nBYTE $0xc3\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, test.source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			ir, err := Translate(file, Options{
				Goarch:       test.goarch,
				TargetTriple: test.triple,
				Sigs: map[string]FuncSig{
					"raw": {Name: "raw", Ret: Void},
				},
			})
			if err != nil {
				t.Fatalf("Translate() error = %v", err)
			}
			if strings.Contains(ir, "module asm") {
				t.Fatalf("raw-only function bypassed instruction validation:\n%s", ir)
			}
			if !strings.Contains(ir, "define void @raw()") || !strings.Contains(ir, "ret void") {
				t.Fatalf("semantic function body missing:\n%s", ir)
			}
		})
	}
}

func TestX86RawPCRelativeInstructionOutsideDirectiveGroupFailsClosed(t *testing.T) {
	source := `TEXT rawBranch(SB), NOSPLIT, $0-0
	MOVQ $0, AX
	BYTE $0xeb
	BYTE $0x7f
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	_, err = Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawBranch": {Name: "rawBranch", Ret: Void},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "PC-relative") {
		t.Fatalf("Translate() error = %v, want explicit PC-relative raw-instruction rejection", err)
	}
}

func TestX86RawInternalConditionalBranchCompleteFamily(t *testing.T) {
	targets := []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	}
	forms := []struct {
		name  string
		bytes func(condition byte) []byte
	}{
		{name: "short_forward", bytes: func(condition byte) []byte {
			return []byte{0x70 + condition, 0x01, 0x90, 0xc3}
		}},
		{name: "short_backward", bytes: func(condition byte) []byte {
			return []byte{0x90, 0x70 + condition, 0xfd, 0xc3}
		}},
		{name: "near_forward", bytes: func(condition byte) []byte {
			return []byte{0x0f, 0x80 + condition, 0x01, 0, 0, 0, 0x90, 0xc3}
		}},
		{name: "near_backward", bytes: func(condition byte) []byte {
			return []byte{0x90, 0x0f, 0x80 + condition, 0xf9, 0xff, 0xff, 0xff, 0xc3}
		}},
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.goarch, func(t *testing.T) {
			var source strings.Builder
			sigs := make(map[string]FuncSig)
			for condition := byte(0); condition < 16; condition++ {
				for _, form := range forms {
					name := fmt.Sprintf("rawJcc_%02x_%s", condition, form.name)
					fmt.Fprintf(&source, "TEXT %s(SB), NOSPLIT, $0-0\n", name)
					for _, value := range form.bytes(condition) {
						fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
					}
					sigs[name] = FuncSig{Name: name, Ret: Void}
				}
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "raw_jcc") {
				t.Fatalf("synthetic raw branch labels missing:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-jcc-"+target.goarch+".ll", "raw-jcc-"+target.goarch+".o", ir)
		})
	}
}

func TestX86RawMULXReportedEncoding(t *testing.T) {
	const source = `TEXT rawMULX(SB), NOSPLIT, $0-0
	BYTE $0xc4
	BYTE $0x42
	BYTE $0xe3
	BYTE $0xf6
	BYTE $0xf6
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawMULX": {Name: "rawMULX", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-mulx.ll", "raw-mulx.o", ir)
}

func TestX86RawMULXCompleteGoAssemblerForms(t *testing.T) {
	// Go's x86 table defines both register and Yml memory sources for MULXL
	// and (on amd64) MULXQ. Exercise both widths plus direct, SIB, disp8 and
	// base-less disp32 ModRM forms, including extended registers.
	targets := []struct {
		goarch string
		triple string
		forms  [][]byte
	}{
		{
			goarch: "amd64",
			triple: "x86_64-unknown-linux-gnu",
			forms: [][]byte{
				{0xc4, 0x42, 0xe3, 0xf6, 0xf6},                               // MULXQ R14, BX, R14
				{0xc4, 0x42, 0x3b, 0xf6, 0xfe},                               // MULXL R14, R8, R15
				{0xc4, 0x22, 0xab, 0xf6, 0x5c, 0x88, 0x10},                   // MULXQ 16(AX)(R9*4), R10, R11
				{0xc4, 0xe2, 0x6b, 0xf6, 0x5c, 0x48, 0x08},                   // MULXL 8(AX)(CX*2), DX, BX
				{0xc4, 0xe2, 0xfb, 0xf6, 0x0c, 0x25, 0x78, 0x56, 0x34, 0x12}, // MULXQ 0x12345678, AX, CX
			},
		},
		{
			goarch: "386",
			triple: "i386-unknown-linux-gnu",
			forms: [][]byte{
				{0xc4, 0xe2, 0x73, 0xf6, 0xd0},                         // MULXL AX, CX, DX
				{0xc4, 0xe2, 0x6b, 0xf6, 0x5c, 0x48, 0x08},             // MULXL 8(AX)(CX*2), DX, BX
				{0xc4, 0xe2, 0x7b, 0xf6, 0x0d, 0x78, 0x56, 0x34, 0x12}, // MULXL 0x12345678, AX, CX
			},
		},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.goarch, func(t *testing.T) {
			var source strings.Builder
			sigs := make(map[string]FuncSig)
			for i, encoding := range target.forms {
				name := fmt.Sprintf("rawMULX_%d", i)
				fmt.Fprintf(&source, "TEXT %s(SB), NOSPLIT, $0-0\n", name)
				for _, value := range encoding {
					fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
				}
				source.WriteString("\tRET\n")
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-mulx-forms.ll", "raw-mulx-forms.o", ir)
		})
	}
}

func TestX86RawMULXRejectsLayoutDependentAddressForms(t *testing.T) {
	tests := []struct {
		name     string
		encoding []byte
	}{
		{name: "address_size_override", encoding: []byte{0x67, 0xc4, 0xe2, 0x6b, 0xf6, 0x5c, 0x48, 0x08}},
		{name: "rip_relative", encoding: []byte{0xc4, 0xe2, 0xfb, 0xf6, 0x0d, 0, 0, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawMULX(SB), NOSPLIT, $0-0\n")
			for _, value := range test.encoding {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawMULX": {Name: "rawMULX", Ret: Void}}})
			if err == nil || !strings.Contains(err.Error(), "source-layout safe") {
				t.Fatalf("Translate() error = %v, want source-layout safety rejection", err)
			}
		})
	}
}

func TestX86RawForwardJumpSkipsEmbeddedDataButStillLowersReachableCode(t *testing.T) {
	const source = `TEXT rawSignature(SB), NOSPLIT, $0-0
	BYTE $0xeb
	BYTE $0x04
	LONG $0xe77da1c4
	BYTE $0xc3
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawSignature": {Name: "rawSignature", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "module asm") || !strings.Contains(ir, "ret void") {
		t.Fatalf("reachable raw control flow was not lowered semantically:\n%s", ir)
	}
}

func encodeX86RawRetpoline(register int) []byte {
	return []byte{0xe8, 0x04, 0, 0, 0, 0xf3, 0x90, 0xeb, 0xfc, byte(0x48 | (register&8)>>1), 0x89, byte(0x04 | (register&7)<<3), 0x24, 0xc3}
}

func TestX86RawRetpolineFamilyLowersToIndirectTailCalls(t *testing.T) {
	names := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for register, name := range names {
		if register == 4 {
			continue
		}
		function := "retpoline" + name
		fmt.Fprintf(&source, "TEXT %s(SB),NOSPLIT,$0-0\n", function)
		for _, value := range encodeX86RawRetpoline(register) {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[function] = FuncSig{Name: function, Ret: Void}
		if got, ok := x86RawRetpolineTarget(encodeX86RawRetpoline(register)); !ok || got != Reg(name) {
			t.Fatalf("decoded retpoline register %d as %s, ok=%v", register, got, ok)
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "module asm") || !strings.Contains(ir, "call i64 %") || !strings.Contains(ir, "ret void") {
		t.Fatalf("raw retpolines were not lowered as semantic indirect tail calls:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-retpoline.ll", "amd64-raw-retpoline.o", ir)
}

func TestX86RawRetpolineDecoderRejectsNearMisses(t *testing.T) {
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13} {
		nearMiss := append([]byte(nil), encodeX86RawRetpoline(0)...)
		nearMiss[offset] ^= 1
		if _, ok := x86RawRetpolineTarget(nearMiss); ok {
			t.Fatalf("retpoline decoder accepted byte %d near miss %#v", offset, nearMiss)
		}
	}
	if _, ok := x86RawRetpolineTarget(encodeX86RawRetpoline(4)); ok {
		t.Fatal("retpoline decoder accepted impossible SP target")
	}
}
