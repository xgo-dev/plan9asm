package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestSynthesizeEncoderLines(t *testing.T) {
	// x86 dual reg/mem expansion
	x86Lines := synthesizeEncoderLines("amd64", encoderFormReport{
		Opcode:         "VADDPS",
		OperandClasses: []string{"Yxm", "Yxr", "Yxr"},
	})
	if len(x86Lines) != 2 || x86Lines[0] != "VADDPS X0, X1, X2" || x86Lines[1] != "VADDPS 8(BX), X1, X2" {
		t.Fatalf("x86 VADDPS lines = %#v", x86Lines)
	}

	// x86 special and system operand classes
	for _, tc := range []struct {
		row  encoderFormReport
		want string
	}{
		{encoderFormReport{Opcode: "ADJSP", OperandClasses: []string{"@special"}}, "ADJSP $8"},
		{encoderFormReport{Opcode: "ENTER", OperandClasses: []string{"@special"}}, "ENTER $8, $0"},
		{encoderFormReport{Opcode: "FFREE", OperandClasses: []string{"@special"}}, "FFREE F0"},
		{encoderFormReport{Opcode: "RET"}, "RET"},
		{encoderFormReport{Opcode: "MOVQ", OperandClasses: []string{"Ycr0", "Yrl"}}, "MOVQ CR0, BX"},
		{encoderFormReport{Opcode: "MOVQ", OperandClasses: []string{"Ydr2", "Yrl"}}, "MOVQ DR2, BX"},
		{encoderFormReport{Opcode: "MOVL", OperandClasses: []string{"Ytr6", "Yrl"}}, "MOVL TR6, BX"},
		{encoderFormReport{Opcode: "MOVW", OperandClasses: []string{"Yfs", "Yrl"}}, "MOVW FS, BX"},
		{encoderFormReport{Opcode: "MOVW", OperandClasses: []string{"Yldtr", "Yrl"}}, "MOVW LDTR, BX"},
		{encoderFormReport{Opcode: "VGATHERDPS", OperandClasses: []string{"Yzvm", "Yknot0", "Yzr"}}, "VGATHERDPS (BX)(Z0*4), K2, Z2"},
		{encoderFormReport{Opcode: "MOVQ", OperandClasses: []string{"Ytls", "Yrl"}}, "MOVQ 0(TLS), BX"},
		{encoderFormReport{Opcode: "MOVQ", OperandClasses: []string{"Yiauto", "Yrl"}}, "MOVQ $a+0(FP), BX"},
		{encoderFormReport{Opcode: "CALL", OperandClasses: []string{"Yindir"}}, "CALL AX"},
		{encoderFormReport{Opcode: "JMP", OperandClasses: []string{"Ybr"}}, "JMP target"},
	} {
		got := synthesizeEncoderLines("amd64", tc.row)
		if len(got) == 0 || got[0] != tc.want {
			t.Errorf("x86 %s -> %#v, want %q", tc.row.Opcode, got, tc.want)
		}
	}
	if got := synthesizeEncoderLines("amd64", encoderFormReport{Opcode: "END"}); len(got) != 0 {
		t.Fatalf("END should synthesize 0 lines, got %#v", got)
	}
	if got := synthesizeEncoderLines("amd64", encoderFormReport{Opcode: "TEXT", OperandClasses: []string{"Ytextsize"}}); len(got) != 0 {
		t.Fatalf("Ytextsize should synthesize 0 lines, got %#v", got)
	}

	// arm
	if got := synthesizeEncoderLines("arm", encoderFormReport{
		Opcode:         "ADD",
		OperandClasses: []string{"from=C_SHIFT", "reg=C_REG", "to=C_REG"},
	}); len(got) != 1 || got[0] != "ADD R1<<1, R1, R2" {
		t.Fatalf("arm ADD lines = %#v", got)
	}
	for _, cls := range []string{
		"C_REG", "C_FREG", "C_RCON", "C_SFCON", "C_SHIFT", "C_SHIFTADDR",
		"C_SOREG", "C_SAUTO", "C_ADDR", "C_LACON", "C_REGLIST", "C_REGREG",
		"C_REGREG2", "C_SBRA", "C_PSR", "C_FCR",
	} {
		if arg, ok := synthARMOperand(cls, 1); !ok || arg == "" {
			t.Errorf("synthARMOperand(%s) = (%q, %v)", cls, arg, ok)
		}
	}

	// arm64 optab + inst_gen
	if got := synthesizeEncoderLines("arm64", encoderFormReport{
		Opcode:         "MADD",
		OperandClasses: []string{"from=C_ZREG", "reg=C_ZREG", "from3=C_ZREG", "to=C_ZREG"},
	}); len(got) != 1 || got[0] != "MADD R0, R1, R2, R3" {
		t.Fatalf("arm64 MADD lines = %#v", got)
	}
	if got := synthesizeEncoderLines("arm64", encoderFormReport{
		Opcode:         "ADD",
		OperandClasses: []string{"from=C_REG", "to=C_REG", "to2=1"},
	}); len(got) != 1 || got[0] != "ADD R0, R1" {
		t.Fatalf("arm64 Go 1.20/1.21 numeric to2 lines = %#v", got)
	}
	if got := synthesizeEncoderLines("arm64", encoderFormReport{
		Opcode:         "ZADD",
		OperandClasses: []string{"args=Zm_T__Zdn_T__PgM__Zdn_T__1"},
	}); len(got) != 1 || !strings.HasPrefix(got[0], "ZADD Z0.S, Z1.S, P0.M, Z2.S") {
		t.Fatalf("arm64 ZADD lines = %#v", got)
	}
	if got := synthesizeEncoderLines("arm64", encoderFormReport{
		Opcode:         "ZBFDOT",
		OperandClasses: []string{"args=Zm_H_imm___Zn_H__Zda_S__3"},
	}); len(got) != 1 || got[0] != "ZBFDOT Z0.H[0], Z1.H, Z2.S" {
		t.Fatalf("arm64 ZBFDOT lines = %#v", got)
	}

	// wasm
	for _, tc := range []struct {
		op, want string
	}{
		{"I32ADD", "I32ADD"},
		{"I64CONST", "I64CONST $1"},
		{"F64CONST", "F64CONST $1.0"},
		{"V128CONST", "V128CONST $0, $0"},
		{"GET", "GET R0"},
		{"BR", "BR 0"},
		{"CALL", "CALL sym(SB)"},
		{"MOVD", "MOVD R0, R1"},
		{"I64LOAD", "I64LOAD $0"},
		{"MEMORYGROW", "MEMORYGROW $0"},
	} {
		got := synthesizeEncoderLines("wasm", encoderFormReport{Opcode: tc.op})
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("wasm %s -> %#v, want %q", tc.op, got, tc.want)
		}
	}
}

func TestScanEncoderSynthesizedAllArches(t *testing.T) {
	goroot := runtime.GOROOT()
	for _, tc := range []struct {
		goarch   string
		arch     plan9asm.Arch
		minForms int
	}{
		{"386", plan9asm.ArchAMD64, 1500},
		{"amd64", plan9asm.ArchAMD64, 1500},
		{"arm", plan9asm.ArchARM, 200},
		{"arm64", plan9asm.ArchARM64, 500},
		{"wasm", plan9asm.ArchWASM, 200},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			ops, forms, parseErrs, tables, catalog, err := scanEncoderSynthesized(goroot, tc.arch, tc.goarch)
			if err != nil {
				t.Fatalf("scanEncoderSynthesized(%s): %v", tc.goarch, err)
			}
			if len(catalog) == 0 || tables == 0 || len(ops) == 0 || len(forms) < tc.minForms {
				t.Fatalf("%s: catalog=%d tables=%d ops=%d forms=%d (want >=%d)",
					tc.goarch, len(catalog), tables, len(ops), len(forms), tc.minForms)
			}
			if len(parseErrs) > 0 {
				limit := len(parseErrs)
				if limit > 10 {
					limit = 10
				}
				t.Fatalf("%s: %d parse errors (first %d): %#v", tc.goarch, len(parseErrs), limit, parseErrs[:limit])
			}
		})
	}
}
