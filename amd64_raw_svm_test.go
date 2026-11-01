package plan9asm

import (
	"strings"
	"testing"
)

func TestX86RawDecoderCompleteAMDSystemManagementFamily(t *testing.T) {
	family := []struct {
		opcode byte
		op     Op
	}{
		{opcode: 0xd8, op: "VMRUN"},
		{opcode: 0xd9, op: "VMMCALL"},
		{opcode: 0xda, op: "VMLOAD"},
		{opcode: 0xdb, op: "VMSAVE"},
		{opcode: 0xdc, op: "STGI"},
		{opcode: 0xdd, op: "CLGI"},
		{opcode: 0xde, op: "SKINIT"},
		{opcode: 0xdf, op: "INVLPGA"},
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, test := range family {
			t.Run(goarch+"/"+string(test.op), func(t *testing.T) {
				fn := Func{Instrs: []Instr{
					{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: 0x0f}}},
					{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: 0x01}}},
					{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(test.opcode)}}},
				}}
				got, err := decodeX86RawDirectives(fn, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != test.op || len(got.Instrs[0].Args) != 0 {
					t.Fatalf("decoded 0f 01 %02x as %#v, want one operand-free %s", test.opcode, got.Instrs, test.op)
				}
			})
		}
	}
}

func TestTranslateX86RawAMDSystemManagementFamilyAllTargets(t *testing.T) {
	const source = `TEXT svmfamily(SB),$0-0
	BYTE $0x0f; BYTE $0x01; BYTE $0xd8 // VMRUN
	BYTE $0x0f; BYTE $0x01; BYTE $0xd9 // VMMCALL
	BYTE $0x0f; BYTE $0x01; BYTE $0xda // VMLOAD
	BYTE $0x0f; BYTE $0x01; BYTE $0xdb // VMSAVE
	BYTE $0x0f; BYTE $0x01; BYTE $0xdc // STGI
	BYTE $0x0f; BYTE $0x01; BYTE $0xdd // CLGI
	BYTE $0x0f; BYTE $0x01; BYTE $0xde // SKINIT
	BYTE $0x0f; BYTE $0x01; BYTE $0xdf // INVLPGA
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
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
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"svmfamily": {Name: "svmfamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"vmrun", "vmmcall", "vmload", "vmsave", "stgi", "clgi", "skinit", "invlpga"} {
				if !strings.Contains(ll, `asm sideeffect "`+op+`"`) {
					t.Fatalf("translated IR does not retain %s:\n%s", op, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-svm-family-"+target.name+".ll", "raw-svm-family-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86AMDSystemManagementFamilyRejectsOperands(t *testing.T) {
	for _, op := range []string{"VMRUN", "VMMCALL", "VMLOAD", "VMSAVE", "STGI", "CLGI", "SKINIT", "INVLPGA"} {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+op+" AX\n")
		if err != nil {
			t.Fatalf("Parse(%s AX) error = %v", op, err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted operand form for fixed no-operand %s", op)
		}
	}
}
