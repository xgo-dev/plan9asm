package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86RawBLSMSKReportedEncoding(t *testing.T) {
	const source = `TEXT rawBLSMSK(SB), NOSPLIT, $0-0
	BYTE $0xc4
	BYTE $0xe2
	BYTE $0x88
	BYTE $0xf3
	BYTE $0xd2
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawBLSMSK": {Name: "rawBLSMSK", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, `"target-features"="+bmi"`) {
		t.Fatalf("raw BLSMSK did not infer BMI1 target feature:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-blsmsk-reported.ll", "raw-blsmsk-reported.o", ir)
}

func TestTranslateX86BLSCompleteGoAssemblerForms(t *testing.T) {
	registers386 := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
	registersAMD64 := append(append([]string{}, registers386...), "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	targets := []struct {
		name      string
		goarch    string
		triple    string
		widths    []string
		registers []string
	}{
		{name: "386-linux", goarch: "386", triple: "i386-unknown-linux-gnu", widths: []string{"L", "Q"}, registers: registers386},
		{name: "386-windows", goarch: "386", triple: "i686-pc-windows-msvc", widths: []string{"L", "Q"}, registers: registers386},
		{name: "amd64-darwin", goarch: "amd64", triple: "x86_64-apple-darwin", widths: []string{"L", "Q"}, registers: registersAMD64},
		{name: "amd64-linux", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", widths: []string{"L", "Q"}, registers: registersAMD64},
		{name: "amd64-windows", goarch: "amd64", triple: "x86_64-pc-windows-msvc", widths: []string{"L", "Q"}, registers: registersAMD64},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT blsforms(SB),$0-0\n")
			for _, family := range []string{"BLSI", "BLSMSK", "BLSR"} {
				for _, width := range target.widths {
					op := family + width
					for index, register := range target.registers {
						other := target.registers[(index+5)%len(target.registers)]
						fmt.Fprintf(&source, "\t%s %s, %s\n", op, register, other)
						fmt.Fprintf(&source, "\t%s %s, %s\n", op, other, register)
					}
					fmt.Fprintf(&source, "\t%s 8(AX), DX\n", op)
					fmt.Fprintf(&source, "\t%s 16(AX)(CX*4), BX\n", op)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"blsforms": {Name: "blsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+bmi"`) {
				t.Fatalf("BLS family did not infer BMI1 target feature:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "bls-family.ll", "bls-family.o", ir)
		})
	}
}

func TestTranslateX86BLSRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "386", instruction: "BLSIL R8, AX"},
		{goarch: "386", instruction: "BLSIQ R8, AX"},
		{goarch: "386", instruction: "BLSIL AX, R8"},
		{goarch: "386", instruction: "BLSIQ AX, R8"},
		{goarch: "amd64", instruction: "BLSIW AX, DX"},
		{goarch: "amd64", instruction: "BLSIL AL, DX"},
		{goarch: "amd64", instruction: "BLSIL X0, DX"},
		{goarch: "amd64", instruction: "BLSIL $1, DX"},
		{goarch: "amd64", instruction: "BLSIL AX, 0(DX)"},
		{goarch: "amd64", instruction: "BLSIL AX"},
		{goarch: "amd64", instruction: "BLSIL AX, DX, BX"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
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
			if _, err := Translate(file, Options{Goarch: test.goarch, TargetTriple: triple, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yblsil table", test.instruction)
			}
		})
	}
}

func TestX86RawBLSCompleteRegisterFields(t *testing.T) {
	families := []struct {
		digit byte
		name  string
	}{
		{digit: 1, name: "BLSR"},
		{digit: 2, name: "BLSMSK"},
		{digit: 3, name: "BLSI"},
	}
	for _, mode := range []int{32, 64} {
		registerCount := 8
		widths := []bool{false, true}
		if mode == 64 {
			registerCount = 16
		}
		for _, family := range families {
			for _, width64 := range widths {
				for destinationNumber := 0; destinationNumber < registerCount; destinationNumber++ {
					for sourceNumber := 0; sourceNumber < registerCount; sourceNumber++ {
						vex1 := byte(0xe2)
						if sourceNumber >= 8 {
							vex1 &^= 0x20
						}
						vex2 := byte((^destinationNumber & 15) << 3)
						if width64 {
							vex2 |= 0x80
						}
						modRM := byte(0xc0 | int(family.digit)<<3 | sourceNumber&7)
						code := []byte{0xc4, vex1, vex2, 0xf3, modRM}
						instruction, length, ok, err := decodedX86BLSInstruction(code, mode)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("mode=%d %x: instruction=%#v length=%d ok=%v err=%v", mode, code, instruction, length, ok, err)
						}
						width := "L"
						if width64 && mode == 64 {
							width = "Q"
						}
						source, _ := decodedX86GeneralRegister(sourceNumber)
						destination, _ := decodedX86GeneralRegister(destinationNumber)
						if instruction.Op != Op(family.name+width) || len(instruction.Args) != 2 || instruction.Args[0].Reg != source || instruction.Args[1].Reg != destination {
							t.Fatalf("mode=%d %x decoded as %#v, want %s%s %s, %s", mode, code, instruction, family.name, width, source, destination)
						}
					}
				}
			}
		}
	}
}

func TestX86RawBLSCompleteMemoryFormsAndTargets(t *testing.T) {
	targets := []struct {
		name      string
		goarch    string
		triple    string
		encodings [][]byte
	}{
		{
			name: "386-linux", goarch: "386", triple: "i386-unknown-linux-gnu",
			encodings: [][]byte{
				{0xc4, 0xe2, 0x70, 0xf3, 0x18},                         // BLSIL 0(AX), CX
				{0xc4, 0xe2, 0x68, 0xf3, 0x54, 0x48, 0x08},             // BLSMSKL 8(AX)(CX*2), DX
				{0xc4, 0xe2, 0x60, 0xf3, 0x0d, 0x78, 0x56, 0x34, 0x12}, // BLSRL 0x12345678, BX
			},
		},
		{
			name: "386-windows", goarch: "386", triple: "i686-pc-windows-msvc",
			encodings: [][]byte{
				{0xc4, 0xe2, 0x70, 0xf3, 0x18},
				{0xc4, 0xe2, 0x68, 0xf3, 0x54, 0x48, 0x08},
				{0xc4, 0xe2, 0x60, 0xf3, 0x0d, 0x78, 0x56, 0x34, 0x12},
			},
		},
		{
			name: "amd64-darwin", goarch: "amd64", triple: "x86_64-apple-darwin",
			encodings: [][]byte{
				{0xc4, 0xe2, 0x88, 0xf3, 0xd2},                               // reported BLSMSKQ DX, R14
				{0xc4, 0x82, 0x88, 0xf3, 0x5c, 0x88, 0x10},                   // BLSIQ 16(R8)(R9*4), R14
				{0x64, 0xc4, 0xe2, 0x80, 0xf3, 0x4c, 0x48, 0x08},             // BLSRQ FS:8(AX)(CX*2), R15
				{0xc4, 0xe2, 0x80, 0xf3, 0x1c, 0x25, 0x78, 0x56, 0x34, 0x12}, // BLSIQ 0x12345678, R15
			},
		},
		{
			name: "amd64-linux", goarch: "amd64", triple: "x86_64-unknown-linux-gnu",
			encodings: [][]byte{
				{0xc4, 0xe2, 0x88, 0xf3, 0xd2},
				{0xc4, 0x82, 0x88, 0xf3, 0x5c, 0x88, 0x10},
				{0x64, 0xc4, 0xe2, 0x80, 0xf3, 0x4c, 0x48, 0x08},
				{0xc4, 0xe2, 0x80, 0xf3, 0x1c, 0x25, 0x78, 0x56, 0x34, 0x12},
			},
		},
		{
			name: "amd64-windows", goarch: "amd64", triple: "x86_64-pc-windows-msvc",
			encodings: [][]byte{
				{0xc4, 0xe2, 0x88, 0xf3, 0xd2},
				{0xc4, 0x82, 0x88, 0xf3, 0x5c, 0x88, 0x10},
				{0x64, 0xc4, 0xe2, 0x80, 0xf3, 0x4c, 0x48, 0x08},
				{0xc4, 0xe2, 0x80, 0xf3, 0x1c, 0x25, 0x78, 0x56, 0x34, 0x12},
			},
		},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			sigs := make(map[string]FuncSig)
			for index, encoding := range target.encodings {
				name := fmt.Sprintf("rawBLS_%d", index)
				fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
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
			compileLLVMToObject(t, llc, target.triple, "raw-bls.ll", "raw-bls.o", ir)
		})
	}
}

func TestX86RawBLSRejectsInvalidOrLayoutDependentForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
	}{
		{name: "vex_l", mode: 64, encoding: []byte{0xc4, 0xe2, 0x8c, 0xf3, 0xd2}},
		{name: "vex_prefix", mode: 64, encoding: []byte{0xc4, 0xe2, 0x89, 0xf3, 0xd2}},
		{name: "invalid_digit", mode: 64, encoding: []byte{0xc4, 0xe2, 0x88, 0xf3, 0xc2}},
		{name: "extended_destination_386", mode: 32, encoding: []byte{0xc4, 0xe2, 0x38, 0xf3, 0xd2}},
		{name: "address_size_override", mode: 64, encoding: []byte{0x67, 0xc4, 0xe2, 0x88, 0xf3, 0x54, 0x48, 0x08}},
		{name: "rip_relative", mode: 64, encoding: []byte{0xc4, 0xe2, 0x88, 0xf3, 0x15, 0, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86BLSInstruction(test.encoding, test.mode)
			if test.name == "vex_l" || test.name == "vex_prefix" {
				if ok {
					t.Fatalf("reserved VEX encoding %x was recognized: %v", test.encoding, err)
				}
				return
			}
			if !ok || err == nil {
				t.Fatalf("encoding %x: ok=%v err=%v, want recognized rejection", test.encoding, ok, err)
			}
		})
	}
}

func TestAMD64BLSRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT blssemantics(SB),$0-8
	MOVQ out+0(FP), DI
	MOVQ $0, AX
	BLSIQ AX, BX
	MOVQ BX, 0(DI)
	SETCS 48(DI)
	SETEQ 49(DI)
	SETMI 50(DI)
	SETOS 51(DI)
	MOVQ $0x8000000000000000, AX
	BLSIQ AX, BX
	MOVQ BX, 8(DI)
	MOVQ $0, AX
	BLSMSKQ AX, BX
	MOVQ BX, 16(DI)
	SETCS 52(DI)
	SETEQ 53(DI)
	SETMI 54(DI)
	SETOS 55(DI)
	MOVQ $10, AX
	BLSRQ AX, BX
	MOVQ BX, 24(DI)
	SETCS 56(DI)
	SETEQ 57(DI)
	SETMI 58(DI)
	SETOS 59(DI)
	MOVL $0x80000000, AX
	BLSIL AX, BX
	MOVQ BX, 32(DI)
	MOVL $0, AX
	BLSMSKL AX, BX
	MOVQ BX, 40(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"blssemantics": {Name: "blssemantics", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void blssemantics(uint8_t *);
int main(void) {
  uint8_t out[64] = {0};
  blssemantics(out);
  const uint64_t want[6] = {0, UINT64_C(0x8000000000000000), UINT64_MAX, 8, UINT64_C(0x80000000), UINT64_C(0xffffffff)};
  for (int i = 0; i < 6; i++) {
    uint64_t got;
    memcpy(&got, out + i * 8, sizeof(got));
    if (got != want[i]) return 10 + i;
  }
  const uint8_t flags[12] = {0,1,0,0, 1,0,1,0, 0,0,0,0};
  for (int i = 0; i < 12; i++) if (out[48+i] != flags[i]) return 30+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "bls_semantics", triple, ir, mainC, runPrefix)
}
