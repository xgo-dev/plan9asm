package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86RawANDNReportedEncoding(t *testing.T) {
	const source = `
TEXT rawANDN(SB),$0-0
	BYTE $0xc4
	BYTE $0x42
	BYTE $0x38
	BYTE $0xf2
	BYTE $0xe2
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
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-apple-darwin"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawANDN": {Name: "rawANDN", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+bmi"`) {
				t.Fatalf("raw ANDN did not infer BMI1 target feature:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-andn.ll", "raw-andn.o", ir)
		})
	}
}

func TestX86ANDNCompleteGo127FormsAcrossTargets(t *testing.T) {
	registers386 := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
	registersAMD64 := append(append([]string{}, registers386...), "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	targets := []struct {
		name      string
		goarch    string
		triple    string
		registers []string
	}{
		{name: "386-linux", goarch: "386", triple: "i386-unknown-linux-gnu", registers: registers386},
		{name: "386-windows", goarch: "386", triple: "i686-pc-windows-msvc", registers: registers386},
		{name: "amd64-darwin", goarch: "amd64", triple: "x86_64-apple-darwin", registers: registersAMD64},
		{name: "amd64-linux", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", registers: registersAMD64},
		{name: "amd64-windows", goarch: "amd64", triple: "x86_64-pc-windows-msvc", registers: registersAMD64},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT andnall(SB),$0-0\n")
			for _, width := range []string{"L", "Q"} {
				for index, first := range target.registers {
					second := target.registers[(index+3)%len(target.registers)]
					destination := target.registers[(index+5)%len(target.registers)]
					fmt.Fprintf(&source, "\tANDN%s %s, %s, %s\n", width, first, second, destination)
				}
				fmt.Fprintf(&source, "\tANDN%s 8(AX), CX, DX\n", width)
				fmt.Fprintf(&source, "\tANDN%s 16(AX)(CX*4), DX, BX\n", width)
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
				Sigs:         map[string]FuncSig{"andnall": {Name: "andnall", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+bmi"`) {
				t.Fatalf("ANDN family did not infer BMI1 target feature:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "andn-family.ll", "andn-family.o", ir)
		})
	}
}

func TestX86RawANDNCompleteRegisterFields(t *testing.T) {
	for _, mode := range []int{32, 64} {
		registerCount := 8
		if mode == 64 {
			registerCount = 16
		}
		for _, width64 := range []bool{false, true} {
			for first := 0; first < registerCount; first++ {
				for second := 0; second < registerCount; second++ {
					for destination := 0; destination < registerCount; destination++ {
						p0 := byte((^destination>>3)&1)<<7 | 1<<6 | byte((^first>>3)&1)<<5 | 2
						p1 := byte((^second)&15) << 3
						if width64 {
							p1 |= 0x80
						}
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0xc4, p0, p1, 0xf2, modRM}
						instruction, length, ok, err := decodedX86ANDNInstruction(encoding, mode)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("mode=%d width64=%v first=%d second=%d destination=%d: ok=%v length=%d err=%v", mode, width64, first, second, destination, ok, length, err)
						}
						wantOp := Op("ANDNL")
						if width64 && mode == 64 {
							wantOp = "ANDNQ"
						}
						wantFirst, _ := decodedX86GeneralRegister(first)
						wantSecond, _ := decodedX86GeneralRegister(second)
						wantDestination, _ := decodedX86GeneralRegister(destination)
						if instruction.Op != wantOp || len(instruction.Args) != 3 || instruction.Args[0].Reg != wantFirst || instruction.Args[1].Reg != wantSecond || instruction.Args[2].Reg != wantDestination {
							t.Fatalf("encoding %x decoded as %#v", encoding, instruction)
						}
					}
				}
			}
		}
	}
}

func TestX86RawANDNMemoryForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding []byte
	}{
		{name: "direct", encoding: []byte{0xc4, 0xe2, 0x30, 0xf2, 0x13}},
		{name: "extended base", encoding: []byte{0xc4, 0xc2, 0x30, 0xf2, 0x13}},
		{name: "sib disp8", encoding: []byte{0xc4, 0x82, 0x88, 0xf2, 0x54, 0x88, 0x10}},
		{name: "base less", encoding: []byte{0xc4, 0xe2, 0x30, 0xf2, 0x14, 0x25, 0x78, 0x56, 0x34, 0x12}},
		{name: "segment", encoding: []byte{0x64, 0xc4, 0xe2, 0x30, 0xf2, 0x54, 0x48, 0x08}},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86ANDNInstruction(test.encoding, 64)
			if !ok || err != nil || length != len(test.encoding) || len(instruction.Args) != 3 || instruction.Args[0].Kind != OpMem {
				t.Fatalf("encoding %x: instruction=%#v ok=%v length=%d err=%v", test.encoding, instruction, ok, length, err)
			}
		})
	}
}

func TestX86RawANDNRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
	}{
		{name: "vex l", mode: 64, encoding: []byte{0xc4, 0xe2, 0x34, 0xf2, 0xd2}},
		{name: "vex pp", mode: 64, encoding: []byte{0xc4, 0xe2, 0x31, 0xf2, 0xd2}},
		{name: "missing modrm", mode: 64, encoding: []byte{0xc4, 0xe2, 0x30, 0xf2}},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0xc4, 0xe2, 0x30, 0xf2, 0xd2}},
		{name: "rip relative", mode: 64, encoding: []byte{0xc4, 0xe2, 0x30, 0xf2, 0x15, 0, 0, 0, 0}},
		{name: "extended first 386", mode: 32, encoding: []byte{0xc4, 0xc2, 0x70, 0xf2, 0xc0}},
		{name: "extended second 386", mode: 32, encoding: []byte{0xc4, 0xe2, 0x38, 0xf2, 0xc0}},
		{name: "extended destination 386", mode: 32, encoding: []byte{0xc4, 0x62, 0x70, 0xf2, 0xc0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86ANDNInstruction(test.encoding, test.mode)
			if !ok || err == nil {
				t.Fatalf("encoding %x: ok=%v err=%v, want recognized rejection", test.encoding, ok, err)
			}
		})
	}
}

func TestX86ANDNRuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT andnsemantics(SB),$0-8
	MOVQ out+0(FP), DI
	MOVQ $0xf0, AX
	MOVQ $0xcc, BX
	ANDNQ AX, BX, CX
	MOVQ CX, 0(DI)
	SETCS 24(DI)
	SETEQ 25(DI)
	SETMI 26(DI)
	SETOS 27(DI)
	MOVQ $0, AX
	MOVQ $0, BX
	ANDNQ AX, BX, CX
	MOVQ CX, 8(DI)
	SETCS 28(DI)
	SETEQ 29(DI)
	SETMI 30(DI)
	SETOS 31(DI)
	MOVL $0x80000000, AX
	MOVL $0, BX
	ANDNL AX, BX, CX
	MOVQ CX, 16(DI)
	SETCS 32(DI)
	SETEQ 33(DI)
	SETMI 34(DI)
	SETOS 35(DI)
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
			"andnsemantics": {Name: "andnsemantics", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void andnsemantics(uint8_t *);
int main(void) {
  uint8_t out[40] = {0};
  andnsemantics(out);
  const uint64_t want[3] = {UINT64_C(0x30), 0, UINT64_C(0x80000000)};
  for (int i = 0; i < 3; i++) {
    uint64_t got;
    memcpy(&got, out + i * 8, sizeof(got));
    if (got != want[i]) return 10 + i;
  }
  const uint8_t flags[12] = {0,0,0,0, 0,1,0,0, 0,0,1,0};
  for (int i = 0; i < 12; i++) if (out[24+i] != flags[i]) return 30+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "andn_semantics", triple, ir, mainC, runPrefix)
}
