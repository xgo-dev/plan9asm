package plan9asm

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const x86Linux386SyscallAssembly = `TEXT ·Raw(SB),4,$0-36
MOVL number+0(FP), AX
MOVL a1+4(FP), BX
MOVL a2+8(FP), CX
MOVL a3+12(FP), DX
MOVL a4+16(FP), SI
MOVL a5+20(FP), DI
MOVL a6+24(FP), BP
INT $0x80
MOVL AX, r1+28(FP)
MOVL DX, r2+32(FP)
RET
`

func TestX86Linux386SyscallOriginalGo(t *testing.T) {
	x86LinuxSyscallOriginalGo(t, "386", x86Linux386SyscallAssembly)
}

func TestX86Linux386SyscallFormAndTarget(t *testing.T) {
	ins := x86PureGPUnknownInstruction(t, "INT $0x80")
	for _, target := range []string{"i386-unknown-linux-gnu", "i686-linux-gnu"} {
		form, known, err := x86LinuxSyscallProperties(ins, "386", target)
		if !known || err != nil || form.width != 4 || form.inputs != [7]Reg{AX, BX, CX, DX, SI, DI, BP} ||
			form.clobbers != [2]Reg{} || !form.observesDX || form.instruction != "int $$0x80" {
			t.Fatal("complete target-aware raw form", target, known, err, form)
		}
	}
	for _, target := range []string{"", "i386-linux-windows-msvc", "i686-w64-windows-gnu", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
		if _, known, err := x86LinuxSyscallProperties(ins, "386", target); !known || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("invalid target for the 386 kernel form", target, known, err)
		}
	}
	if _, _, err := x86LinuxSyscallProperties(ins, "amd64", "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("64-bit source acquired the 386 syscall convention", err)
	}
}

func TestX86Linux386SyscallImmediateAndPairedResult(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	for _, vector := range []string{"0x80", "-128", "384"} {
		t.Run(vector, func(t *testing.T) {
			instruction := "INT $" + vector
			original := x86PackedShiftActualGoBytes(t, "386", "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
			if want := []byte{0xcd, 0x80, 0xc3}; !bytes.Equal(original, want) {
				t.Fatalf("Go encoded %s as %x, want %x", instruction, original, want)
			}
			source := strings.Replace(x86Linux386SyscallAssembly, "INT $0x80", instruction, 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, x86LinuxSyscallDeclaration, "386", triple, api)
				if err != nil {
					t.Errorf("%s: paired Linux kernel result transfer: %v", api, err)
					continue
				}
				if !strings.Contains(ir, `asm sideeffect "int $$0x80"`) {
					t.Errorf("%s: lost the original Linux interrupt", api)
				}
				x86NumericNativeAddressObject(t, ir, triple)
			}
		})
	}
}

func TestX86Linux386SyscallInputGuards(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	for _, row := range []struct{ name, old, replacement string }{
		{"undefined BP", "MOVL a6+24(FP), BP", "NOP"},
		{"partial BP", "MOVL a6+24(FP), BP", "MOVW a6+24(FP), BP"},
		{"logical address", "MOVL a6+24(FP), BP", "LEAL r1+28(FP), BP"},
		{"virtual FLAGS", "INT $0x80", "CMPL BX,CX\nINT $0x80\nJEQ 2(PC)\nNOP"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := strings.Replace(x86Linux386SyscallAssembly, row.old, row.replacement, 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, x86LinuxSyscallDeclaration, "386", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: missing input, private address or virtual FLAGS crossed the syscall: %v", api, err)
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·Raw(SB),4,$0-0\nINT $0x80\nRET\n", "func Raw()", "386", triple, api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: a Void syscall acquired uninitialized register values: %v", api, err)
		}
	}
}
