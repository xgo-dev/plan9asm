package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// The Go name retains W=1, but physical non-64-bit execution ignores that
// bit. Bind the source encoder independently from the effective byte effect.
func TestX86ScalarLaneMode32QUsesActualDwordEncoding(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, destination := range []string{"AX", "1(BX)"} {
		for _, immediate := range []int{0, 1, 2, 3, 128, 255, -1, -128} {
			t.Run(fmt.Sprintf("%s/%d", destination, immediate), func(t *testing.T) {
				row := fmt.Sprintf("VPEXTRQ $%d,X0,%s", immediate, destination)
				code := assembleX87ControlBytes(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				if len(code) < 7 || code[0] != 0xc4 || code[1] != 0xe3 || code[2] != 0xf9 || code[3] != 0x16 || code[len(code)-1] != 0xc3 {
					t.Fatalf("actual Go W1 source bytes changed: %x", code)
				}
				var input strings.Builder
				for _, value := range code[:len(code)-1] {
					fmt.Fprintf(&input, "%#02x ", value)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=i386-unknown-linux-gnu", "--mattr=+avx")
				command.Stdin = strings.NewReader(input.String())
				output, err := runtimeOracleCombinedOutput(ctx, command)
				cancel()
				// LLVM22 spells W1 as Q even for the i386 triple (and prints
				// RAX for the register operand). This is an encoding observer,
				// not a physical-width authority or native mode32 execution.
				if err != nil || !strings.Contains(string(output), fmt.Sprintf("vpextrq\t$%d, %%xmm0,", byte(immediate))) || strings.Contains(string(output), "warning:") {
					t.Fatalf("LLVM22 exact W1 encoding observation: %v\n%s", err, output)
				}
				dword := assembleX87ControlBytes(t, "386", "TEXT f(SB),4,$0-0\n"+strings.Replace(row, "VPEXTRQ", "VPEXTRD", 1)+"\nRET\n")
				withoutW := append([]byte(nil), code...)
				withoutW[2] &^= 0x80
				if string(withoutW) != string(dword) {
					t.Fatalf("actual Go Q/D bytes differ outside the ignored W bit: %x / %x", code, dword)
				}
				// Intel SDM Vol2 PEXTRB/PEXTRD/PEXTRQ, note2 and operation:
				// non-64-bit W is ignored, with imm[1:0] and r32/m32.
				for _, ins := range []Instr{x86ScalarLaneInstruction(t, row), func() Instr {
					fn, err := decodeX86RawDirectives(rawX86Function(code), "386")
					if err != nil || len(fn.Instrs) != 2 {
						t.Fatalf("complete physical byte decode: %v %+v", err, fn)
					}
					return fn.Instrs[0]
				}()} {
					form, known, err := x86ScalarLaneProperties(ins, "386")
					if err != nil || !known || form.bits != 32 || form.gpBits != 32 || form.offset != int(byte(immediate)&3)*4 {
						t.Fatalf("source/raw effective WIG lane differs from native bytes: %+v known=%t err=%v", form, known, err)
					}
					if destination != "AX" {
						width, write, valid := x86InstructionMemoryShape(ins, 2, "386")
						if !valid || !write || width != 4 {
							t.Fatal("physical memory effect was widened", width, write, valid)
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarLaneMode32QResultBytesThreeAPIs(t *testing.T) {
	for _, target := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, memory := range []bool{false, true} {
			for lane := 0; lane < 4; lane++ {
				t.Run(fmt.Sprintf("%s/memory=%t/lane=%d", target, memory, lane), func(t *testing.T) {
					body := fmt.Sprintf("PINSRD $%d,k+0(FP),X0\nVPEXTRQ $%d,X0,AX\nMOVL AX,ret+4(FP)\n", lane, lane)
					if memory {
						body = fmt.Sprintf("PINSRD $%d,k+0(FP),X0\nVPEXTRQ $%d,X0,ret+4(FP)\n", lane, lane)
					}
					source := "TEXT ·view(SB),4,$0-8\n" + body + "RET\n"
					goAssemblerOracleOutput(t, "386", source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k uint32) uint32\n", "386", target, api)
						if err != nil || !strings.Contains(ir, "extractelement <4 x i32>") || strings.Contains(ir, "extractelement <2 x i64>") {
							t.Fatalf("%s observes an unknown Q lane/overwrites adjacent result bytes: %v\n%s", api, err, ir)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target, "wig.ll", "wig.o", ir)
					}
					// A four-byte insertion cannot define any other dword.
					bad := strings.Replace(source, fmt.Sprintf("PINSRD $%d", lane), fmt.Sprintf("PINSRD $%d", (lane+1)&3), 1)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, bad, "func view(k uint32) uint32\n", "386", target, api); err == nil || ir != "" {
							t.Fatalf("%s changed lane granted unknown bytes: %v", api, err)
						}
					}
				})
			}
		}
	}
}
