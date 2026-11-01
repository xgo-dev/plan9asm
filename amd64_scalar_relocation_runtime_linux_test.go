//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarAbsoluteRelocation(t *testing.T) {
	llc := findLLVM22Tool("llc")
	compiler, compilerErr := exec.LookPath("i686-linux-gnu-gcc")
	qemu, qemuErr := exec.LookPath("qemu-i386")
	if llc == "" || compilerErr != nil || qemuErr != nil {
		t.Fatal("LLVM 22, IA32 Linux compiler and pinned QEMU required", compilerErr, qemuErr)
	}
	var source strings.Builder
	source.WriteString("TEXT ·Value(SB),4,$0-0\n")
	index := 0
	for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		for _, seed := range []uint32{0, 0xffffffff, 0x81234567} {
			for _, carry := range []string{"CLC", "STC"} {
				fmt.Fprintf(&source, "MOVL $%d,AX\n%s\n%sL $·cell+8(SB),AX\nMOVL AX,·result+%d(SB)\nMOVL $0,BX\nSETCS BX\nMOVL BX,·result+%d(SB)\n",
					seed, carry, stem, index*8, index*8+4)
				index++
			}
		}
	}
	source.WriteString("RET\n")
	if index != 42 {
		t.Fatal("incomplete independent operation/seed/carry matrix", index)
	}
	run := func(executable string) {
		t.Helper()
		command := runtimeOracleGuestArguments(t, []string{qemu, "-L", "/usr/i686-linux-gnu"}, executable)
		if output := x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...)); string(output) != "OK 42\n" {
			t.Fatalf("incomplete IA32 relocated-value/carry observations: %q", output)
		}
	}
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386",
		"package main\nfunc Value()\n", source.String(), x86ScalarRelocationOriginalGo)
	run(original)
	llvmSource, llvmReference := x86ScalarRelocationOwnedLLVMFixture(t, source.String(), x86ScalarRelocationReferenceC)
	for _, api := range []string{"text", "module", "go"} {
		ir, err := x86AddressMemoryAPI(t, api, llvmSource, "386", "i386-unknown-linux-gnu")
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(api+level, func(t *testing.T) {
				dir := t.TempDir()
				input, driver := filepath.Join(dir, "source.ll"), filepath.Join(dir, "reference.c")
				object, executable := filepath.Join(dir, "source.o"), filepath.Join(dir, "reference")
				for name, data := range map[string]string{input: ir, driver: llvmReference} {
					if err := os.WriteFile(name, []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
				x86FloatCompareCaptureCommand(t, exec.Command(compiler, "-O2", "-no-pie", object, driver, "-o", executable))
				run(executable)
			})
		}
	}
}

const x86ScalarRelocationOriginalGo = `package main
import ("fmt"; "unsafe")
var cell = [32]byte{0xa7}
var result [84]uint32
func main() {
    Value()
    address := uint64(uintptr(unsafe.Pointer(&cell[8])))
    index := 0
    for operation := 0; operation < 7; operation++ {
        for _, initial := range []uint64{0, 0xffffffff, 0x81234567} {
            for carry := uint64(0); carry < 2; carry++ {
                var value, flag uint64
                switch operation {
                case 0: value = initial + address; flag = value >> 32
                case 1: value = initial - address; if initial < address { flag = 1 }
                case 2: value = initial + address + carry; flag = value >> 32
                case 3: value = initial - address - carry; if initial < address + carry { flag = 1 }
                case 4: value = initial & address
                case 5: value = initial | address
                case 6: value = initial ^ address
                }
                if result[index*2] != uint32(value) || result[index*2+1] != uint32(flag) {
                    panic(fmt.Sprintf("original relocation case %d: %x/%x want %x/%x", index, result[index*2], result[index*2+1], uint32(value), flag))
                }
                index++
            }
        }
    }
    fmt.Printf("OK %d\n", index)
}
`

const x86ScalarRelocationReferenceC = `
#include <stdint.h>
#include <stdio.h>
uint8_t cell[32] = {0xa7};
uint32_t result[84];
extern void Value(void);
int main(void) {
    Value();
    uint64_t address = (uintptr_t)&cell[8];
    uint32_t seeds[] = {0, UINT32_MAX, 0x81234567};
    unsigned index = 0;
    for (unsigned operation = 0; operation < 7; operation++) {
        for (unsigned seed = 0; seed < 3; seed++) {
            for (unsigned carry = 0; carry < 2; carry++, index++) {
                uint64_t initial = seeds[seed], value = 0, flag = 0;
                switch (operation) {
                case 0: value = initial + address; flag = value >> 32; break;
                case 1: value = initial - address; flag = initial < address; break;
                case 2: value = initial + address + carry; flag = value >> 32; break;
                case 3: value = initial - address - carry; flag = initial < address + carry; break;
                case 4: value = initial & address; break;
                case 5: value = initial | address; break;
                case 6: value = initial ^ address; break;
                }
                if (result[index*2] != (uint32_t)value || result[index*2+1] != flag) {
                    fprintf(stderr, "LLVM relocation case %u: %x/%x want %x/%x\n", index,
                        result[index*2], result[index*2+1], (uint32_t)value, (uint32_t)flag);
                    return 1;
                }
            }
        }
    }
    printf("OK %u\n", index);
    return 0;
}
`
