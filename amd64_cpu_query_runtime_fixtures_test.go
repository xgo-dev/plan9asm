package plan9asm

import (
	"fmt"
	"strings"
)

func x86CPUQueryRuntimeFixtures(raw bool, arch string) (declarations, assembly string) {
	for _, op := range []Op{OpCPUID, OpXGETBV} {
		name := "query"
		if op == OpXGETBV {
			name = "fault"
		}
		body := string(op) + "\n"
		if raw {
			body = "BYTE $0x0f\nBYTE $0xa2\n"
			if op == OpXGETBV {
				body = "BYTE $0x0f\nBYTE $0x01\nBYTE $0xd0\n"
			}
		}
		for index, seed := range []uint64{0x8c7, 0x12} {
			entry := name
			if index != 0 {
				entry += "_af"
			}
			declarations += fmt.Sprintf("func %s(out *[8]uint64)\n", entry)
			assembly += fmt.Sprintf(`TEXT ·%s(SB),4,$0-8
    MOVQ out+0(FP),DI
    MOVQ $0xa1b2c3d400000000,AX
    MOVQ $0xa1b2c3d400000000,CX
    MOVQ $0x7e6d5c4b3a291807,BX
    MOVQ $-1,DX
    PUSHQ $%#x
    POPFQ
    %s
    MOVQ AX,0(DI)
    MOVQ BX,8(DI)
    MOVQ CX,16(DI)
    MOVQ DX,24(DI)
    PUSHFQ
    POPQ R8
    MOVQ R8,32(DI)
    STMXCSR 40(DI)
    RET
`, entry, seed, body)
		}
	}
	if arch == "386" {
		declarations = strings.ReplaceAll(declarations, "uint64", "uint32")
		assembly = strings.NewReplacer(
			"$0-8", "$0-4", "MOVQ", "MOVL", "PUSHQ", "PUSHL", "POPFQ", "POPFL",
			"PUSHFQ", "PUSHFL", "POPQ R8", "POPL SI", "R8,32(DI)", "SI,16(DI)",
			"$0xa1b2c3d400000000", "$0", "$0x7e6d5c4b3a291807", "$0x3a291807",
			"BX,8(DI)", "BX,4(DI)", "CX,16(DI)", "CX,8(DI)", "DX,24(DI)", "DX,12(DI)",
			"40(DI)", "20(DI)",
		).Replace(assembly)
	} else if arch != "amd64" {
		panic("CPU-query fixture requires an x86 architecture")
	}
	return
}

const x86CPUQueryOriginalDriver = `package main

import (
    "fmt"
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
        panic(err)
    }
    cpu, state, flags := query, fault, uint64(0x8c5)
    if len(os.Args) == 2 && os.Args[1] == "_af" {
        cpu, state, flags = query_af, fault_af, 0x10
    }
    sample := func(call func(*[8]uint64)) [8]uint64 {
        out := [8]uint64{0,0,0,0,0,0,0xabcdef0123456789,0x13579bdf2468ace0}
        call(&out)
        if out[4]&0x8d5 != flags || out[6] != 0xabcdef0123456789 || out[7] != 0x13579bdf2468ace0 {
            panic(fmt.Sprintf("original query flags/canary: %x", out))
        }
        return out
    }
    out := sample(cpu)
    for _, value := range out[:4] {
        if value>>32 != 0 { panic("query output did not zero-extend") }
    }
    fmt.Printf("cpu query %x %x %x %x\n", out[0],out[1],out[2],out[3])
    out = sample(state)
    if out[0]>>32 != 0 || out[3]>>32 != 0 || out[1] != 0x7e6d5c4b3a291807 || out[2] != 0xa1b2c3d400000000 {
        panic(fmt.Sprintf("original XGETBV implicit registers: %x", out))
    }
    fmt.Printf("xgetbv %x %x\n", out[0],out[3])
}
`

func x86CPUQuery386OriginalDriver() string {
	return strings.NewReplacer(
		"uint64", "uint32", "0xabcdef0123456789", "0x23456789", "0x13579bdf2468ace0", "0x2468ace0",
		"0x7e6d5c4b3a291807", "0x3a291807", "0xa1b2c3d400000000", "0",
	).Replace(x86CPUQueryOriginalDriver)
}
