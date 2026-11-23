package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86RMWSharedAddressOriginalGo(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			word, move, base, widths := 8, "MOVQ", "R11", "BWLQ"
			triple := "x86_64-unknown-linux-gnu"
			compiler := []string{clang, "-target", triple}
			if arch == "386" {
				word, move, base, widths = 4, "MOVL", "BX", "BWL"
				triple = "i386-unknown-linux-gnu"
				cross, err := exec.LookPath("i686-linux-gnu-gcc")
				if err != nil {
					t.Fatal("i686-linux-gnu-gcc required", err)
				}
				compiler = []string{cross, "-static", "-no-pie"}
			}
			var source, declarations, goRows, cDecls, cRows strings.Builder
			stems := []string{"XCHG", "XADD", "CMPXCHG", "BT", "BTC", "BTR", "BTS", "ADD", "ADC", "SUB", "SBB", "AND", "OR", "XOR"}
			stems = append(stems, "MOV", "MOVNTI", "MOVBE", "SHL", "SHR")
			for _, op := range stems {
				for i, width := range widths {
					bits, bitTest := 8<<i, strings.HasPrefix(op, "BT")
					doubleShift := op == "SHL" || op == "SHR"
					if bits == 8 && (bitTest || doubleShift || op == "MOVBE") || op == "MOVNTI" && bits < 32 {
						continue
					}
					name := "Check" + op + string(width)
					data := base
					if arch == "386" && bits == 8 {
						data = "BL"
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s value+0(FP),%s\n%s adjustment+%d(FP),DX\n"+
						"%s $0x2468,AX\nSTC\n", name, 3*word, move, base, move, word, move)
					if doubleShift {
						source.WriteString("MOVL $7,CX\n")
						data = "CL, " + data
					}
					fmt.Fprintf(&source, "%s%c %s, 5(%s)(DX*1)\n", op, width, data, base)
					switch {
					case bitTest:
						source.WriteString("SETCS AL\nMOVBLZX AL,AX\n")
					case op == "XADD" || op == "XCHG":
						fmt.Fprintf(&source, "%s %s,AX\n", move, base)
					case op == "MOVNTI":
						source.WriteString("SFENCE\n")
					}
					fmt.Fprintf(&source, "%s AX,ret+%d(FP)\nRET\n", move, 2*word)
					fmt.Fprintf(&declarations, "func %s(value, adjustment uintptr) uintptr\n", name)
					fmt.Fprintf(&cDecls, "extern uintptr_t %s(uintptr_t, uintptr_t);\n", name)
					for _, raw := range []uint64{0, 1, 63, 64, ^uint64(64), ^uint64(0)} {
						value := raw & (uint64(1)<<(8*word) - 1)
						for _, seed := range []uint64{0x2468, 0xfedcba9876543210} {
							offset, old, result, stored := x86SharedRMWExpected(op, bits, value, seed)
							fmt.Fprintf(&goRows, "{%s, %#x, %#x, %#x, %#x, %d, %d},\n", name, value, old, result, stored, offset, bits/8)
							fmt.Fprintf(&cRows, "{%s, %#xULL, %#xULL, %#xULL, %#xULL, %d, %d},\n", name, value, old, result, stored, offset, bits/8)
						}
					}
				}
			}
			execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
			goMain := fmt.Sprintf(x86SharedRMWGoDriver, goRows.String())
			cMain := fmt.Sprintf(x86SharedRMWCDriver, cDecls.String(), cRows.String())
			x86DirectTailCheckCallRuntime(t, arch, execution, source.String(), declarations.String(), goMain, cMain,
				"shared RMW addresses passed\n", "unsafe")
		})
	}
}

func x86SharedRMWExpected(op string, bits int, value, seed uint64) (offset int, old, result, stored uint64) {
	mask := uint64(1)<<bits - 1
	old, result, offset = seed&mask, 0x2468, 48
	data := value & mask
	stored = old
	switch op {
	case "XCHG", "XADD":
		result = old
		if bits < 32 {
			result |= value &^ mask
		}
		stored = data
		if op == "XADD" {
			stored += old
		}
	case "CMPXCHG":
		if old == result&mask {
			stored = data
		} else {
			result = result&^mask | old
		}
	case "BT", "BTC", "BTR", "BTS":
		index := int64(value<<uint(64-bits)) >> uint(64-bits)
		part := index & int64(bits-1)
		offset += int((index - part) / 8)
		bit := uint64(1) << uint(part)
		result = (old & bit) >> uint(part)
		switch op {
		case "BTC":
			stored = old ^ bit
		case "BTR":
			stored = old &^ bit
		case "BTS":
			stored = old | bit
		}
	case "ADD":
		stored = old + data
	case "ADC":
		stored = old + data + 1
	case "SUB":
		stored = old - data
	case "SBB":
		stored = old - data - 1
	case "AND":
		stored = old & data
	case "OR":
		stored = old | data
	case "XOR":
		stored = old ^ data
	case "MOV", "MOVNTI":
		stored = data
	case "MOVBE":
		stored = 0
		for i := 0; i < bits/8; i++ {
			stored = stored<<8 | data&0xff
			data >>= 8
		}
	case "SHL":
		stored = old<<7 | data>>uint(bits-7)
	case "SHR":
		stored = old>>7 | data<<uint(bits-7)
	}
	return offset, old, result, stored & mask
}

const x86SharedRMWGoDriver = `
var memory [96]byte
func main() {
	rows := []struct {
		invoke func(uintptr, uintptr) uintptr
		value uintptr
		old, result, stored uint64
		offset, size int
	}{
%s
	}
	for i, row := range rows {
		for j := range memory { memory[j] = 0xa5 }
		for j := 0; j < row.size; j++ { memory[row.offset+j] = byte(row.old >> (8*j)) }
		delta := uintptr(unsafe.Pointer(&memory[48])) - row.value - 5
		if actual := row.invoke(row.value, delta); uint64(actual) != row.result {
			panic(fmt.Sprintf("row %%d register got %%#x want %%#x", i, actual, row.result))
		}
		for j, actual := range memory {
			want := byte(0xa5)
			if at := j-row.offset; at >= 0 && at < row.size { want = byte(row.stored >> (8*at)) }
			if actual != want { panic(fmt.Sprintf("row %%d byte %%d got %%x want %%x", i, j, actual, want)) }
		}
	}
	fmt.Println("shared RMW addresses passed")
}
`

const x86SharedRMWCDriver = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
int main(void) {
	const struct {
		uintptr_t (*invoke)(uintptr_t, uintptr_t);
		uintptr_t value;
		uint64_t old, result, stored;
		int offset, size;
	} rows[] = {
%s
	};
	for (unsigned i = 0; i < sizeof rows / sizeof rows[0]; ++i) {
		unsigned char memory[96];
		memset(memory, 0xa5, sizeof memory);
		for (int j = 0; j < rows[i].size; ++j)
			memory[rows[i].offset + j] = rows[i].old >> (8*j);
		uintptr_t delta = (uintptr_t)(memory + 48) - rows[i].value - 5;
		if (rows[i].invoke(rows[i].value, delta) != rows[i].result) {
			fprintf(stderr, "row %%u register mismatch\n", i);
			return 1;
		}
		for (int j = 0; j < (int)sizeof memory; ++j) {
			int at = j - rows[i].offset;
			unsigned char want = at >= 0 && at < rows[i].size ? rows[i].stored >> (8*at) : 0xa5;
			if (memory[j] != want) {
				fprintf(stderr, "row %%u byte %%d mismatch\n", i, j);
				return 2;
			}
		}
	}
	puts("shared RMW addresses passed");
	return 0;
}
`
