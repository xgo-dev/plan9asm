package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86CMPXCHGOriginalNumerical(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	declarations, source, names := x86CMPXCHGNumericalFixture()
	driver := strings.Replace(x86CMPXCHGGoNumerical, "KERNEL_NAMES", names, 1)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), runtime.GOOS, "amd64", declarations, source, driver)
	output := execution.run(t, original)
	if string(output) != "original CMPXCHG numerical observations 576 failures 0\n" {
		t.Fatalf("actual unchanged Go ABI0 numerical/status/canary oracle: %s", output)
	}
	t.Log(string(output))
}

func TestX86CMPXCHGLLVMCompleteNumerical(t *testing.T) {
	x86CMPXCHGLLVMNumerical(t, x86FloatCompareExecutionTools(t))
}

func x86CMPXCHGLLVMNumerical(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	declarations, source, names := x86CMPXCHGNumericalFixture()
	ir, err := x86OrderingHintTranslateAPI(t, "Go", source, declarations, "amd64", execution.triple)
	if err != nil {
		t.Fatal(err)
	}
	var prototypes strings.Builder
	for _, name := range strings.Split(strings.TrimSpace(names), ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			fmt.Fprintf(&prototypes, "extern void %s(uint64_t *, unsigned char *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);\n", name)
		}
	}
	reference := strings.Replace(x86CMPXCHGCNumerical, "KERNEL_PROTOTYPES", prototypes.String(), 1)
	reference = strings.Replace(reference, "KERNEL_NAMES", names, 1)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "cmpxchg-numerical", ir, reference, level)
			if string(output) != "LLVM CMPXCHG numerical observations 576 failures 0\n" {
				t.Fatalf("independent full byte/status/canary oracle: %s", output)
			}
			t.Log(string(output))
		})
	}
}

func x86CMPXCHGNumericalFixture() (declarations, source, names string) {
	var decl, assembly, functions strings.Builder
	decl.WriteString("package main\n")
	// The independent family order binds the oracle's widths and pair policy.
	for index, op := range []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ", "CMPXCHG8B", "CMPXCHG16B"} {
		for _, locked := range []bool{false, true} {
			name := fmt.Sprintf("numeric_%d_%t", index, locked)
			fmt.Fprintf(&decl, "func %s(out *[16]uint64, p *[32]byte, expectedLo, expectedHi, desiredLo, desiredHi, seed uint64)\n", name)
			fmt.Fprintf(&functions, "%s,\n", name)
			fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-56
MOVQ out+0(FP),R10
MOVQ p+8(FP),SI
MOVQ expectedLo+16(FP),AX
MOVQ expectedHi+24(FP),DX
MOVQ desiredLo+32(FP),BX
MOVQ desiredHi+40(FP),CX
MOVQ seed+48(FP),R8
PUSHQ R8
POPFQ
`, name)
			if locked {
				assembly.WriteString("LOCK\n")
			}
			switch index {
			case 0:
				assembly.WriteString(op + " BL,(SI)\n")
			case 4, 5:
				assembly.WriteString(op + " (SI)\n")
			default:
				assembly.WriteString(op + " BX,(SI)\n")
			}
			assembly.WriteString(`MOVQ AX,0(R10)
MOVQ DX,8(R10)
MOVQ BX,16(R10)
MOVQ CX,24(R10)
PUSHFQ
POPQ R9
MOVQ R9,32(R10)
LAHF
MOVBLZX AH,BX
MOVQ BX,40(R10)
STMXCSR 48(R10)
RET
`)
		}
	}
	decl.WriteString("func csr() uint32\n")
	assembly.WriteString("TEXT ·csr(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\n")
	return decl.String(), assembly.String(), functions.String()
}

const x86CMPXCHGGoNumerical = `package main

import (
    "encoding/binary"
    "fmt"
    "os"
    "runtime"
    "unsafe"
)

func widthMask(bits uint) uint64 {
    if bits == 64 { return ^uint64(0) }
    return uint64(1)<<bits - 1
}

func subtractFlags(a, b uint64, bits uint) uint64 {
    mask := widthMask(bits)
    a, b = a&mask, b&mask
    result := (a-b)&mask
    var flags uint64
    if a < b { flags |= 1 }
    parity := byte(result)
    parity ^= parity>>4
    parity ^= parity>>2
    parity ^= parity>>1
    if parity&1 == 0 { flags |= 4 }
    if a&15 < b&15 { flags |= 16 }
    if result == 0 { flags |= 64 }
    if result>>(bits-1) != 0 { flags |= 128 }
    if ((a^b)&(a^result))>>(bits-1) != 0 { flags |= 2048 }
    return flags
}

func main() {
    runtime.LockOSThread()
    kernels := []func(*[16]uint64, *[32]byte, uint64, uint64, uint64, uint64, uint64){
        KERNEL_NAMES
    }
    edges := []uint64{0, 1, 15, 16, 127, 128, 255, 256,
        0x7fffffff, 0x80000000, 0x8000000000000000, ^uint64(0)}
    widths := []uint{8, 16, 32, 64, 32, 64}
    const canary uint64 = 0xa7a7a7a7a7a7a7a7
    observations, failures := 0, 0
    for index, kernel := range kernels {
        kernelFailures, registerFailures, statusFailures := 0, 0, 0
        family := index/2
        bits := widths[family]
        mask := widthMask(bits)
        size := int(bits/8)
        if family >= 4 { size *= 2 }
        for _, edge := range edges {
            for _, equal := range []bool{false, true} {
                for _, seed := range []uint64{0x8c7, 0x12} {
                    raw := [96]byte{}
                    for i := range raw { raw[i] = 0xa7 }
                    aligned := 16 + int((-uintptr(unsafe.Pointer(&raw[0])))&15)
                    if family != 5 { aligned++ }
                    p := (*[32]byte)(unsafe.Pointer(&raw[aligned]))
                    low, high := edge&mask, (^edge)&mask
                    for byteIndex := 0; byteIndex < size; byteIndex++ {
                        value := low
                        if byteIndex >= int(bits/8) { value = high }
                        p[byteIndex] = byte(value >> (8*uint(byteIndex%int(bits/8))))
                    }
                    expectedLow, expectedHigh := low, high
                    if !equal { expectedLow = (low+1)&mask }
                    expectedLow |= 0x13579bdf2468ace0 & ^mask
                    expectedHigh |= 0x2468ace013579bdf & ^mask
                    desiredLow := edge ^ 0xd3c2b1a097867564
                    desiredHigh := ^edge ^ 0x789abcdef0123456
                    expectedRaw := raw
                    if equal {
                        for byteIndex := 0; byteIndex < size; byteIndex++ {
                            value := desiredLow
                            if byteIndex >= int(bits/8) { value = desiredHigh }
                            expectedRaw[aligned+byteIndex] = byte(value >> (8*uint(byteIndex%int(bits/8))))
                        }
                    }
                    out := [16]uint64{}
                    for i := range out { out[i] = canary }
                    before := csr()
                    kernel(&out, p, expectedLow, expectedHigh, desiredLow, desiredHigh, seed)
                    after := csr()
                    wantLow, wantHigh := expectedLow, expectedHigh
                    if !equal {
                        if bits == 32 { wantLow = low } else { wantLow = expectedLow&^mask | low }
                        if family >= 4 {
                            if bits == 32 { wantHigh = high } else { wantHigh = high }
                        }
                    }
                    flags := subtractFlags(expectedLow, low, bits)
                    if family >= 4 {
                        flags = seed & 0x8d5 &^ 64
                        if equal { flags |= 64 }
                    }
                    csr := binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(&out[6]))[:])
                    bad := out[0] != wantLow || out[1] != wantHigh ||
                        out[2] != desiredLow || out[3] != desiredHigh ||
                        out[4]&0x8d5 != flags || out[5] != (flags&0xd5 | 2) ||
                        out[6]>>32 != canary>>32 || csr != before || after != before || raw != expectedRaw
                    for i := 7; i < len(out); i++ { bad = bad || out[i] != canary }
                    if bad {
                        kernelFailures++
                        if out[0] != wantLow || out[1] != wantHigh || out[2] != desiredLow || out[3] != desiredHigh {
                            registerFailures++
                        }
                        if out[4]&0x8d5 != flags || out[5] != (flags&0xd5 | 2) {
                            statusFailures++
                        }
                        if failures < 24 {
                            fmt.Printf("original failure kernel=%d bits=%d edge=%x equal=%t seed=%x out=%x wantAX=%x wantDX=%x flags=%x\n",
                                index, bits, edge, equal, seed, out, wantLow, wantHigh, flags)
                        }
                        failures++
                    }
                    observations++
                }
            }
        }
        if kernelFailures != 0 {
            fmt.Printf("original kernel=%d observations=48 failures=%d register=%d status=%d\n",
                index, kernelFailures, registerFailures, statusFailures)
        }
    }
    fmt.Printf("original CMPXCHG numerical observations %d failures %d\n", observations, failures)
    if failures != 0 { os.Exit(1) }
}
`

const x86CMPXCHGCNumerical = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

KERNEL_PROTOTYPES
typedef void (*Kernel)(uint64_t *, unsigned char *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t width_mask(unsigned bits) {
    return bits == 64 ? UINT64_MAX : ((UINT64_C(1)<<bits)-1);
}

static uint64_t subtraction(uint64_t a, uint64_t b, unsigned bits) {
    uint64_t mask = width_mask(bits);
    a &= mask;
    b &= mask;
    uint64_t difference = (a-b)&mask;
    uint64_t flags = a < b;
    unsigned ones = 0;
    for (unsigned bit = 0; bit < 8; bit++) ones += (difference>>bit)&1;
    if (!(ones&1)) flags |= 4;
    if ((a&15) < (b&15)) flags |= 16;
    if (!difference) flags |= 64;
    if (difference>>(bits-1)) flags |= 128;
    if (((a^b)&(a^difference))>>(bits-1)) flags |= 2048;
    return flags;
}

int main(void) {
    Kernel kernels[] = { KERNEL_NAMES };
    const uint64_t edges[] = {0, 1, 15, 16, 127, 128, 255, 256,
        0x7fffffff, 0x80000000, UINT64_C(0x8000000000000000), UINT64_MAX};
    const unsigned widths[] = {8, 16, 32, 64, 32, 64};
    const uint64_t seeds[] = {0x8c7, 0x12};
    const uint64_t canary = UINT64_C(0xa7a7a7a7a7a7a7a7);
    unsigned observations = 0, failures = 0;
    for (unsigned index = 0; index < 12; index++) {
        unsigned kernel_failures = 0, register_failures = 0, status_failures = 0;
        unsigned family = index/2, bits = widths[family];
        uint64_t mask = width_mask(bits);
        unsigned size = bits/8 * (family >= 4 ? 2 : 1);
        for (unsigned edge = 0; edge < 12; edge++) {
            for (unsigned equal = 0; equal < 2; equal++) {
                for (unsigned seed = 0; seed < 2; seed++) {
                    _Alignas(16) unsigned char raw[96], expected[96];
                    memset(raw, 0xa7, sizeof(raw));
                    unsigned start = family == 5 ? 16 : 17;
                    unsigned char *p = raw+start;
                    uint64_t low = edges[edge]&mask, high = ~edges[edge]&mask;
                    for (unsigned byte = 0; byte < size; byte++) {
                        uint64_t value = byte >= bits/8 ? high : low;
                        p[byte] = value>>(8*(byte%(bits/8)));
                    }
                    uint64_t expected_low = equal ? low : (low+1)&mask;
                    expected_low |= UINT64_C(0x13579bdf2468ace0)&~mask;
                    uint64_t expected_high = high | (UINT64_C(0x2468ace013579bdf)&~mask);
                    uint64_t desired_low = edges[edge]^UINT64_C(0xd3c2b1a097867564);
                    uint64_t desired_high = ~edges[edge]^UINT64_C(0x789abcdef0123456);
                    memcpy(expected, raw, sizeof(raw));
                    if (equal) {
                        for (unsigned byte = 0; byte < size; byte++) {
                            uint64_t value = byte >= bits/8 ? desired_high : desired_low;
                            expected[start+byte] = value>>(8*(byte%(bits/8)));
                        }
                    }
                    uint64_t out[16];
                    for (unsigned i = 0; i < 16; i++) out[i] = canary;
                    unsigned before, after;
                    __asm__ volatile("stmxcsr %0" : "=m"(before));
                    kernels[index](out, p, expected_low, expected_high, desired_low, desired_high, seeds[seed]);
                    __asm__ volatile("stmxcsr %0" : "=m"(after));
                    uint64_t want_low = expected_low, want_high = expected_high;
                    if (!equal) {
                        want_low = bits == 32 ? low : (expected_low&~mask)|low;
                        if (family >= 4) want_high = high;
                    }
                    uint64_t flags = subtraction(expected_low, low, bits);
                    if (family >= 4) {
                        flags = (seeds[seed]&0x8d5)&~UINT64_C(64);
                        if (equal) flags |= 64;
                    }
                    int bad = out[0] != want_low || out[1] != want_high ||
                        out[2] != desired_low || out[3] != desired_high ||
                        (out[4]&0x8d5) != flags || out[5] != ((flags&0xd5)|2) ||
                        (out[6]>>32) != (canary>>32) || (uint32_t)out[6] != before ||
                        after != before || memcmp(raw, expected, sizeof(raw));
                    for (unsigned i = 7; i < 16; i++) bad |= out[i] != canary;
                    if (bad) {
                        kernel_failures++;
                        register_failures += out[0] != want_low || out[1] != want_high ||
                            out[2] != desired_low || out[3] != desired_high;
                        status_failures += (out[4]&0x8d5) != flags || out[5] != ((flags&0xd5)|2);
                        if (kernel_failures <= 2) {
                            fprintf(stdout, "LLVM failure kernel=%u bits=%u edge=%llx equal=%u seed=%llx AX=%llx/%llx DX=%llx/%llx flags=%llx/%llx BX=%llx CX=%llx\n",
                                index, bits, (unsigned long long)edges[edge], equal,
                                (unsigned long long)seeds[seed], (unsigned long long)out[0],
                                (unsigned long long)want_low, (unsigned long long)out[1],
                                (unsigned long long)want_high, (unsigned long long)out[4],
                                (unsigned long long)flags, (unsigned long long)out[2], (unsigned long long)out[3]);
                        }
                        failures++;
                    }
                    observations++;
                }
            }
        }
        if (kernel_failures) {
            printf("LLVM kernel=%u observations=48 failures=%u register=%u status=%u\n",
                index, kernel_failures, register_failures, status_failures);
        }
    }
    printf("LLVM CMPXCHG numerical observations %u failures %u\n", observations, failures);
    return failures ? 1 : 0;
}
`
