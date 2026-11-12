package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Independent runtime metadata follows the test's Go encoder rows, never the
// production descriptor. This exact-result oracle excludes four W double
// forms with unspecified low16 outcomes. Their whole-object/paired-access and
// producer-consistency controls have independent architectural-choice owners.
type x86ShiftMemoryRuntimeRow struct {
	x86ShiftMemoryOracle
	kind, count int
	flags       uint64
}

func x86ShiftMemoryRuntimeRows(arch string) []x86ShiftMemoryRuntimeRow {
	var rows []x86ShiftMemoryRuntimeRow
	for _, row := range x86ScalarShiftMemoryRows(arch) {
		if row.valueChoice {
			continue
		}
		rows = append(rows, x86ShiftMemoryRuntimeMetadata(row))
	}
	return rows
}

// The independent runtime directory and official-row object producer share
// observation metadata, never a production permission for undefined FLAGS.
func x86ShiftMemoryRuntimeMetadata(row x86ShiftMemoryOracle) x86ShiftMemoryRuntimeRow {
	op, operands, _ := strings.Cut(row.text, " ")
	stem := op[:len(op)-1]
	kind := -1
	for i, name := range []string{"RCL", "RCR", "ROL", "ROR", "SAL", "SAR", "SHL", "SHR", "SHL", "SHR", "SARX", "SHLX", "SHRX", "RORX"} {
		if name == stem && (i < 8) == (strings.Count(operands, ",") == 1) {
			kind = i
		}
	}
	count := -1
	if first, _, _ := strings.Cut(operands, ","); strings.HasPrefix(first, "$") {
		var err error
		count, err = strconv.Atoi(first[1:])
		if err != nil {
			panic(err)
		}
		count &= 31
		if row.bits == 64 {
			original, _ := strconv.Atoi(first[1:])
			count = original & 63
		}
	}
	if kind < 0 {
		panic("unregistered independent scalar-shift reference")
	}
	flags := uint64(0x8d5)
	if kind < 10 && count != 0 {
		if count != 1 {
			flags &^= 0x800 // OF is undefined, not a value to compare.
		}
		if kind >= 4 {
			flags &^= 0x10 // AF is undefined after nonzero shifts.
			if row.bits < 32 && kind != 5 && count < 0 {
				flags &^= 1 // B/W logical counts can make CF undefined.
			}
		}
	}
	if row.valueChoice {
		// Some W double counts have no defined data/status expectation. Their
		// existing paired lowering can choose a finite value, not known FLAGS.
		flags = 0
	}
	return x86ShiftMemoryRuntimeRow{row, kind, count, flags}
}

func x86ShiftMemoryRuntimeFixture(arch string, rows []x86ShiftMemoryRuntimeRow) (string, string, string) {
	word, move, suffix, cword := 8, "MOVQ", "Q", "uint64_t"
	if arch == "386" {
		word, move, suffix, cword = 4, "MOVL", "L", "uint32_t"
	}
	var source, declaration, prototypes, metadata strings.Builder
	for i, row := range rows {
		name := fmt.Sprint("MemoryShift", i)
		fmt.Fprintf(&declaration, "func %s(p *[128]byte,out *[8]uint64,value,count,seed uintptr)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", name, word*5)
		fmt.Fprintf(&source, "%s p+0(FP),DI\n%s out+%d(FP),SI\n%s value+%d(FP),AX\n%s count+%d(FP),CX\n%s seed+%d(FP),DX\n",
			move, move, word, move, word*2, move, word*3, move, word*4)
		fmt.Fprintf(&source, "PUSH%s DX\nPOPF%s\n%s\nPUSHF%s\nPOP%s DX\nAND%s $%d,DX\n",
			suffix, suffix, row.text, suffix, suffix, suffix, row.flags)
		fmt.Fprintf(&source, "%s DX,0(SI)\n%s AX,8(SI)\n%s CX,16(SI)\nRET\n", move, move, move)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint64_t*,word,word,word);\n", name)
		fmt.Fprintf(&metadata, "{%s,%d,%d,%d,%d},\n", name, row.bits, row.kind, row.count, row.flags)
	}
	driver := strings.NewReplacer("@WORD@", cword, "@PROTOTYPES@", prototypes.String(),
		"@ROWS@", metadata.String()).Replace(x86ShiftMemoryReferenceC)
	return source.String(), declaration.String(), driver
}

func x86ShiftMemoryPortableRuntime(t *testing.T, api string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, originalTriple, want := "amd64", "x86_64-unknown-linux-gnu", 144
	if strconv.IntSize == 32 {
		arch, originalTriple, want = "386", "i386-unknown-linux-gnu", 106
	}
	rows := x86ShiftMemoryRuntimeRows(arch)
	if len(rows) != want {
		t.Fatal("incomplete defined-count memory runtime denominator", len(rows), want)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for first := 0; first < len(rows); first += 72 {
		last := first + 72
		if last > len(rows) {
			last = len(rows)
		}
		t.Run(fmt.Sprint("batch-", first/72), func(t *testing.T) {
			source, declaration, driver := x86ShiftMemoryRuntimeFixture(arch, rows[first:last])
			x86LEAActualTargetGoObject(t, arch, originalTriple, source)
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete initialized memory runtime rejected", err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "scalar-shift-memory", triple,
							text, driver, nil, level)
					})
				}
			}
		})
	}
	t.Logf("%d kernels: all imm8 runtime counts, both carry seeds, exact memory/GP bytes, defined FLAGS and canaries; portable LLVM, not native x86 execution", len(rows))
}

func TestX86ScalarShiftMemoryPortableTextRuntime(t *testing.T) {
	x86ShiftMemoryPortableRuntime(t, "text")
}

func TestX86ScalarShiftMemoryPortableModuleRuntime(t *testing.T) {
	x86ShiftMemoryPortableRuntime(t, "module")
}

func TestX86ScalarShiftMemoryPortableGoRuntime(t *testing.T) {
	x86ShiftMemoryPortableRuntime(t, "Go")
}

// Repeated single-bit operations deliberately do not mirror LLVM's lowering.
// Native access/fault behavior has its own original-Go execution oracle.
const x86ShiftMemoryReferenceC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef @WORD@ word;
@PROTOTYPES@
typedef struct {
    void (*fn)(uint8_t*,uint64_t*,word,word,word);
    unsigned bits, kind;
    int count;
    uint64_t flags;
} Kernel;
static const Kernel kernels[] = {@ROWS@};
/* Original Go opcode definitions. */

static uint64_t reference(Kernel k, uint64_t input, uint64_t source,
        unsigned count, uint64_t seed, uint64_t *status) {
    const uint64_t mask = k.bits == 64 ? UINT64_MAX : (UINT64_C(1)<<k.bits)-1;
    uint64_t value = input & mask, old = value;
    unsigned cf = seed&1, pf = (seed>>2)&1, af = (seed>>4)&1;
    unsigned zf = (seed>>6)&1, sf = (seed>>7)&1, of = (seed>>11)&1;
    count = (k.count >= 0 ? (unsigned)k.count : count) & (k.bits == 64 ? 63 : 31);
    source &= mask;
    unsigned effective = count;
    if (k.kind < 2) effective %= k.bits+1;
    if (k.kind == 2 || k.kind == 3) effective %= k.bits;
    for (unsigned i = 0; i < effective; i++) {
        unsigned next;
        switch (k.kind) {
        case 0:
            next = value>>(k.bits-1);
            value = ((value<<1)|cf)&mask;
            cf = next;
            break;
        case 1:
            next = value&1;
            value = (value>>1)|((uint64_t)cf<<(k.bits-1));
            cf = next;
            break;
        case 2:
            cf = value>>(k.bits-1);
            value = ((value<<1)|cf)&mask;
            break;
        case 3:
            cf = value&1;
            value = (value>>1)|((uint64_t)cf<<(k.bits-1));
            break;
        case 4: case 6: case 11:
            cf = value>>(k.bits-1);
            value = (value<<1)&mask;
            break;
        case 5: case 10:
            cf = value&1;
            value = (value>>1)|(value&(UINT64_C(1)<<(k.bits-1)));
            break;
        case 7: case 12:
            cf = value&1;
            value >>= 1;
            break;
        case 8:
            cf = value>>(k.bits-1);
            value = ((value<<1)|((source>>(k.bits-i-1))&1))&mask;
            break;
        case 9:
            cf = value&1;
            value = (value>>1)|(((source>>i)&1)<<(k.bits-1));
            break;
        case 13:
            value = (value>>1)|((value&1)<<(k.bits-1));
            break;
        }
    }
    if (k.kind >= 10) {
        *status = seed&k.flags;
        return value;
    }
    if (count && k.kind < 4) {
        if (k.kind == 2) cf = value&1;
        if (k.kind == 3) cf = value>>(k.bits-1);
        if (count == 1) {
            of = k.kind == 0 || k.kind == 2 ? (value>>(k.bits-1))^cf :
                ((value>>(k.bits-1))^(value>>(k.bits-2)))&1;
        }
    } else if (count) {
        zf = value == 0;
        sf = value>>(k.bits-1);
        pf = (__builtin_popcount((uint8_t)value)&1) == 0;
        if (count == 1) {
            if (k.kind >= 8) of = (old^value)>>(k.bits-1);
            else if (k.kind == 5) of = 0;
            else if (k.kind == 7) of = old>>(k.bits-1);
            else of = (value>>(k.bits-1))^cf;
        }
    }
    *status = (cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7)|(of<<11))&k.flags;
    return value;
}

int main(void) {
    const uint64_t samples[] = {0,1,UINT64_MAX,UINT64_C(0x8000000080000000),
        UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0x8877665544332211)};
    const uint64_t sentinel = UINT64_C(0xa7a7a7a7a7a7a7a7);
    unsigned observations = 0;
    for (unsigned kernel = 0; kernel < sizeof(kernels)/sizeof(kernels[0]); kernel++) {
        const Kernel k = kernels[kernel];
        for (unsigned n = 0; n < 256; n++) {
            for (unsigned sample = 0; sample < 7; sample++) {
                for (unsigned carry = 0; carry < 2; carry++) {
                    unsigned offset = 32+(sample+n)%8;
                    uint8_t memory[128], expected[128];
                    uint64_t output[8], wanted[8];
                    for (unsigned i = 0; i < 128; i++) memory[i] = i*37+91;
                    for (unsigned b = 0; b < k.bits/8; b++) memory[offset+b] = samples[sample]>>(8*b);
                    memcpy(expected,memory,sizeof(memory));
                    for (unsigned i = 0; i < 8; i++) output[i] = wanted[i] = sentinel;
                    word value = (word)samples[(sample+3)%7];
                    word count = (word)(n|UINT64_C(0x1234567800000000));
                    word seed = carry ? 0x8c7 : 0x12;
                    uint64_t flags, result = reference(k,samples[sample],value,count,seed,&flags);
                    uint64_t ax = value;
                    if (k.kind >= 10) ax = result;
                    else for (unsigned b = 0; b < k.bits/8; b++) expected[offset+b] = result>>(8*b);
                    word status = (word)flags, resultWord = (word)ax;
                    memcpy(wanted,&status,sizeof(word));
                    memcpy(wanted+1,&resultWord,sizeof(word));
                    memcpy(wanted+2,&count,sizeof(word));
#ifdef ORIGINAL_NATIVE
                    uint8_t originalMemory[128];
                    uint64_t originalOutput[8];
                    memcpy(originalMemory,memory,sizeof(memory));
                    memcpy(originalOutput,output,sizeof(output));
#endif
                    k.fn(memory+offset-1,output,value,count,seed);
                    if (memcmp(memory,expected,sizeof(memory)) || memcmp(output,wanted,sizeof(output))) {
                        fprintf(stderr,"kernel%u bits%u kind%u count%u sample%u carry%u: memory/FLAGS/GP/canary mismatch\n",
                            kernel,k.bits,k.kind,n,sample,carry);
                        return 1;
                    }
#ifdef ORIGINAL_NATIVE
                    originals[kernel](originalMemory+offset-1,originalOutput,value,count,seed);
                    if (memcmp(originalMemory,expected,sizeof(memory)) || memcmp(originalOutput,wanted,sizeof(output))) {
                        fprintf(stderr,"original kernel%u bits%u kind%u count%u sample%u carry%u mismatch\n",
                            kernel,k.bits,k.kind,n,sample,carry);
                        return 3;
                    }
#endif
                    observations++;
                }
            }
        }
    }
    if (observations != sizeof(kernels)/sizeof(kernels[0])*256*7*2) return 2;
#ifdef ORIGINAL_NATIVE
    if (check_faults()) return 4;
#endif
    printf("scalar shift memory observations %u\n",observations);
    return 0;
}
`
