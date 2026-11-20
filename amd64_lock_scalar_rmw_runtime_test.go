package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type x86LockScalarRuntimeCase struct {
	name, stem, body string
	width            int
	immediate        bool
	literal          uint64
}

func x86ScalarRuntimeStatusMask(stem string) int {
	switch stem {
	case "BTC", "BTR", "BTS":
		return 0x41 // CF is defined; ZF is preserved. Other status bits are undefined.
	case "AND", "OR", "XOR":
		return 0x8c5 // AF is undefined, not a numerical zero.
	default:
		return 0x8d5
	}
}

func x86LockScalarRuntimeCases(arch string) []x86LockScalarRuntimeCase {
	var rows []x86LockScalarRuntimeCase
	for _, form := range x86LockScalarOracleForms(arch) {
		width := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[form.op[len(form.op)-1]]
		stem := form.op[:len(form.op)-1]
		immediate := strings.Contains(form.text, "$1")
		rows = append(rows, x86LockScalarRuntimeCase{
			name: fmt.Sprintf("sample%d", len(rows)), stem: stem,
			body:  strings.ReplaceAll(strings.Replace(form.text, "1(SI)", "(SI)", 1), "CL,", "CX,"),
			width: width, immediate: immediate, literal: 1,
		})
		if !immediate || stem == "BTC" || stem == "BTR" || stem == "BTS" {
			continue
		}
		// Independent Yi32 boundaries and equal-bit-pattern spellings. Native Q
		// sign-extends imm32; the smaller widths retain their low encoded bits.
		for _, literal := range []uint64{0x7fffffff, 0x80000000, 0xffffffff} {
			rows = append(rows, x86LockScalarRuntimeCase{
				name: fmt.Sprintf("sample%d", len(rows)), stem: stem,
				body: strings.Replace(strings.Replace(form.text, "1(SI)", "(SI)", 1),
					"$1,", fmt.Sprintf("$%d,", literal), 1),
				width: width, immediate: true, literal: literal,
			})
		}
	}
	return rows
}

func x86LockScalarRuntimeFixture(arch string) (declarations, assembly, driver, reference string, count int) {
	rows := x86LockScalarRuntimeCases(arch)
	word, suffix, slot := "uint64", "Q", 8
	if arch == "386" {
		word, suffix, slot = "uint32", "L", 4
	}
	var decl, source, goRows, prototypes, cRows strings.Builder
	decl.WriteString("package main\n")
	for _, row := range rows {
		fmt.Fprintf(&decl, "func %s(memory *[128]byte, output *[8]uint64, offset %s, value %s, seed %s)\n",
			row.name, word, word, word)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", row.name, slot*5)
		fmt.Fprintf(&source, "MOV%s memory+0(FP),SI\nMOV%s output+%d(FP),DI\nMOV%s offset+%d(FP),AX\n",
			suffix, suffix, slot, suffix, slot*2)
		fmt.Fprintf(&source, "ADD%s AX,SI\nMOV%s value+%d(FP),CX\nMOV%s seed+%d(FP),DX\n",
			suffix, suffix, slot*3, suffix, slot*4)
		fmt.Fprintf(&source, "PUSH%s DX\nPOPF%s\nSTMXCSR 24(DI)\nLOCK\n%s\nPUSHF%s\nPOP%s AX\n",
			suffix, suffix, row.body, suffix, suffix)
		// Refine the original saved word before observing it as numerical
		// output. A mask in the C/Go reference cannot define missing source bits.
		fmt.Fprintf(&source, "AND%s $%d,AX\nMOV%s AX,0(DI)\nMOV%s CX,8(DI)\nMOV%s DX,16(DI)\nSTMXCSR 32(DI)\nRET\n",
			suffix, x86ScalarRuntimeStatusMask(row.stem), suffix, suffix, suffix)
		fmt.Fprintf(&goRows, "{%s,%q,%d,%t,%d},\n", row.name, row.stem, row.width, row.immediate, row.literal)
		cWord := "uint64_t"
		if arch == "386" {
			cWord = "uint32_t"
		}
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *, uint64_t *, %s, %s, %s);\n", row.name, cWord, cWord, cWord)
		imm := 0
		if row.immediate {
			imm = 1
		}
		fmt.Fprintf(&cRows, "{%s,%q,%d,%d,UINT64_C(%d)},\n", row.name, row.stem, row.width, imm, row.literal)
	}
	driver = strings.NewReplacer("@WORD@", word, "@ROWS@", goRows.String()).Replace(x86LockScalarOriginalReference)
	cWord := "uint64_t"
	if arch == "386" {
		cWord = "uint32_t"
	}
	reference = strings.NewReplacer("@WORD@", cWord, "@PROTOTYPES@", prototypes.String(), "@ROWS@", cRows.String()).Replace(x86LockScalarIndependentC)
	return decl.String(), source.String(), driver, reference, len(rows)
}

func TestCrossLinuxRuntimeMatrixX86LockScalarRMWOriginalAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declarations, assembly, driver, reference, count := x86LockScalarRuntimeFixture("amd64")
	if count != 174 {
		t.Fatal("independent complete runtime kernel denominator changed", count)
	}
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), runtime.GOOS, "amd64", declarations, assembly, driver)
	want := fmt.Sprintf("lock observations %d\n", count*292*2*8)
	if output := execution.run(t, original); string(output) != want {
		t.Fatalf("actual original Go initialized-memory/defined-flags/canary oracle: %q, want %q", output, want)
	}
	t.Logf("actual original Go: %d kernels / %d complete initialized-memory observations", count, count*292*2*8)
	ir := x86NarrowOracleIR(t, assembly, declarations, execution.triple)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			if output := execution.compileAndRunLLVM(t, "lock-rmw", ir, reference, level); string(output) != want {
				t.Fatalf("independent integer arithmetic/bit-string/memory/flags/canary oracle: %q", output)
			}
			t.Logf("%d complete observations: all initialized memory bytes, defined/preserved status bits, source registers, MXCSR and canaries", count*292*2*8)
		})
	}
}

func TestX86LockScalarRMWOriginal386StaticELFCompileOnly(t *testing.T) {
	declarations, assembly, driver, _, count := x86LockScalarRuntimeFixture("386")
	if count != 129 {
		t.Fatal("complete mode-32 runtime kernel denominator changed", count)
	}
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386", declarations, assembly, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual original Go %d-kernel static IA32 ELF: %d bytes SHA256=%x; execution is a distinct required native axis",
		count, sealed.size, sealed.hash)
}

const x86LockScalarOriginalReference = `package main

import (
	"fmt"
	"math/bits"
	"runtime"
)

type word = @WORD@
type kernel struct {
	fn func(*[128]byte, *[8]uint64, word, word, word)
	op string
	width int
	immediate bool
	literal uint64
}
var kernels = []kernel{
	@ROWS@
}

func load(p *[128]byte, offset, width int) uint64 {
	var value uint64
	for i := 0; i < width/8; i++ {
		value |= uint64(p[offset+i]) << (8*i)
	}
	return value
}

func store(p *[128]byte, offset, width int, value uint64) {
	for i := 0; i < width/8; i++ {
		p[offset+i] = byte(value >> (8*i))
	}
}

func reference(k kernel, memory *[128]byte, offset int, b, seed uint64) (uint64, uint64) {
	mask := ^uint64(0)
	if k.width < 64 {
		mask = (uint64(1) << k.width) - 1
	}
	if k.immediate {
		b = uint64(int64(int32(k.literal)))
	}
	b &= mask
	if k.op == "BTC" || k.op == "BTR" || k.op == "BTS" {
		index := int64(b)
		if k.width == 16 {
			index = int64(int16(b))
		} else if k.width == 32 {
			index = int64(int32(b))
		}
		if k.immediate {
			index = int64(k.literal % uint64(k.width))
		}
		quotient, bit := index/int64(k.width), index%int64(k.width)
		if bit < 0 {
			quotient--
			bit += int64(k.width)
		}
		offset += int(quotient) * (k.width / 8)
		a := load(memory, offset, k.width)
		cf := (a >> uint(bit)) & 1
		switch k.op {
		case "BTC":
			a ^= uint64(1) << uint(bit)
		case "BTR":
			a &^= uint64(1) << uint(bit)
		case "BTS":
			a |= uint64(1) << uint(bit)
		}
		store(memory, offset, k.width, a)
		return cf | seed&64, 65 // Other status bits are architecturally undefined.
	}
	a := load(memory, offset, k.width)
	if k.op == "NOT" {
		store(memory, offset, k.width, ^a)
		return seed & 0x8d5, 0x8d5
	}
	if k.op == "AND" || k.op == "OR" || k.op == "XOR" {
		switch k.op {
		case "AND":
			a &= b
		case "OR":
			a |= b
		case "XOR":
			a ^= b
		}
		a &= mask
		store(memory, offset, k.width, a)
		flags := uint64(0)
		if bits.OnesCount8(uint8(a))%2 == 0 { flags |= 4 }
		if a == 0 { flags |= 64 }
		if a>>(k.width-1) != 0 { flags |= 128 }
		return flags, 0x8c5 // AF is undefined, not preserved or forced to zero.
	}
	carry := uint64(0)
	if k.op == "ADC" || k.op == "SBB" {
		carry = seed & 1
	}
	add := k.op == "ADD" || k.op == "ADC" || k.op == "INC"
	if k.op == "INC" || k.op == "DEC" { b = 1 }
	if k.op == "NEG" { b, a = a, 0 }
	result, cf := bits.Sub64(a, b, carry)
	af := (a & 15) < (b & 15) + carry
	if add {
		result, cf = bits.Add64(a, b, carry)
		if k.width < 64 && result > mask { cf = 1 }
		af = (a & 15) + (b & 15) + carry > 15
	}
	result &= mask
	sign := uint64(1) << (k.width - 1)
	overflow := (a^b)&(a^result)&sign != 0
	if add { overflow = ^(a^b)&(a^result)&sign != 0 }
	if k.op == "INC" || k.op == "DEC" { cf = seed & 1 }
	flags := cf
	if bits.OnesCount8(uint8(result))%2 == 0 { flags |= 4 }
	if af { flags |= 16 }
	if result == 0 { flags |= 64 }
	if result&sign != 0 { flags |= 128 }
	if overflow { flags |= 2048 }
	store(memory, offset, k.width, result)
	return flags, 0x8d5
}

func main() {
	runtime.LockOSThread()
	edges := []uint64{0,1,15,16,17,127,128,255,256,32767,32768,65535,
		0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,^uint64(0)}
	const sentinel = uint64(0xa7a7a7a7a7a7a7a7)
	observations := 0
	var memory, expected [128]byte
	var out [8]uint64
	for _, k := range kernels {
		for sample := 0; sample < 292; sample++ {
			a, b := uint64(sample/16), uint64(sample%16)
			if sample >= 256 {
				a = edges[(sample-256)/2]
				b = edges[((sample-256)/2 + 1 + 6*(sample%2))%len(edges)]
			}
			if (k.op == "BTC" || k.op == "BTR" || k.op == "BTS") && !k.immediate {
				index := []int{-2*k.width-1,-k.width,-1,0,1,k.width-1,k.width,k.width+1,2*k.width}
				b = uint64(int64(index[sample%len(index)]))
			}
			b = uint64(word(b))
			for _, seed := range []uint64{0x8c7, 0x12} {
				for unaligned := 0; unaligned < 8; unaligned++ {
					for i := range memory { memory[i] = byte(i*73+19) ^ byte(sample*29) }
					offset := 64 + unaligned
					store(&memory, offset, k.width, a)
					expected = memory
					for i := range out { out[i] = sentinel }
					flags, valid := reference(k, &expected, offset, b, seed)
					k.fn(&memory, &out, word(offset), word(b), word(seed))
					wordMask := uint64(^word(0))
					if memory != expected || out[0]&valid != flags ||
						out[1]&wordMask != b || out[2]&wordMask != seed ||
						uint32(out[3]) != uint32(out[4]) {
						panic(fmt.Sprintf("%s/%d imm=%t literal=%x sample=%d unaligned=%d b=%x seed=%x flags=%x/%x mask=%x out=%x",
							k.op,k.width,k.immediate,k.literal,sample,unaligned,b,seed,out[0],flags,valid,out))
					}
					for i := 0; i < 3; i++ {
						if out[i]&^wordMask != sentinel&^wordMask { panic("upper output canary") }
					}
					if out[3]>>32 != sentinel>>32 || out[4]>>32 != sentinel>>32 ||
						out[5] != sentinel || out[6] != sentinel || out[7] != sentinel {
						panic("output extent canary")
					}
					observations++
				}
			}
		}
	}
	fmt.Printf("lock observations %d\n", observations)
}
`

// Shared independent arithmetic only. Each execution driver separately owns
// its memory, FLAGS and platform-specific observations.
const x86ScalarMemoryIndependentC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__i386__)
// The largest IA32 operation is 32 bits; 64-bit intermediates close its carry
// and signed-overflow bounds without relying on unsupported int128 on i386.
typedef uint64_t wide_unsigned;
typedef int64_t wide_signed;
#else
typedef __uint128_t wide_unsigned;
typedef __int128 wide_signed;
#endif

@PROTOTYPES@
typedef @WORD@ word;
typedef void (*function)(uint8_t *, uint64_t *, word, word, word);
struct kernel {
	function fn;
	const char *op;
	unsigned width, immediate;
	uint64_t literal;
};
static const struct kernel kernels[] = {
	@ROWS@
};

static uint64_t load(const uint8_t *memory, int offset, unsigned width) {
	uint64_t value = 0;
	for (unsigned i = 0; i < width / 8; i++) {
		value |= (uint64_t)memory[offset + i] << (8 * i);
	}
	return value;
}
static void store(uint8_t *memory, int offset, unsigned width, uint64_t value) {
	for (unsigned i = 0; i < width / 8; i++) {
		memory[offset + i] = value >> (8 * i);
	}
}
static uint64_t reference(const struct kernel *k, uint8_t *memory,
		int offset, uint64_t b, uint64_t seed, uint64_t *valid) {
	uint64_t mask = k->width == 64 ? UINT64_MAX : (UINT64_C(1) << k->width) - 1;
	if (k->immediate) {
		b = (uint64_t)(int64_t)(int32_t)k->literal;
	}
	b &= mask;
	if (!strcmp(k->op, "BTC") || !strcmp(k->op, "BTR") || !strcmp(k->op, "BTS")) {
		int64_t index = (int64_t)b;
		if (k->width == 16) { index = (int16_t)b; }
		if (k->width == 32) { index = (int32_t)b; }
		if (k->immediate) { index = k->literal % k->width; }
		int64_t quotient = index / (int64_t)k->width;
		int64_t bit = index % (int64_t)k->width;
		if (bit < 0) {
			quotient--;
			bit += k->width;
		}
		offset += quotient * (k->width / 8);
		uint64_t a = load(memory, offset, k->width), cf = (a >> bit) & 1;
		uint64_t selected = UINT64_C(1) << bit;
		if (!strcmp(k->op, "BTC")) { a ^= selected; }
		if (!strcmp(k->op, "BTR")) { a &= ~selected; }
		if (!strcmp(k->op, "BTS")) { a |= selected; }
		store(memory, offset, k->width, a);
		*valid = 65;
		return cf | (seed & 64);
	}
	uint64_t a = load(memory, offset, k->width), result;
	*valid = 0x8d5;
	if (!strcmp(k->op, "NOT")) {
		store(memory, offset, k->width, ~a);
		return seed & *valid;
	}
	unsigned cf = 0, af = 0, of = 0;
	if (!strcmp(k->op, "AND") || !strcmp(k->op, "OR") || !strcmp(k->op, "XOR")) {
		result = !strcmp(k->op, "AND") ? a & b : !strcmp(k->op, "OR") ? a | b : a ^ b;
		*valid = 0x8c5;
	} else {
		unsigned carry = !strcmp(k->op, "ADC") || !strcmp(k->op, "SBB") ? seed & 1 : 0;
		unsigned add = !strcmp(k->op, "ADD") || !strcmp(k->op, "ADC") || !strcmp(k->op, "INC");
		if (!strcmp(k->op, "INC") || !strcmp(k->op, "DEC")) { b = 1; }
		if (!strcmp(k->op, "NEG")) { b = a; a = 0; }
		wide_unsigned wide = add ? (wide_unsigned)a + b + carry : (wide_unsigned)a - b - carry;
		result = wide & mask;
		cf = add ? wide > mask : (wide_unsigned)a < (wide_unsigned)b + carry;
		af = add ? (a & 15) + (b & 15) + carry > 15 : (a & 15) < (b & 15) + carry;
		wide_signed sign = (wide_signed)1 << (k->width - 1);
		wide_signed sa = (a & (uint64_t)sign) ? (wide_signed)a - 2 * sign : a;
		wide_signed sb = (b & (uint64_t)sign) ? (wide_signed)b - 2 * sign : b;
		wide_signed signed_wide = add ? sa + sb + carry : sa - sb - carry;
		of = signed_wide < -sign || signed_wide >= sign;
		if (!strcmp(k->op, "INC") || !strcmp(k->op, "DEC")) { cf = seed & 1; }
	}
	result &= mask;
	unsigned ones = 0;
	for (unsigned bit = 0; bit < 8; bit++) { ones += (result >> bit) & 1; }
	uint64_t flags = cf | ((ones % 2 == 0) << 2) | (af << 4) |
		((result == 0) << 6) | ((result >> (k->width - 1)) << 7) | (of << 11);
	store(memory, offset, k->width, result);
	return flags;
}

`

const x86LockScalarIndependentC = x86ScalarMemoryIndependentC + `int main(void) {
	static const uint64_t edges[] = {0,1,15,16,17,127,128,255,256,32767,32768,65535,
		0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,UINT64_MAX};
	const uint64_t sentinel = UINT64_C(0xa7a7a7a7a7a7a7a7);
	unsigned observations = 0;
	for (unsigned kernel = 0; kernel < sizeof(kernels) / sizeof(kernels[0]); kernel++) {
		const struct kernel *k = &kernels[kernel];
		for (unsigned sample = 0; sample < 292; sample++) {
			uint64_t a = sample / 16, b = sample % 16;
			if (sample >= 256) {
				a = edges[(sample - 256) / 2];
				b = edges[((sample - 256) / 2 + 1 + 6 * (sample % 2)) % 18];
			}
			if ((!strcmp(k->op, "BTC") || !strcmp(k->op, "BTR") || !strcmp(k->op, "BTS")) && !k->immediate) {
				const int index[] = {-2*(int)k->width-1,-(int)k->width,-1,0,1,
					(int)k->width-1,(int)k->width,(int)k->width+1,2*(int)k->width};
				b = (uint64_t)(int64_t)index[sample % 9];
			}
			b = (word)b;
			for (unsigned s = 0; s < 2; s++) {
				uint64_t seed = s ? 0x12 : 0x8c7;
				for (unsigned unaligned = 0; unaligned < 8; unaligned++) {
					uint8_t memory[128], expected[128];
					uint64_t out[8];
					for (unsigned i = 0; i < 128; i++) { memory[i] = (i*73+19) ^ (sample*29); }
					int offset = 64 + unaligned;
					store(memory, offset, k->width, a);
					memcpy(expected, memory, 128);
					for (unsigned i = 0; i < 8; i++) { out[i] = sentinel; }
					uint64_t valid, flags = reference(k, expected, offset, b, seed, &valid);
					unsigned before_csr, after_csr;
					__asm__ volatile("stmxcsr %0" : "=m"(before_csr));
					k->fn(memory, out, offset, b, seed);
					__asm__ volatile("stmxcsr %0" : "=m"(after_csr));
					uint64_t word_mask = (word)~(word)0;
					if (memcmp(memory, expected, 128) || (out[0] & valid) != flags ||
							(out[1] & word_mask) != b || (out[2] & word_mask) != seed ||
							(uint32_t)out[3] != before_csr || (uint32_t)out[4] != before_csr ||
							after_csr != before_csr) {
						fprintf(stderr, "%s/%u imm=%u literal=%llx sample=%u unaligned=%u b=%llx seed=%llx flags=%llx/%llx mask=%llx\n",
							k->op,k->width,k->immediate,(unsigned long long)k->literal,sample,unaligned,
							(unsigned long long)b,(unsigned long long)seed,(unsigned long long)out[0],
							(unsigned long long)flags,(unsigned long long)valid);
						return 1;
					}
					for (unsigned i = 0; i < 3; i++) {
						if ((out[i] & ~word_mask) != (sentinel & ~word_mask)) { return 2; }
					}
					if (out[3] >> 32 != sentinel >> 32 || out[4] >> 32 != sentinel >> 32 ||
							out[5] != sentinel || out[6] != sentinel || out[7] != sentinel) { return 3; }
					observations++;
				}
			}
		}
	}
	printf("lock observations %u\n", observations);
	return 0;
}
`
