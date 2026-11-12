//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type fixedLocalMachineRuntimeCase struct {
	operation, bits, left, right, carry int
	destinationShift, sourceShift       int
	body                                string
}

// Native pointers contribute their actual initialized bits. The independent
// Go and C references each use their own buffers' addresses, never assume the
// same linker/stack layout, and check every canary byte after the assembly call.
func fixedLocalMachineRuntimeCases() []fixedLocalMachineRuntimeCase {
	flags := "SETCS 0(R8)\nSETEQ 1(R8)\nSETMI 2(R8)\nSETOS 3(R8)\nSETPS 4(R8)\n"
	var rows []fixedLocalMachineRuntimeCase
	for wi, suffix := range []string{"B", "W", "L", "Q"} {
		for op, stem := range []string{"ADD", "ADC", "SUB", "SBB", "AND", "OR", "XOR"} {
			for _, left := range []int{0, 1} {
				for _, right := range []int{0, 2} {
					for carry := 0; carry < 2; carry++ {
						register := []string{"AX", "SI", "DI"}
						body := "MOVQ SI,R8\nMOVQ " + register[left] + ",BX\nMOVQ " + register[right] + ",CX\nCMPQ AX,AX\n"
						if carry != 0 {
							body += "STC\n"
						}
						body += stem + suffix + " CX,BX\n" + flags + "XORQ $0,BX\nMOVQ BX,AX"
						rows = append(rows, fixedLocalMachineRuntimeCase{op, []int{8, 16, 32, 64}[wi], left, right, carry, 0, 0, body})
					}
				}
			}
		}
	}
	for _, operand := range []struct {
		source string
		role   int
	}{{"SI", 1}, {"p+0(FP)", 1}} {
		body := "MOVQ SI,R8\nMULQ " + operand.source + "\nSETCS 0(R8)\nMOVB $0,1(R8)\nMOVB $0,2(R8)\nSETOS 3(R8)\nMOVB $0,4(R8)"
		rows = append(rows, fixedLocalMachineRuntimeCase{7, 64, 0, operand.role, 0, 0, 0, body})
	}
	for _, shifts := range [][2]int{{0, 8}, {8, 0}} {
		registers := map[int]string{0: "AL", 8: "AH"}
		body := "MOVQ SI,R8\nMOVQ SI,AX\nSUBB " + registers[shifts[1]] + "," + registers[shifts[0]] + "\n" + flags + "XORQ $0,AX"
		rows = append(rows, fixedLocalMachineRuntimeCase{2, 8, 1, 1, 0, shifts[0], shifts[1], body})
	}
	return rows
}

func fixedLocalMachineRuntimeScope(scope string) []fixedLocalMachineRuntimeCase {
	rows := fixedLocalMachineRuntimeCases()
	if scope == "machine" {
		return rows
	}
	if scope == "auxiliary" {
		var selected []fixedLocalMachineRuntimeCase
		for _, row := range rows {
			if row.operation > 3 || row.bits != 64 || row.left != 1 || row.right != 0 {
				continue
			}
			// Preserve BX and the five SETcc observations. AH cannot be
			// encoded directly with the REX prefix required by an R8 address.
			row.body = strings.Replace(row.body, "XORQ $0,BX",
				"LAHF\nMOVB AH,CL\nANDB $16,CL\nMOVB CL,5(R8)\nXORQ $0,BX", 1)
			selected = append(selected, row)
		}
		return selected
	}
	if scope == "vector spill" {
		return []fixedLocalMachineRuntimeCase{{operation: 8, bits: 64, left: 1,
			body: "MOVQ SI,R8\nMOVQ SP,R11\nANDQ $-16,SP\nADDQ $16,SP\n" +
				"MOVQ SI,16(SP)\nMOVQ AX,24(SP)\nCMPQ AX,AX\n" +
				"PXOR X0,X0\nPADDQ 16(SP),X0\nMOVQ R11,SP\n" +
				"SETCS 0(R8)\nSETEQ 1(R8)\nSETMI 2(R8)\nSETOS 3(R8)\nSETPS 4(R8)\nMOVQ X0,AX",
		}}
	}
	if scope == "multiply" {
		var selected []fixedLocalMachineRuntimeCase
		for _, stem := range []string{"MUL", "IMUL"} {
			operation := 7
			if stem == "IMUL" {
				operation = 9
			}
			for _, width := range fixedLocalImplicitMultiplyWidths {
				for _, accumulator := range []bool{false, true} {
					left, right := 0, 1
					body := "MOVQ SI,R8\nMOVQ SI,CX\n" + stem + width.suffix + " CX\n"
					if accumulator {
						left, right = 1, 0
						body = "MOVQ SI,R8\nMOVQ SI,AX\n" + stem + width.suffix + " 0(SP)\n"
					}
					body += "SETCS 0(R8)\nMOVB $0,1(R8)\nMOVB $0,2(R8)\nSETOS 3(R8)\nMOVB $0,4(R8)"
					selected = append(selected, fixedLocalMachineRuntimeCase{
						operation: operation, bits: int(width.width * 8), left: left, right: right, body: body,
					})
				}
			}
		}
		return selected
	}
	return nil
}

func fixedLocalMachineBitsRuntimeProgram(t *testing.T, triple, scope string) (assembly, declarations, original, driver string) {
	t.Helper()
	rows := fixedLocalMachineRuntimeScope(scope)
	want := map[string]int{"machine": 228, "auxiliary": 8, "vector spill": 1, "multiply": 16}[scope]
	if want == 0 || len(rows) != want {
		t.Fatal("independent machine-bit runtime inventory changed", len(rows))
	}
	checkedFlags := 5
	if scope == "auxiliary" {
		checkedFlags = 6
	}
	var functions []fixedLocalPointerChoiceCase
	var goRows, cRows, goFunctions, cFunctions, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, row := range rows {
		functions = append(functions, fixedLocalPointerChoiceCase{fmt.Sprintf("machine%d", index), row.body})
		fields := fmt.Sprintf("{%d,%d,%d,%d,%d,%d,%d},", row.operation, row.bits, row.left, row.right, row.carry, row.destinationShift, row.sourceShift)
		goRows.WriteString(fields)
		cRows.WriteString(fields)
		fmt.Fprintf(&goFunctions, "Value%d,", index)
		fmt.Fprintf(&cFunctions, "value%d,", index)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t*,uint64_t*,uint64_t) __asm__(%s);\n", index,
			runtimeCAsmLabel(prefix+fmt.Sprintf("example.invalid/framefixture.Value%d", index)))
	}
	assembly, declarations = fixedLocalPointerChoiceProgram(t, "", functions)
	original = `package main

import (
	"fmt"
	"math/bits"
	"unsafe"
)

` + fmt.Sprintf("const checkedFlags = %d\n", checkedFlags) + declarations + `

type row struct{ op, width, left, right, carry, ds, ss int }

var rows = []row{` + goRows.String() + `}

func reference(c row, base, other, a uint64) (uint64, [6]byte) {
	values := [3]uint64{a, base, other}
	old := values[c.left]
	if c.op == 8 {
		// The vector adds zero to the spilled native address. Integer FLAGS
		// still describe the equal comparison preceding the vector operation.
		return old, [6]byte{0, 1, 0, 0, 1, 0}
	}
	mask := ^uint64(0)
	if c.width < 64 {
		mask = (uint64(1) << c.width) - 1
	}
	x, y := (old>>c.ds)&mask, (values[c.right]>>c.ss)&mask
	sign := uint64(1) << (c.width - 1)
	var r, cf, of uint64
	switch c.op {
	case 0, 1:
		carry := uint64(0)
		if c.op == 1 {
			carry = uint64(c.carry)
		}
		r, cf = bits.Add64(x, y, carry)
		if c.width < 64 && r > mask {
			cf = 1
		}
		r &= mask
		if (^(x ^ y) & (x ^ r) & sign) != 0 {
			of = 1
		}
	case 2, 3:
		carry := uint64(0)
		if c.op == 3 {
			carry = uint64(c.carry)
		}
		r, cf = bits.Sub64(x, y, carry)
		r &= mask
		if ((x ^ y) & (x ^ r) & sign) != 0 {
			of = 1
		}
	case 4:
		r = x & y
	case 5:
		r = x | y
	case 6:
		r = x ^ y
	case 7:
		hi, lo := bits.Mul64(x, y)
		r = lo
		if hi != 0 || c.width < 64 && lo>>c.width != 0 {
			cf, of = 1, 1
		}
	case 9:
		if x&sign != 0 {
			x |= ^mask
		}
		if y&sign != 0 {
			y |= ^mask
		}
		hi, lo := bits.Mul64(x, y)
		if int64(x) < 0 {
			hi -= y
		}
		if int64(y) < 0 {
			hi -= x
		}
		r = lo
		low, high := lo&mask, uint64(0)
		if low&sign != 0 {
			low |= ^mask
			high = ^uint64(0)
		}
		if lo != low || hi != high {
			cf, of = 1, 1
		}
	default:
		panic("unknown reference")
	}
	flags := [6]byte{byte(cf), 0, 0, byte(of), 0, 0}
	if checkedFlags == 6 {
		carry := uint64(0)
		if c.op == 1 || c.op == 3 {
			carry = uint64(c.carry)
		}
		if c.op < 2 && (x&15)+(y&15)+carry > 15 ||
			c.op >= 2 && (x&15) < (y&15)+carry {
			flags[5] = 16
		}
	}
	if c.op != 7 && c.op != 9 {
		if r == 0 {
			flags[1] = 1
		}
		if r&sign != 0 {
			flags[2] = 1
		}
		if bits.OnesCount8(uint8(r))%2 == 0 {
			flags[4] = 1
		}
	}
	if c.op == 7 || c.op == 9 {
		if c.width == 8 {
			mask = 65535 // Byte multiply writes AX; word multiply also writes AX.
		}
		r &= mask
	}
	if c.width < 32 {
		r = (old &^ (mask << c.ds)) | (r << c.ds)
	}
	return r, flags
}
func main() {
	functions := []func(*uint64, *uint64, uint64) uint64{` + goFunctions.String() + `}
	for index, fn := range functions {
		for alias := 0; alias < 2; alias++ {
			var left, right [32]uint64
			p, q := &left[4], &right[4]
			if alias != 0 {
				q = p
			}
			base, other := uint64(uintptr(unsafe.Pointer(p))), uint64(uintptr(unsafe.Pointer(q)))
			inputs := []uint64{
				0, 1, 7, 8, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
				1<<31 - 1, 1 << 31, 1<<63 - 1, 1 << 63, ^uint64(0),
				-base, other - base, base,
			}
			for sample, a := range inputs {
				for i := range left {
					left[i] = uint64(i+1)*0x0102030405060708 ^ a
					right[i] = ^left[i]
				}
				wantLeft, wantRight := left, right
				want, flags := reference(rows[index], base, other, a)
				bytes := (*[256]byte)(unsafe.Pointer(&wantLeft))
				for i, f := range flags[:checkedFlags] {
					bytes[32+i] = f
				}
				got := fn(p, q, a)
				if got != want || left != wantLeft || right != wantRight {
					panic(fmt.Sprintf("case=%d sample=%d alias=%d got=%016x want=%016x", index, sample, alias, got, want))
				}
				fmt.Printf("%d %d %d PASS\n", index, alias, sample)
			}
		}
	}
}
`
	driver = "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		fmt.Sprintf("enum { function_count = %d, checked_flags = %d };\n", len(rows), checkedFlags) +
		runtimeCAsmLabelPreamble + cDeclarations.String() + `
typedef struct {
    unsigned op, width, left, right, carry, ds, ss;
} row;
static const row rows[] = {
    ` + cRows.String() + `
};
static uint64_t reference(row c, uint64_t base, uint64_t other, uint64_t a,
                          unsigned char flags[6]) {
    uint64_t values[] = {a, base, other}, old = values[c.left];
    if (c.op == 8) {
        const unsigned char equal_flags[] = {0, 1, 0, 0, 1, 0};
        memcpy(flags, equal_flags, sizeof equal_flags);
        return old;
    }
    uint64_t mask = c.width == 64 ? UINT64_MAX : (UINT64_C(1) << c.width) - 1;
    uint64_t x = (old >> c.ds) & mask, y = (values[c.right] >> c.ss) & mask,
             sign = UINT64_C(1) << (c.width - 1), r = 0;
    unsigned cf = 0, of = 0;
    switch (c.op) {
    case 0:
    case 1: {
        __uint128_t wide = (__uint128_t)x + y + (c.op == 1 ? c.carry : 0);
        r = (uint64_t)wide & mask;
        cf = wide > mask;
        of = (~(x ^ y) & (x ^ r) & sign) != 0;
        break;
    }
    case 2:
    case 3: {
        __uint128_t rhs = (__uint128_t)y + (c.op == 3 ? c.carry : 0);
        r = (uint64_t)((__uint128_t)x - rhs) & mask;
        cf = (__uint128_t)x < rhs;
        of = ((x ^ y) & (x ^ r) & sign) != 0;
        break;
    }
    case 4:
        r = x & y;
        break;
    case 5:
        r = x | y;
        break;
    case 6:
        r = x ^ y;
        break;
    case 7: {
        __uint128_t wide = (__uint128_t)x * y;
        r = (uint64_t)wide;
        cf = of = wide > mask;
        break;
    }
    case 9: {
        __int128 sx = x, sy = y;
        if (x & sign)
            sx -= (__int128)1 << c.width;
        if (y & sign)
            sy -= (__int128)1 << c.width;
        __int128 wide = sx * sy;
        r = (uint64_t)wide;
        __int128 limit = (__int128)1 << (c.width - 1);
        cf = of = wide < -limit || wide >= limit;
        break;
    }
    default:
        return 0;
    }
    flags[0] = cf;
    flags[1] = 0;
    flags[2] = 0;
    flags[3] = of;
    flags[4] = 0;
    flags[5] = 0;
    if (checked_flags == 6) {
        unsigned carry = c.op == 1 || c.op == 3 ? c.carry : 0;
        unsigned low_left = x & 15, low_right = (y & 15) + carry;
        if (c.op < 2 ? low_left + low_right > 15 : low_left < low_right) {
            flags[5] = 16;
        }
    }
    if (c.op != 7 && c.op != 9) {
        unsigned parity = 0;
        for (unsigned b = 0; b < 8; b++)
            parity ^= (r >> b) & 1;
        flags[1] = r == 0;
        flags[2] = (r & sign) != 0;
        flags[4] = !parity;
    }
    if (c.op == 7 || c.op == 9) {
        if (c.width == 8)
            mask = 65535;
        r &= mask;
    }
    if (c.width < 32)
        r = (old & ~(mask << c.ds)) | (r << c.ds);
    return r;
}
int main(void) {
    uint64_t (*functions[])(uint64_t *, uint64_t *, uint64_t) = {
        ` + cFunctions.String() + `
    };
    for (unsigned index = 0; index < function_count; index++)
        for (unsigned alias = 0; alias < 2; alias++) {
            uint64_t left[32], right[32], wantLeft[32], wantRight[32];
            uint64_t *p = &left[4], *q = alias ? p : &right[4];
            uint64_t base = (uintptr_t)p, other = (uintptr_t)q;
            uint64_t inputs[] = {0,
                                 1,
                                 7,
                                 8,
                                 127,
                                 128,
                                 255,
                                 256,
                                 32767,
                                 32768,
                                 65535,
                                 65536,
                                 (UINT64_C(1) << 31) - 1,
                                 UINT64_C(1) << 31,
                                 (UINT64_C(1) << 63) - 1,
                                 UINT64_C(1) << 63,
                                 UINT64_MAX,
                                 -base,
                                 other - base,
                                 base};
            for (unsigned sample = 0; sample < 20; sample++) {
                uint64_t a = inputs[sample];
                for (unsigned i = 0; i < 32; i++) {
                    left[i] = (uint64_t)(i + 1) * UINT64_C(0x0102030405060708) ^ a;
                    right[i] = ~left[i];
                }
                memcpy(wantLeft, left, sizeof left);
                memcpy(wantRight, right, sizeof right);
                unsigned char flags[6];
                uint64_t want = reference(rows[index], base, other, a, flags);
                memcpy((unsigned char *)wantLeft + 32, flags, checked_flags);
                uint64_t got = functions[index](p, q, a);
                if (got != want || memcmp(left, wantLeft, sizeof left) ||
                    memcmp(right, wantRight, sizeof right)) {
                    fprintf(stderr, "case=%u sample=%u alias=%u got=%016llx want=%016llx\n", index,
                            sample, alias, (unsigned long long)got, (unsigned long long)want);
                    return 1;
                }
                printf("%u %u %u PASS\n", index, alias, sample);
            }
        }
    return 0;
}
`
	return
}

func fixedLocalMachineBitsRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	fixedLocalMachineRuntime(t, execution, execute, "machine")
}

func fixedLocalMachineRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool, scope string) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	assembly, declarations, original, driver := fixedLocalMachineBitsRuntimeProgram(t, execution.triple, scope)
	count := len(fixedLocalMachineRuntimeScope(scope))
	var want []string
	for index := 0; index < count; index++ {
		for alias := 0; alias < 2; alias++ {
			for sample := 0; sample < 20; sample++ {
				want = append(want, fmt.Sprintf("%d %d %d PASS", index, alias, sample))
			}
		}
	}
	check := func(output []byte) {
		t.Helper()
		if strings.TrimSpace(string(output)) != strings.Join(want, "\n") {
			t.Fatalf("incomplete machine-bit arithmetic oracle:\n%s", output)
		}
	}
	if execute {
		check(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))
	} else {
		x86COMICompileOriginalGo(t, map[string]string{"go.mod": "module machinebits\ngo 1.20\n", "main.go": original, "original_amd64.s": assembly}, false)
	}
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalResultsRuntimeAPIs(t, pkg, request, file, options, assembly, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(level, func(t *testing.T) {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				if execute {
					check(execution.compileAndRunLLVM(t, "machine-bits", input, driver, level))
				} else {
					execution.compileLLVM(t, "machine-bits", input, driver, level)
				}
			})
		}
	})
	t.Logf("%s: %d complete functions, 20 actual-address samples, two aliases and all 512 canary bytes; execute=%v", scope, count, execute)
}

func TestGoAMD64FixedLocalMachineBitsRuntimeObjects(t *testing.T) {
	fixedLocalMachineBitsRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}

func TestGoAMD64FixedLocalMachineSupplementalRuntimeObjects(t *testing.T) {
	for _, scope := range []string{"auxiliary", "vector spill", "multiply"} {
		t.Run(scope, func(t *testing.T) {
			fixedLocalMachineRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, scope)
		})
	}
}
