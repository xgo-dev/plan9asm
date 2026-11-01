package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86LODSStateCase struct {
	name, arch, op, prefix string
	width, count           int
	backward               bool
}

type x86LODSStateReference struct {
	ax, cx, flags uint64
	siDelta       int
}

func x86LODSStateCases(arch string) []x86LODSStateCase {
	var cases []x86LODSStateCase
	for _, width := range []struct {
		suffix string
		bytes  int
	}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
		if arch == "386" && width.bytes == 8 {
			continue
		}
		for _, prefix := range []string{"", "REP", "REPN"} {
			for _, count := range []int{0, 3} {
				for _, backward := range []bool{false, true} {
					cases = append(cases, x86LODSStateCase{
						name: fmt.Sprintf("lodsstate%d", len(cases)), arch: arch,
						op: "LODS" + width.suffix, prefix: prefix,
						width: width.bytes, count: count, backward: backward,
					})
				}
			}
		}
	}
	return cases
}

func x86LODSStateSeed(arch string) uint64 {
	if arch == "386" {
		return 0x55667788
	}
	return 0x1122334455667788
}

// The reference models only the explicit initialized fixture state. It never
// gives an unspecified incoming register byte a value or authenticates memory.
func x86LODSStateExpected(row x86LODSStateCase) x86LODSStateReference {
	executions := row.count
	if row.prefix == "" {
		executions = 1 // Without REP/REPN, CX does not suppress the instruction.
	}
	state := x86LODSStateReference{ax: x86LODSStateSeed(row.arch), cx: uint64(row.count), flags: 0x890}
	step := row.width
	if row.backward {
		step = -step
		state.flags |= 1 << 10
	}
	if executions != 0 {
		address := 32 + (executions-1)*step
		var value uint64
		for index := 0; index < row.width; index++ {
			value |= uint64(byte((address+index)*37+11)) << (8 * index)
		}
		if row.width >= 4 {
			state.ax = value
		} else {
			mask := uint64(1)<<(8*row.width) - 1
			state.ax = state.ax&^mask | value
		}
	}
	state.siDelta = executions * step
	if row.prefix != "" {
		state.cx = 0
	}
	return state
}

func x86LODSStateFixture(arch string) (string, string) {
	word, move, typ, push, pop := 8, "MOVQ", "uint64", "PUSHFQ", "POPQ"
	if arch == "386" {
		word, move, typ, push, pop = 4, "MOVL", "uint32", "PUSHFL", "POPL"
	}
	var source, declarations strings.Builder
	for _, row := range x86LODSStateCases(arch) {
		fmt.Fprintf(&declarations, "func %s(out *%s, src *byte)\n", row.name, typ)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s src+%d(FP),SI\n",
			row.name, 2*word, move, move, word)
		// 0x7f+1 defines all six status flags: AF/SF/OF set, CF/PF/ZF clear.
		// The subsequent moves preserve them. Every accumulator byte is real
		// initialized numerical fixture data, including a nonzero AMD64 high32.
		fmt.Fprintf(&source, "MOVB $127,AL\nADDB $1,AL\n%s $%d,AX\n%s $%d,CX\n",
			move, x86LODSStateSeed(arch), move, row.count)
		if row.backward {
			source.WriteString("STD\n")
		} else {
			source.WriteString("CLD\n")
		}
		if row.prefix != "" {
			source.WriteString(row.prefix + "\n")
		}
		source.WriteString(row.op + "\n")
		fmt.Fprintf(&source, "%s AX,0(DI)\n%s SI,%d(DI)\n%s CX,%d(DI)\n%s\n%s AX\n",
			move, move, word, move, 2*word, push, pop)
		// Snapshot only the six status bits and DF. The observer does not
		// invent the remaining native FLAGS bits or claim they are portable.
		and := "ANDQ"
		if arch == "386" {
			and = "ANDL"
		}
		fmt.Fprintf(&source, "%s $0xcd5,AX\n%s AX,%d(DI)\nCLD\nRET\n", and, move, 3*word)
	}
	return source.String(), declarations.String()
}

func TestX86LODSStateCompleteIndependentCases(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		cases := x86LODSStateCases(arch)
		want := 48
		if arch == "386" {
			want = 36
		}
		if len(cases) != want {
			t.Fatal("complete width/prefix/count/direction denominator changed", arch, len(cases))
		}
		for _, row := range cases {
			expected := x86LODSStateExpected(row)
			if row.prefix != "" && row.count == 0 {
				if expected.ax != x86LODSStateSeed(arch) || expected.cx != 0 || expected.siDelta != 0 {
					t.Fatal("a zero iteration cannot create an accumulator write or pointer movement", row, expected)
				}
			} else if expected.siDelta == 0 {
				t.Fatal("unprefixed count zero still executes one element", row, expected)
			}
			if row.width == 4 && (row.prefix == "" || row.count != 0) && expected.ax>>32 != 0 {
				t.Fatal("an executed dword load must zero the AMD64 high half", row, expected)
			}
			if expected.flags&^uint64(0xcd5) != 0 || expected.flags&0x8d5 != 0x890 {
				t.Fatal("fixture invented unspecified FLAGS or changed the initialized six status bits", row, expected)
			}
		}
		source, _ := x86LODSStateFixture(arch)
		file, err := Parse(ArchAMD64, source)
		if err != nil || len(file.Funcs) != want {
			t.Fatal("complete actual source fixture lost a function", arch, err)
		}
	}
}

func TestX86LODSZeroCountDoesNotCreateResultFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []string{"REP", "REPN"} {
			for _, result := range []struct{ typ, store string }{
				{"uint32", "MOVL AX"}, {"bool", "MOVB AL"},
			} {
				body := "MOVL $0,CX\nCLD\n" + prefix + "\nLODSL\n" + result.store + ",ret+0(FP)\nRET"
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() "+result.typ, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("zero iterations manufactured NUM/canonical knowledge from an unspecified accumulator", arch, prefix, result.typ, err)
				}
			}
		}
	}
}
