//go:build unix && go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownedPackedArithmeticRuntimeProgram(t *testing.T) (string, string, []uint64, [][]string) {
	t.Helper()
	var data [512]byte
	var source, declarations strings.Builder
	for offset := 0; offset < len(data); offset += 8 {
		value := uint64(0x719283a4b5c6d7e8) ^ uint64(offset)*0x0102030405060708
		binary.LittleEndian.PutUint64(data[offset:], value)
		fmt.Fprintf(&source, "DATA numericBytes<>+%d(SB)/8,$0x%016x\n", offset, value)
	}
	source.WriteString("GLOBL numericBytes<>(SB),8,$512\n")
	inputs := []uint64{1, 2, 3, 7}
	expected := make([][]string, len(inputs))
	count := 0
	for _, opcode := range ownedPackedArithmeticNames() {
		for half := 0; half < 2; half++ {
			assembly, declaration := ownedPackedArithmeticFunction(fmt.Sprintf("Value%d", count), opcode, "amd64", "lea", true)
			// Nonzero asymmetric initial lanes and a fully initialized tail
			// keep low products observable; every loop performs three m128 reads.
			assembly = strings.Replace(assembly, "PXOR X0,X0", "MOVOU numericBytes<>+32(SB),X0", 1)
			assembly = strings.Replace(assembly, "MOVQ X0,AX", fmt.Sprintf("PEXTRQ $%d,X0,AX", half), 1)
			source.WriteString(assembly)
			declarations.WriteString(strings.ReplaceAll(declaration, "uintptr", "uint64"))
			for index, iterations := range inputs {
				value := ownedPackedArithmeticRuntimeOracle(opcode, data, iterations)
				expected[index] = append(expected[index], fmt.Sprintf("%016x", binary.LittleEndian.Uint64(value[half*8:])))
			}
			count++
		}
	}
	if count != 38 {
		t.Fatal("complete arithmetic/full128 runtime inventory changed", count)
	}
	return source.String(), declarations.String(), inputs, expected
}

// Independent scalar arithmetic: no production forms, lane helpers or LLVM
// expressions participate. Original Go must agree before it becomes an oracle.
func ownedPackedArithmeticRuntimeOracle(opcode string, data [512]byte, iterations uint64) [16]byte {
	var output [16]byte
	copy(output[:], data[32:48])
	bytes := 4
	switch opcode[len(opcode)-1] {
	case 'B':
		bytes = 1
	case 'W':
		bytes = 2
	case 'Q':
		bytes = 8
	}
	read := func(p []byte) uint64 {
		var value uint64
		for index := bytes - 1; index >= 0; index-- {
			value = value<<8 | uint64(p[index])
		}
		return value
	}
	subtract := strings.HasPrefix(opcode, "PSUB")
	for round := uint64(0); round < iterations; round++ {
		for _, offset := range []int{0, 16, 480} {
			for lane := 0; lane < 16; lane += bytes {
				a, b := read(output[lane:]), read(data[offset+lane:])
				value := a + b
				if subtract {
					value = a - b
				}
				switch opcode {
				case "PMULLW", "PMULLD":
					value = a * b
				case "PADDSB", "PADDSW", "PSUBSB", "PSUBSW":
					shift := uint(64 - bytes*8)
					x, y := int64(a<<shift)>>shift, int64(b<<shift)>>shift
					signed := x + y
					if subtract {
						signed = x - y
					}
					minimum, maximum := -int64(1)<<uint(bytes*8-1), int64(1)<<uint(bytes*8-1)-1
					if signed < minimum {
						signed = minimum
					} else if signed > maximum {
						signed = maximum
					}
					value = uint64(signed)
				case "PADDUSB", "PADDUSW", "PSUBUSB", "PSUBUSW":
					maximum := uint64(1)<<uint(bytes*8) - 1
					if subtract && a < b {
						value = 0
					} else if !subtract && value > maximum {
						value = maximum
					}
				}
				for index := 0; index < bytes; index++ {
					output[lane+index] = byte(value >> uint(index*8))
				}
			}
		}
	}
	return output
}

func ownedPackedArithmeticRuntimePreflight(t *testing.T, execution x86FloatCompareExecution) string {
	t.Helper()
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "sse41.c"), filepath.Join(directory, "sse41")
	const program = `#include <stdio.h>
__attribute__((target("sse4.1"))) static int actual_product(void) {
    typedef int V __attribute__((vector_size(16)));
    V a={2,3,4,5}, b={7,11,13,17};
    __asm__ volatile("pmulld %1,%0" : "+x"(a) : "x"(b));
    return a[0]==14 && a[1]==33 && a[2]==52 && a[3]==85;
}
int main(void) {
    __builtin_cpu_init();
    int available=!!__builtin_cpu_supports("sse4.1");
    printf("owned packed arithmetic native SSE4.1=%d\n",available);
    return available && actual_product() ? 0 : 1;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	return executable
}

func TestX86OwnedPackedArithmeticRuntimeObjects(t *testing.T) {
	assembly, declarations, _, _ := ownedPackedArithmeticRuntimeProgram(t)
	ownedPackedArithmeticRuntimePreflight(t, fixedLocalPackedCompileOnlyTools(t))
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly)
			goos := "linux"
			if strings.Contains(target.triple, "apple") {
				goos = "darwin"
			} else if strings.Contains(target.triple, "windows") {
				goos = "windows"
			}
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declarations, goos+"/amd64", target.triple)
			fixedLocalResultsRuntimeAPIs(t, pkg, request, file, options, assembly,
				func(t *testing.T, ir string, err error) {
					operations := strings.Count(ir, "asm sideeffect ")
					initial := strings.Count(ir, "asm sideeffect \"movdqu ")
					if err != nil || operations != 152 || initial != 38 {
						t.Fatal("38 kernels require 38 initial reads and 114 arithmetic m128 reads", operations, initial, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
		})
	}
}

func TestX86RuntimeOrdinarySourceCannotBypassFrameBinding(t *testing.T) {
	for _, row := range []struct {
		name    string
		file    *File
		options Options
		want    bool
	}{
		{"ordinary", &File{Arch: ArchAMD64, Funcs: []Func{{}}}, Options{}, false},
		{"nil", nil, Options{}, true},
		{"empty", &File{Arch: ArchAMD64}, Options{}, true},
		{"other arch", &File{Arch: ArchARM64, Funcs: []Func{{}}}, Options{}, true},
		{"private", &File{Arch: ArchAMD64, Funcs: []Func{{FrameSize: 16}}}, Options{}, true},
		{"mixed", &File{Arch: ArchAMD64, Funcs: []Func{{}, {FrameSize: 16}}}, Options{}, true},
		{"negative frame", &File{Arch: ArchAMD64, Funcs: []Func{{FrameSize: -1}}}, Options{}, true},
		{"untrusted proof", &File{Arch: ArchAMD64, Funcs: []Func{{x86FixedLocal: &x86FixedLocalProof{}}}}, Options{}, true},
		{"source stack", &File{Arch: ArchAMD64, Funcs: []Func{{x86SourceStack: &x86SourceStackProof{}}}}, Options{}, true},
		{"invalid binding", &File{Arch: ArchAMD64, Funcs: []Func{{}}},
			Options{Sigs: map[string]FuncSig{"value": {x86FixedLocal: &x86FixedLocalBinding{}}}}, true},
		{"numerical owner", &File{Arch: ArchAMD64, Funcs: []Func{{}}},
			Options{NumericalReads: &GoX86NumericalReadBinding{}}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := fixedLocalResultsRuntimeNeedsBinding(row.file, row.options); got != row.want {
				t.Fatal("ordinary test driver selected the wrong source/owner route", got, row.want)
			}
		})
	}
	t.Run("private-driver", func(t *testing.T) {
		goAMD64FramePrepareOwnedToolCache(t)
		assembly := fixedLocalConstantIndexFunction("Value0", "MOVQ 0(SP),AX")
		triple := "x86_64-unknown-linux-gnu"
		pkg, request, file, options := fixedLocalTransportFixture(t, assembly, "func Value0(a uint64) uint64", "linux/amd64", triple)
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM22 required")
		}
		fixedLocalResultsRuntimeAPIs(t, pkg, request, file, options, assembly,
			func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "%fixed_local_native = alloca") {
					t.Fatal("private source lost its independent fresh frame binding", err)
				}
				x86PackedStringCompileObject(t, llc, triple, ir, "-O2")
			})
	})
}
