//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// These numerical kernels exercise the same original amd64 program on both
// sides. In particular, a host-target rewrite cannot stand in for x86 FLAGS,
// partial memory writes or the original Go-generated frame.
func fixedLocalGPRuntimeProgram(triple string) (string, string, string, string) {
	var bodies []string
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, stem := range []string{"ADD", "SUB", "AND", "OR", "XOR", "ADC", "SBB"} {
			bodies = append(bodies, "STC\n"+stem+width+" $1,0(SP)\n")
		}
	}
	for _, stem := range []string{"ADD", "SUB", "AND", "OR", "XOR", "ADC", "SBB"} {
		bodies = append(bodies, "STC\n"+stem+"Q a+0(FP),AX\nMOVQ AX,0(SP)\n")
	}
	for _, operation := range []string{
		"CMPQ a+0(FP),AX", "CMPQ AX,a+0(FP)", "CMPQ a+0(FP),$1",
		"TESTQ a+0(FP),AX", "TESTQ AX,a+0(FP)", "TESTQ $1,a+0(FP)",
	} {
		bodies = append(bodies, operation+"\n")
	}
	for _, condition := range []string{
		"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS",
		"LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS",
	} {
		bodies = append(bodies, "MOVQ $42,CX\nCMPQ a+0(FP),$1\nCMOVQ"+condition+
			" a+0(FP),CX\nMOVQ CX,0(SP)\n")
	}
	for _, body := range []string{
		"MOVQ $3,CX\nagain:\nADDQ CX,AX\nSUBQ $1,CX\nJNE again\n",
		"MOVQ $3,16(SP)\nagain:\nADDQ $1,AX\nSUBQ $1,16(SP)\nJNE again\n",
		"CMPQ AX,AX\nMOVQ AX,CX\nLEAQ 7(AX)(CX*2),AX\nNOPL 24(SP)\n",
		"CMPQ AX,$1\nJEQ left\nMOVQ $2,CX\nJMP join\nleft:\nMOVQ $3,CX\njoin:\nADDQ CX,AX\n",
	} {
		bodies = append(bodies, body+"MOVQ AX,0(SP)\n")
	}
	for _, register := range []string{"AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			bodies = append(bodies, fmt.Sprintf("MOVQ AX,%s\nADD%s $1,%s\nMOVQ %s,AX\nMOVQ AX,0(SP)\n", register, width, register, register))
		}
	}

	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, body := range bodies {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$64-24
MOVQ a+0(FP),AX
MOVQ AX,0(SP)
MOVQ AX,8(SP)
%s`, name, body)
		// MOV and SETcc preserve FLAGS. Capture every defined arithmetic flag
		// before the shifts/ORs used to pack them; AF is undefined for logic.
		assembly.WriteString(`MOVQ $0,CX
MOVQ $0,DX
MOVQ $0,BX
MOVQ $0,R8
MOVQ $0,R9
SETCS CL
SETPS DL
SETEQ BL
SETMI R8
SETOS R9
SHLQ $1,DX
SHLQ $2,BX
SHLQ $3,R8
SHLQ $4,R9
ORQ DX,CX
ORQ BX,CX
ORQ R8,CX
ORQ R9,CX
MOVQ mode+8(FP),DX
CMPQ DX,$1
JEQ flags
CMPQ DX,$2
JEQ canary
MOVQ 0(SP),AX
JMP done
flags:
MOVQ CX,AX
JMP done
canary:
MOVQ 8(SP),AX
done:
MOVQ AX,ret+16(FP)
RET
`)
		fmt.Fprintf(&declarations, "func %s(a, mode uint64) uint64\n", name)
		fmt.Fprintf(&goRows, "%s,\n", name)
		fmt.Fprintf(&cRows, "value%d,\n", index)
		label := runtimeCAsmLabel(prefix + "example.invalid/framefixture." + name)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t, uint64_t) __asm__(%s);\n", index, label)
	}
	original := `package main
import "fmt"
` + declarations.String() + `
func main() {
    rows := []func(uint64, uint64) uint64{
` + goRows.String() + `
    }
    values := []uint64{
        0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff,
        0x7fffffff, 0x80000000, 0xffffffff,
        0x7fffffffffffffff, 0x8000000000000000, ^uint64(0), 0x8080808080808080,
    }
    for n, call := range rows {
        for v, value := range values {
            for mode := uint64(0); mode < 3; mode++ {
                got := call(value, mode)
                if mode == 2 && got != value {
                    panic("original private-frame canary changed")
                }
                fmt.Printf("%d %d %d %016x\n", n, v, mode, got)
            }
        }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
int main(void) {
    uint64_t (*const rows[])(uint64_t, uint64_t) = {
` + cRows.String() + `
    };
    const uint64_t values[] = {
        0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff,
        0x7fffffff, UINT64_C(0x80000000), UINT64_C(0xffffffff),
        UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000),
        UINT64_MAX, UINT64_C(0x8080808080808080),
    };
    for (unsigned n = 0; n < sizeof(rows)/sizeof(rows[0]); n++) {
        for (unsigned v = 0; v < sizeof(values)/sizeof(values[0]); v++) {
            for (unsigned mode = 0; mode < 3; mode++) {
                uint64_t got = rows[n](values[v], mode);
                if (mode == 2 && got != values[v]) {
                    return 2;
                }
                printf("%u %u %u %016llx\n", n, v, mode, (unsigned long long)got);
            }
        }
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func TestGoAMD64FixedLocalTypedGPRuntimeObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const triple = "x86_64-unknown-linux-gnu"
	assembly, declarations, _, _ := fixedLocalGPRuntimeProgram(triple)
	pkg, request, _, options := fixedLocalTransportFixture(t,
		assembly, declarations, "linux/amd64", triple)
	var names []string
	for index := 0; index < 121; index++ {
		names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
	}
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				x86CompactExpandRequireAllDefinitions(t, input, names)
				x86PackedStringCompileObject(t, llc, triple, input, level)
			}
		})
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalTypedGP(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	// Each API owns a fresh source observation, not a reused proof. Compile
	// original Go and prepare objdump before opening any observation lease.
	t.Setenv("GOCACHE", t.TempDir())
	assembly, declarations, original, driver := fixedLocalGPRuntimeProgram(execution.triple)
	want := strings.Split(strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))), "\n")
	if len(want) != 121*15*3 {
		t.Fatalf("original Go produced %d rows, want 121 kernels x 15 values x 3 observations", len(want))
	}
	pkg, request, _, options := fixedLocalTransportFixture(t,
		assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalConversionPrepareToolCache(t, request)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					output := execution.compileAndRunLLVM(t, "private-gp", input, driver, level)
					got := strings.Split(strings.TrimSpace(string(output)), "\n")
					if len(got) != len(want) {
						t.Fatalf("LLVM row count = %d, original = %d", len(got), len(want))
					}
					for index := range want {
						if got[index] != want[index] {
							t.Fatalf("private GP value/FLAGS/canary row %d: original %s; LLVM %s", index, want[index], got[index])
						}
					}
				})
			}
		})
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("original Go and LLVM amd64 execution via Rosetta, not native x86 hardware")
	}
}
