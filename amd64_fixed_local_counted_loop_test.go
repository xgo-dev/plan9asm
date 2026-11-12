package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type fixedLocalCountedLoopCase struct {
	name, body string
	iterations int
}

func fixedLocalCountedLoopCases() []fixedLocalCountedLoopCase {
	var cases []fixedLocalCountedLoopCase
	for _, count := range []int{2, 3, 8} {
		for _, step := range []int{1, 8, 16} {
			for _, descending := range []bool{false, true} {
				for _, outer := range []bool{false, true} {
					scale := 1
					if step == 1 {
						scale = 8
					}
					first, limit, update, branch := 0, count*step, "ADDQ", "JB"
					if descending {
						first, limit, update, branch = count*step, 0, "SUBQ", "JA"
					}
					var body strings.Builder
					body.WriteString("MOVQ $77,248(SP)\n")
					if outer {
						// The input-dependent outer loop remains an ordinary CFG
						// fixed point. Its one or two passes must each re-establish
						// the inner loop's complete private initialization.
						body.WriteString("MOVQ a+0(FP),DI\nANDQ $1,DI\nADDQ $1,DI\nMOVQ $0,DX\nouter:\n")
					}
					fmt.Fprintf(&body, "MOVQ $%d,SI\nloop:\nMOVQ AX,16(SP)(SI*%d)\nADDQ $2,16(SP)(SI*%d)\n%s $%d,SI\nCMPQ SI,$%d\n%s loop\n",
						first, scale, scale, update, step, limit, branch)
					if outer {
						body.WriteString("ADDQ $1,DX\nCMPQ DX,DI\nJB outer\n")
					}
					// An independent fixed-address read of every iteration's
					// store detects partial initialization and skipped visits.
					for iteration := 0; iteration < count; iteration++ {
						offset := 16 + iteration*step*scale
						if descending {
							offset = 16 + (count-iteration)*step*scale
						}
						op := "ADDQ"
						if iteration == 0 {
							op = "MOVQ"
						}
						fmt.Fprintf(&body, "%s %d(SP),AX\n", op, offset)
					}
					body.WriteString("ADDQ 248(SP),AX")
					name := fmt.Sprintf("count%d/step%d/descending%t/outer%t", count, step, descending, outer)
					cases = append(cases, fixedLocalCountedLoopCase{name, body.String(), count})
				}
			}
		}
	}
	return cases
}

func fixedLocalCountedLoopFixture(t *testing.T, body string) (Func, FuncSig, string) {
	t.Helper()
	_, sig, source := fixedLocalGPFixture(t, body)
	source = strings.Replace(source, "$64-16", "$256-16", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func TestGoAMD64FixedLocalCountedLoopCompleteInitialization(t *testing.T) {
	var original strings.Builder
	cases := fixedLocalCountedLoopCases()
	if len(cases) != 36 {
		t.Fatal("count/stride/direction/outer-loop inventory changed", len(cases))
	}
	for index, row := range cases {
		fn, sig, source := fixedLocalCountedLoopFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal("bounded iterations lost initialized private bytes", err)
			}
			before, beforeErr := x86CallerSourceFingerprint(fn)
			after, afterErr := x86CallerSourceFingerprint(proved)
			if beforeErr != nil || afterErr != nil || before != after || len(fn.Instrs) != len(proved.Instrs) {
				t.Fatal("proof must retain the complete original source and loop body", beforeErr, afterErr)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalCountedLoopRejectsUnprovedIterations(t *testing.T) {
	const prefix = "MOVQ $0,SI\nloop:\n"
	const store = "MOVQ AX,16(SP)(SI*8)\n"
	const suffix = "ADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 32(SP),AX"
	var original strings.Builder
	for index, row := range []struct{ name, body string }{
		{"read before first write", prefix + "MOVQ 16(SP)(SI*8),BX\n" + store + suffix},
		{"read next iteration before write", prefix + store + "MOVQ 24(SP)(SI*8),BX\n" + suffix},
		{"partial initialization", prefix + "MOVB AX,16(SP)(SI*8)\n" + suffix},
		{"partial counter overwrite", prefix + "ADDB $0,SI\n" + store + suffix},
		{"counter overwritten in body", prefix + "ADDQ $1,SI\n" + store + suffix},
		{"unknown initial counter", "MOVQ a+0(FP),SI\nloop:\n" + store + suffix},
		{"zero update cannot initialize later bytes", prefix + store + "ADDQ $0,SI\nCMPQ SI,$3\nJB loop\nMOVQ 32(SP),AX"},
		{"unbounded limit", prefix + store + "ADDQ $1,SI\nCMPQ SI,AX\nJB loop\nMOVQ AX,AX"},
		{"latch flags replaced", prefix + store + "ADDQ $1,SI\nCMPQ SI,$3\nTESTQ AX,AX\nJB loop\nMOVQ 32(SP),AX"},
		{"latch compares another counter", prefix + store + "ADDQ $1,SI\nCMPQ SI,$3\nCMPQ AX,$3\nJB loop\nMOVQ AX,AX"},
		{"counter wraps", "MOVQ $-1,SI\nloop:\n" + store + "ADDQ $1,SI\nCMPQ SI,$3\nJB loop"},
		{"entry bypasses counter", "CMPQ AX,$0\nJEQ inside\nMOVQ $0,SI\nloop:\ninside:\n" + store + suffix},
		{"conditional write is incomplete", prefix + "CMPQ AX,$0\nJEQ missing\n" + store + "missing:\n" + suffix},
		{"unwritten gap after loop", prefix + store + "ADDQ $2,SI\nCMPQ SI,$4\nJB loop\nMOVQ 24(SP),AX"},
		{"last iteration exceeds frame", "MOVQ $29,SI\nloop:\n" + store + "ADDQ $1,SI\nCMPQ SI,$32\nJB loop"},
		{"early iteration changes residue alias", "MOVQ $77,16(SP)\nMOVQ SP,R8\nADDQ $16,R8\nANDQ $-16,R8\nMOVQ $1,SI\nloop:\nMOVQ AX,(R8)(SI*8)\nADDQ $1,SI\nCMPQ SI,$3\nJB loop\nMOVQ 16(SP),AX"},
	} {
		fn, sig, source := fixedLocalCountedLoopFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err == nil {
				t.Fatal("incomplete iterations or private-byte aliases acquired a proof")
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
