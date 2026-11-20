package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64PrivateCallImmediateCannotObserveHiddenScratch(t *testing.T) {
	base := arm64PrivateCallImmediateSource([]arm64ImmediateOracleCase{{op: "ADDS", value: -1, left: "R0", dest: "R1"}})
	for _, source := range []string{
		strings.Replace(base, "CALL immediate0<>(SB)", "CALL immediate0<>(SB)\nMOVD R27,R20", 1),
		strings.Replace(base, "ADDS $-1,R0,R1", "ADDS $-1,R0,R1\nMOVD R27,R20", 1),
	} {
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CoalesceARM64PrivateRegisterHelpers(file); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("registered scratch became observable hidden data: %v", err)
		}
	}
}

func arm64PrivateCallImmediateCases() []arm64ImmediateOracleCase {
	var cases []arm64ImmediateOracleCase
	for _, form := range arm64ImmediateOracleCases() {
		if form.left == "R0" && (form.dest == "R1" || form.dest == "") {
			cases = append(cases, form)
		}
	}
	return cases
}

func arm64PrivateCallImmediateSource(cases []arm64ImmediateOracleCase) string {
	var root, helpers strings.Builder
	root.WriteString("TEXT ·DivideRem(SB),4,$0-16\nMOVD input+0(FP),R10\nMOVD output+8(FP),R11\n")
	for index, form := range cases {
		root.WriteString("MOVD 0(R10),R0\nMOVD 8(R10),R20\nMOVD 16(R10),R6\nMOVD 24(R10),R7\nMOVD $107,R1\nCMP R7,R6\n")
		fmt.Fprintf(&root, "CALL immediate%d<>(SB)\n", index)
		root.WriteString("MOVD R1,(R11)\nMOVD R20,8(R11)\n")
		root.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET HS,R4\nCSET VS,R5\nLSL $1,R3\nLSL $2,R4\nLSL $3,R5\nORR R3,R2\nORR R4,R2\nORR R5,R2\n")
		root.WriteString("MOVD R2,16(R11)\nADD $24,R11\n")
		fmt.Fprintf(&helpers, "TEXT immediate%d<>(SB),516,$0-0\n%s\nRET\n", index, arm64ImmediateOracleInstruction(form))
	}
	return root.String() + "RET\n" + helpers.String()
}

func TestARM64PrivateCallImmediateCompleteSourcePreparation(t *testing.T) {
	cases := arm64PrivateCallImmediateCases()
	source := arm64PrivateCallImmediateSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	for _, base := range []string{"ADD", "ADDS", "SUB", "SUBS", "CMP", "CMN", "AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST"} {
		for _, suffix := range []string{"", "W"} {
			opcode := base + suffix
			t.Run(opcode, func(t *testing.T) {
				var family []arm64ImmediateOracleCase
				for _, form := range cases {
					if form.op == opcode {
						family = append(family, form)
					}
				}
				file, err := Parse(ArchARM64, arm64PrivateCallImmediateSource(family))
				if err != nil || len(family) != 14 {
					t.Fatalf("incomplete immediate family: cases=%d error=%v", len(family), err)
				}
				prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
				if err != nil || len(prepared.Funcs) != 1 {
					t.Fatalf("registered unobserved immediate scratch lost its source continuation: %v", err)
				}
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateCallImmediateFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	cases := arm64PrivateCallImmediateCases()
	source := arm64PrivateCallImmediateSource(cases)
	// The middle output independently checks preserved R20 data, not R27.
	// Explicit R27 observation remains forbidden across private CALL roots.
	for index := range cases {
		cases[index].scratch = false
	}
	goProgram, cProgram := arm64ImmediateOraclePrograms(cases)
	runARM64LocalRegisterGoOracle(t, source, goProgram, len(runner) != 0, "1.20")
	for api, ir := range arm64DivRemRuntimeIRs(t, source, triple, len(cases)*3) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("private-immediate-%d", api), triple, ir, cProgram, runner)
	}
	t.Logf("30 CALL immediate opcodes: %d cases x8 boundaries, result/NZCV/preserved GP/full canaries", len(cases))
}
