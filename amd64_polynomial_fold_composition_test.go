package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const x86PolynomialFoldDeclaration = "func fold(p *[128]byte, n, seed uint32) uint32\n"

// A first-party polynomial fold, not a copied CRC implementation. Its complete
// result path crosses native pointer reads, private aligned DATA, both CLMUL
// qword selectors, byte/lane shifts, a loop backedge and a two-arm value join.
func x86PolynomialFoldSource(arch string) string {
	word, move, add := 8, "MOVQ", "ADDQ"
	if arch == "386" {
		word, move, add = 4, "MOVL", "ADDL"
	}
	return fmt.Sprintf(`DATA foldPoly<>+0(SB)/8,$0x1f123bb5a7c9d001
DATA foldPoly<>+8(SB)/8,$0xa7c1e305f1b692d3
GLOBL foldPoly<>(SB),8,$16

TEXT ·fold(SB),4,$0-%d
	%s p+0(FP),SI
	MOVL n+%d(FP),CX
	MOVL seed+%d(FP),AX
	PXOR X1,X1
	PINSRD $0,AX,X1
	MOVOA foldPoly<>(SB),X3
	CMPL CX,$0
	JE finish
loop:
	MOVOU (SI),X0
	PXOR X0,X1
	MOVOU X1,X2
	PCLMULQDQ $0,X3,X1
	PCLMULQDQ $17,X3,X2
	PSRLDQ $8,X2
	PXOR X2,X1
	TESTL $1,CX
	JE even
	MOVOU X1,X4
	PSRLQ $7,X4
	PXOR X4,X1
	JMP joined
even:
	MOVOU X1,X4
	PSLLQ $3,X4
	PXOR X4,X1
joined:
	%s $16,SI
	SUBL $1,CX
	JNE loop
finish:
	MOVOU X1,X2
	PSRLO $8,X2
	PXOR X2,X1
	PSRLQ $11,X1
	PEXTRD $0,X1,AX
	MOVL AX,ret+%d(FP)
	RET
`, word+12, move, word, word+4, add, word+8)
}

func TestX86PolynomialFoldCompositionThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := x86PolynomialFoldSource(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, x86PolynomialFoldDeclaration, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, native := range []string{"movdqu", "movdqa"} {
					if !strings.Contains(ir, "asm sideeffect \""+native+" ($1), $0\"") {
						t.Fatal(api, "conditional result lost its original native load", native)
					}
				}
				compileLLVMToObject(t, llc, target.triple, "polynomial-fold.ll", "polynomial-fold.o", ir)
			}
		})
	}
}

func TestX86PolynomialFoldCompositionDoesNotCreateStandalonePermissions(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source := x86PolynomialFoldSource(arch)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		pkg := mustGoPackage(t, "fold", "package fold\n"+x86PolynomialFoldDeclaration)
		resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		fn := file.Funcs[0]
		for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
			if err := check(fn, sigs["fold"], arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("linked-data/native-load composition leaked declaration-only authority", arch, err)
			}
		}
	}
}

func TestX86PolynomialFoldCompositionRejectsOneMissingProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for name, change := range map[string][2]string{
			"external data":        {"MOVOA foldPoly<>(SB),X3", "MOVOA otherPoly<>(SB),X3"},
			"short data":           {"DATA foldPoly<>+8(SB)/8,$0xa7c1e305f1b692d3\nGLOBL foldPoly<>(SB),8,$16", "GLOBL foldPoly<>(SB),8,$8"},
			"relocated data":       {"$0xa7c1e305f1b692d3", "$·external(SB)"},
			"missing pointer":      {"MOVOU (SI),X0", "MOVOU (DI),X0"},
			"missing joined value": {"even:\n\tMOVOU X1,X4", "even:\n\tMOVOU X5,X4"},
			"unknown data input":   {"PCLMULQDQ $0,X3,X1", "PCLMULQDQ $0,X5,X1"},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				source := strings.Replace(x86PolynomialFoldSource(arch), change[0], change[1], 1)
				if arch == "386" && name == "relocated data" {
					source = strings.Replace(source, "+8(SB)/8,$·external(SB)", "+8(SB)/4,$·external(SB)", 1)
				}
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, x86PolynomialFoldDeclaration, arch, testTargetTriple("linux", arch), api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal(api, "incomplete composition acquired a result", err)
					}
				}
			})
		}
	}
}
