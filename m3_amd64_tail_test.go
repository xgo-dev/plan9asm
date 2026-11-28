package plan9asm

import (
	"strings"
	"testing"
)

func TestM3_AMD64LongTailAllFamilies(t *testing.T) {
	ir := translateAndVerifyAMD64(t, "m3Tail", `
GLOBL gtail<>(SB), NOPTR, $64
TEXT ·m3Tail(SB),NOSPLIT,$0-0
	// 1. AVX-512 FP Class (bit-exact @llvm.is.fpclass)
	VFPCLASSPSX $0xff, X0, K1, K2
	VFPCLASSPSY $0x55, Y0, K2
	VFPCLASSPSZ.BCST $0xaa, 8(BX), K1, K3
	VFPCLASSPDX $0x0f, (AX), K1, K2
	VFPCLASSPDY $0xf0, Y0, K1, K2
	VFPCLASSPDZ $0x7f, Z0, K1, K2
	VFPCLASSSS $0x42, X0, K1, K2
	VFPCLASSSD $0x24, (BX), K1, K2

	// 2. SSE/AVX FP Horizontal Add/Sub, AddSub, Round
	ADDSUBPS (BX), X1
	ADDSUBPD X0, X1
	VADDSUBPS Y0, Y1, Y2
	VADDSUBPD X0, X1, X2
	HADDPS (BX), X1
	HADDPD X0, X1
	VHADDPS Y0, Y1, Y2
	VHADDPD X0, X1, X2
	HSUBPS (BX), X1
	HSUBPD X0, X1
	VHSUBPS Y0, Y1, Y2
	VHSUBPD X0, X1, X2
	ROUNDPS $1, (BX), X1
	ROUNDPD $2, X0, X1
	VROUNDPS $3, Y0, Y1
	VROUNDPD $0, X0, X1
	ROUNDSS $1, (BX), X1
	ROUNDSD $2, X0, X1
	VROUNDSS $3, (BX), X1, X2
	VROUNDSD $0, X0, X1, X2

	// 3. Vector Non-Temporal / High-Low / MaskMov / MMX<->XMM Moves
	LDDQU (BX), X1
	VLDDQU (BX), Y1
	MOVNTDQA (BX), X1
	VMOVNTDQA (BX), Y1
	MOVNTDQ X1, (AX)
	MOVNTO X1, (BX)
	MOVNTPD X1, (BX)
	MOVNTPS X1, gtail<>(SB)
	MOVNTQ M1, (BX)
	VMOVNTPD Y1, (BX)
	VMOVNTPS X1, (BX)
	MOVDQ2Q X1, M1
	MOVQOZX M1, X1
	MOVHPD (BX), X1
	MOVHPD X1, (BX)
	MOVHPS (BX), X1
	MOVHPS X1, gtail<>(SB)
	MOVLPD gtail<>(SB), X1
	MOVLPD X1, (BX)
	MOVLPS (BX), X1
	MOVLPS X1, (BX)
	VMOVHPD (BX), X1, X2
	VMOVHPS X1, (BX)
	VMOVLPD (BX), X1, X2
	VMOVLPS (BX), X1, X2
	VMASKMOVPS (BX), X1, X2
	VMASKMOVPD gtail<>(SB), Y1, Y2
	VPMASKMOVD X0, X1, (BX)
	VPMASKMOVQ Y0, Y1, gtail<>(SB)
	MASKMOVQ M0, M1
	MASKMOVOU X0, X1
	VMASKMOVDQU X0, X1

	// 4. Scalar MOVBE, MOVNTI, BMI2 PDEP/PEXT, DIV/IDIV, Stack, String, System
	MOVBEW (BX), AX
	MOVBEW AX, (BX)
	MOVBEL (BX), AX
	MOVBEL AX, gtail<>(SB)
	MOVBEQ (BX), AX
	MOVBEQ AX, (BX)
	MOVNTIL AX, (BX)
	MOVNTIQ AX, gtail<>(SB)
	PDEPL BX, CX, DX
	PDEPQ (BX), R9, R10
	PEXTL BX, CX, DX
	PEXTQ (BX), R9, R10
	DIVQ DX
	DIVQ (BX)
	IDIVL DX
	IDIVQ (BX)
	CWD
	LAHF
	SAHF
	PUSHW AX
	PUSHW (BX)
	POPW DX
	POPW (BX)
	PUSHFW
	POPFW
	XLAT
	CMPSB
	CMPSW
	CMPSL
	CMPSQ
	LODSB
	LODSW
	LODSL
	LODSQ
	SCASB
	SCASW
	SCASL
	SCASQ
	MOVSW
	MOVSL
	STOSB
	STOSW
	STOSL
	RET
`)
	for _, want := range []string{
		"@llvm.is.fpclass.",
		"@llvm.bswap.i64",
		"@llvm.masked.load.",
		"@llvm.masked.store.",
		"sdiv i128",
		"udiv i128",
	} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in M3 tail IR", want)
		}
	}
}

func TestM3_ErrorPaths(t *testing.T) {
	bad := []string{
		"VRNDSCALEPS Z0, Z1",
		"VRCP14SS X0, X1",
		"VRCP14SS X0, X1, AX",
		"ROUNDSS $1, X0",
		"ROUNDSS $1, X0, AX",
		"VRCP14PS Z0",
		"VRCP14PS Z0, AX",
		"VRANGEPS X0, X1, X2",
		"VSCALEFPS Z0, Z1",
		"VSCALEFPS Z0, Z1, (BX)",
		"VSCALEFSS X0, X1, AX",
		"VSCALEFPS Z0, Z1, AX",
		"VFPCLASSPSX X0, K1",
		"VFPCLASSPSX $1, X0, AX",
		"ADDSUBPS X0",
		"VADDSUBPS X0, X1",
		"VADDSUBPS X0, X1, AX",
		"LDDQU (BX)",
		"LDDQU (BX), AX",
		"MOVNTDQ (BX), (BX)",
		"MOVNTDQ AX, (BX)",
		"MOVNTDQ X0, $1",
		"MOVDQ2Q X0, X1",
		"MOVQOZX M0, M1",
		"MOVHPD X0",
		"MOVHPD X0, $1",
		"MOVHPD (BX), AX",
		"MOVHPD $1, X0",
		"VMASKMOVPS (BX), X0",
		"VMASKMOVPS (BX), AX, X0",
		"VMASKMOVPS (BX), X0, AX",
		"VMASKMOVPS $1, X0, X1",
		"VMASKMOVPS $1, X0, (BX)",
		"VMASKMOVPS AX, X0, (BX)",
		"VMASKMOVPS X0, X1, $1",
		"MASKMOVQ M0",
		"MASKMOVQ AX, BX",
		"MOVBEQ AX",
		"MOVBEQ AX, $1",
		"MOVNTIQ AX",
		"MOVNTIQ AX, $1",
		"PDEPQ AX, BX",
		"DIVQ",
		"PUSHW",
		"POPW",
		"POPW $1",
		"CMPSB AX",
		"LGDT",
		"LGDT AX",
		"LGDT (BX)",
		"LIDT (BX)",
		"SGDT (BX)",
		"LLDT $1",
		"LLDT DX",
		"LMSW DX",
		"LTR DX",
		"TPAUSE BX",
		"UMWAIT BX",
		"VRCP14PS Z0, K1, Z1",
		"VRCP28PD Z0, Z1",
		"VRSQRT14PS Y0, K1, Y1",
		"VRSQRT28PD Z0, K2, Z1",
		"VEXP2PS Z0, K1, Z1",
		"VGETEXPPS Z0, K1, Z1",
		"VGETMANTPS $5, Z0, K1, Z1",
		"VRNDSCALEPS $1, Z0, K1, Z1",
		"VREDUCEPS $1, Y0, K1, Y1",
		"VSCALEFPS Z0, Z1, K1, Z2",
		"VRANGEPS $0, X0, X1, K1, X2",
		"VFIXUPIMMPS $47, Z0, Z1, K1, Z2",
	}
	for _, body := range bad {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			ResolveSym:   func(s string) string { return "m3." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m3.bad": {Name: "m3.bad", Ret: Void}},
		})
		if err == nil {
			t.Errorf("expected error for: %s", body)
		}
	}
}
