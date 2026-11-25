package plan9asm

import (
	"os/exec"
	"strings"
	"testing"
)

func verifyLLVMIRWithOpt(t *testing.T, ir string) {
	t.Helper()
	opt, err := exec.LookPath("opt")
	if err != nil {
		return
	}
	cmd := exec.Command(opt, "-passes=verify", "-disable-output")
	cmd.Stdin = strings.NewReader(ir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("LLVM opt -passes=verify failed: %v\noutput:\n%s\nIR:\n%s", err, string(out), ir)
	}
}

func TestM1_386MissingForms(t *testing.T) {
	src := `
GLOBL gvar<>(SB), NOPTR, $16
TEXT ·f386(SB),NOSPLIT,$0-0
	MOVL AX, CR0
	MOVL CR0, BX
	MOVL AX, DR0
	MOVL DR0, BX
	MOVL AX, TR6
	MOVL TR6, BX
	MOVW AX, DS
	MOVW DS, BX
	POPL SS
	SHLW $1, AX
	SHLW $1, 8(BX)
	SHLW $1, AX, DX
	SHRW $1, 8(BX)
	SARW $1, 8(BX)
	SALW $1, 8(BX)
	SHLB $1, 8(BX)
	ROLL $1, 8(BX)
	RORL $1, 8(BX)
	NOTL 8(BX)
	SETEQ gvar<>(SB)
	SETNE gvar<>(SB)
	JMP $4
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse 386 failed: %v", err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-pc-linux-gnu",
		Goarch:       "386",
		ResolveSym:   func(s string) string { return "m1." + strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m1.f386": {Name: "m1.f386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate 386 failed: %v", err)
	}
	verifyLLVMIRWithOpt(t, ir)
}

func TestM1_AMD64ScalarAndMMXForms(t *testing.T) {
	src := `
GLOBL gsym<>(SB), NOPTR, $64
TEXT ·scalarMmx(SB),NOSPLIT,$0-0
	MOVQ DX, CR2
	MOVQ CR2, AX
	CMOVQLT 8(BX), AX
	CMOVQLT gsym<>(SB), AX
	POPQ 8(BX)
	POPQ gsym<>(SB)
	TZCNTQ 8(BX), AX
	TZCNTQ gsym<>(SB), AX
	SHLXQ CX, 8(BX), AX
	SHRXQ CX, 8(BX), AX
	RORXL $3, 8(BX), AX
	RORXQ $5, 8(BX), AX
	CRC32B BL, AX
	CRC32W BX, AX
	CRC32L BX, AX
	CRC32Q BX, AX
	SHLQ $2, 8(BX)
	SHRQ $2, 8(BX)
	SARQ $2, 8(BX)
	SHLL $2, 8(BX)
	SHRL $2, 8(BX)
	SARL $2, 8(BX)
	SALQ $2, 8(BX)
	SALL $2, 8(BX)
	ROLQ $2, 8(BX)
	RORQ $2, 8(BX)
	NEGQ 8(BX)
	SETEQ gsym<>(SB)
	SETLT gsym<>(SB)
	SETGT gsym<>(SB)
	SETGE gsym<>(SB)
	SETHI gsym<>(SB)
	SETCS gsym<>(SB)
	SETNE gsym<>(SB)
	PAND M0, M1
	PAND 8(BX), M1
	PAND gsym<>(SB), M1
	PANDN M0, M1
	PANDN X0, X1
	PMULULQ M0, M1
	PCMPEQB M0, M1
	PCMPEQL M0, M1
	PCMPGTB M0, M1
	PMOVMSKB M0, AX
	PUNPCKLBW M0, M1
	PUNPCKHBW M0, M1
	PUNPCKLLQ M0, M1
	PUNPCKHLQ M0, M1
	PSLLW $2, M0
	PSRLW $2, M0
	PSLLL $2, M0
	PSRLL $2, M0
	PSRAL $2, M0
	PSRLQ $2, M0
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse amd64 scalar+MMX failed: %v", err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return "m1." + strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m1.scalarMmx": {Name: "m1.scalarMmx", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate amd64 scalar+MMX failed: %v", err)
	}
	verifyLLVMIRWithOpt(t, ir)
}

func TestM1_AMD64SSEAVXAndAVX512Forms(t *testing.T) {
	src := `
TEXT ·simdForms(SB),NOSPLIT,$0-0
	CMPSS X0, X1, $0
	CMPSS $1, 8(BX), X1
	CMPPS X0, X1, $2
	CMPPS $4, 8(BX), X1
	CMPPD X0, X1, $5
	CMPPD $6, 8(BX), X1
	CMPSD X0, X1, $7
	VFMADD213SD X0, X1, K1, X2
	VFMADD213SD.Z 8(BX), X1, K1, X2
	VFNMADD231SD X0, X1, K1, X2
	VFNMADD231SD.Z 8(BX), X1, K1, X2
	VPTEST X0, X1
	VPTEST 8(BX), X1
	VPTEST Y0, Y1
	VPTEST 8(BX), Y1
	VMOVNTDQ X0, 8(BX)
	VMOVNTDQ Y0, 8(BX)
	VMOVNTDQ Z0, 8(BX)
	AESKEYGENASSIST $1, 8(BX), X1
	PALIGNR $4, 8(BX), X1
	VPCMPEQB X0, X1, K1
	VPCMPEQB Z0, Z1, K1, K2
	VPCMPGTB Z0, Z1, K1, K2
	VPUNPCKLBW Z0, Z1, K1, Z2
	VPUNPCKHBW.Z Z0, Z1, K1, Z2
	VBROADCASTF32X2 X0, K1, Y1
	VBROADCASTF32X2.Z 8(BX), K1, Z1
	VBROADCASTSD 8(BX), K1, Z1
	VPBROADCASTQ.Z 8(BX), K1, Z1
	VXORPD Z0, Z1, K1, Z2
	VXORPD.BCST.Z 8(BX), Z1, K1, Z2
	VPANDQ.BCST 8(BX), Z1, K1, Z2
	VPORQ.Z Z0, Z1, K1, Z2
	VPXORQ Z0, Z1, K1, Z2
	VPOPCNTB X0, X1
	VPOPCNTB Y0, K1, Y1
	VPOPCNTB.Z Z0, K1, Z1
	VPOPCNTW Z0, K1, Z1
	VPOPCNTD.BCST 8(BX), K1, Z1
	VPOPCNTQ Z0, Z1
	VPTERNLOGD $0x00, Z0, Z1, Z2
	VPTERNLOGD $0xFF, Z0, Z1, Z2
	VPTERNLOGD $0x96, Z0, Z1, K1, Z2
	VPTERNLOGD.BCST.Z $0xCA, 8(BX), Z1, K1, Z2
	VPTERNLOGQ $0xE8, Y0, Y1, K1, Y2
	VPCMPB $0, Z0, Z1, K1
	VPCMPB $3, Z0, Z1, K1
	VPCMPB $7, Z0, Z1, K1
	VPCMPUB $1, Y0, Y1, K1, K2
	VPCMPW $2, X0, X1, K1
	VPCMPUW $4, Z0, Z1, K1
	VPCMPD $5, Z0, Z1, K1
	VPCMPUD $6, Z0, Z1, K1
	VPCMPQ $0, Z0, Z1, K1
	VPCMPUQ $3, Z0, Z1, K1
	VPCMPUQ $7, Z0, Z1, K1, K2
	VPCMPUQ.BCST $1, 8(BX), Z1, K1, K2
	VPCOMPRESSB Z0, K1, Z1
	VPCOMPRESSW.Z Z0, K1, Z1
	VPCOMPRESSD Z0, K1, 8(BX)
	VPCOMPRESSQ Z0, K1, 8(BX)
	VPCOMPRESSQ.Z Z0, K1, Z1
	VPCOMPRESSQ Z0, K1, gsym2<>(SB)
	VCOMPRESSPS Y0, K1, Y1
	VCOMPRESSPD X0, K1, 8(BX)
	VPERMB Z0, Z1, K1, Z2
	VPERMI2B.Z Z0, Z1, K1, Z2
	VGF2P8AFFINEQB $3, X0, X1, K1, X2
	VGF2P8AFFINEQB.BCST.Z $5, 8(BX), Z1, K1, Z2
	VGF2P8AFFINEINVQB $1, Y0, Y1, K1, Y2
	VGF2P8MULB Z0, Z1, K1, Z2
	RET
`
	src = "GLOBL gsym2<>(SB), NOPTR, $64\n" + src
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse amd64 SIMD failed: %v", err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return "m1." + strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m1.simdForms": {Name: "m1.simdForms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate amd64 SIMD failed: %v", err)
	}
	for _, want := range []string{
		"@llvm.ctpop.v64i8",
		"@llvm.ctpop.v16i8",
		"@llvm.ctpop.v32i8",
		"fmul double",
	} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing expected %q in generated IR", want)
		}
	}
	verifyLLVMIRWithOpt(t, ir)
	verifyLLVMIRWithHaswellLLC(t, ir)
}

func verifyLLVMIRWithHaswellLLC(t *testing.T, ir string) {
	t.Helper()
	llc, err := exec.LookPath("llc")
	if err != nil {
		return
	}
	cmd := exec.Command(llc,
		"-mtriple=x86_64-unknown-linux-gnu",
		"-mcpu=haswell",
		"-mattr=+aes,+ssse3,+sse4.1,+sse4.2,+pclmul,+avx,+avx2,+sha,+popcnt,+adx",
		"-filetype=null",
	)
	cmd.Stdin = strings.NewReader(ir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("llc haswell codegen failed: %v\noutput:\n%s", err, string(out))
	}
}

func TestM1_ErrorPaths(t *testing.T) {
	badCases := []struct {
		goarch string
		body   string
	}{
		{"386", "POPL $1"},
		{"amd64", "POPQ"},
		{"amd64", "POPQ $1"},
		{"amd64", "TZCNTQ AX"},
		{"amd64", "SHLW AX"},
		{"amd64", "SHLB AX"},
		{"amd64", "SHLXQ AX, BX"},
		{"amd64", "ROLL AX"},
		{"amd64", "ROLQ AX"},
		{"amd64", "RORQ AX"},
		{"amd64", "RORL AX"},
		{"amd64", "RORXL $1, AX"},
		{"amd64", "NOTL"},
		{"amd64", "NEGQ"},
		{"amd64", "CMPPD X0, X1"},
		{"amd64", "CMPPD X0, 8(BX), $1"},
		{"amd64", "VFMADD213SD X0, X1"},
		{"amd64", "VPTERNLOGD $1, Z0, Z1"},
		{"amd64", "VPTERNLOGD $1, Z0, Z1, AX"},
		{"amd64", "VPTERNLOGQ $1, Z0, Z1"},
		{"amd64", "VPCMPUQ $1, Z0, Z1"},
		{"amd64", "VPCMPB $1, Z0, Z1"},
		{"amd64", "VPCMPB $1, 8(BX), 8(BX), K1"},
		{"amd64", "VPCOMPRESSQ Z0"},
		{"amd64", "VPCOMPRESSQ AX, K1, Z1"},
		{"amd64", "VPCOMPRESSB Z0"},
		{"amd64", "VPCOMPRESSB AX, K1, Z1"},
		{"amd64", "VPCOMPRESSB Z0, K1, Y1"},
		{"amd64", "VPCOMPRESSB Z0, K1, $1"},
		{"amd64", "VPERMB Z0, Z1"},
		{"amd64", "VPERMB Z0, Z1, AX"},
		{"amd64", "VGF2P8AFFINEQB $1, Z0, Z1"},
		{"amd64", "VGF2P8AFFINEINVQB $1, Z0, Z1"},
		{"amd64", "VGF2P8AFFINEINVQB $1, Z0, Z1, AX"},
		{"amd64", "VGF2P8MULB Z0, Z1"},
		{"amd64", "PAND $1, M1"},
		{"amd64", "VBROADCASTF32X2 X0"},
		{"amd64", "VPOPCNTB Z0"},
	}
	for _, tc := range badCases {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + tc.body + "\nRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       tc.goarch,
			ResolveSym:   func(s string) string { return "m1." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m1.bad": {Name: "m1.bad", Ret: Void}},
		})
		if err == nil {
			t.Errorf("expected error for %s: %s", tc.goarch, tc.body)
		}
	}
}
