package plan9asm

import (
	"strings"
	"testing"
)

// These forms come from github.com/golang/snappy@v1.0.0. The source module
// is cross-assembled with the native Go toolchain before it enters the
// third-party corpus, so these are positive assembler cases rather than
// speculative opcode probes.
func TestTranslateSnappyScalarForms(t *testing.T) {
	t.Run("amd64", func(t *testing.T) {
		ir := translateEcosystemScalarForms(t, ArchAMD64, "x86_64-unknown-linux-gnu", "amd64", `
TEXT snappy(SB),NOSPLIT,$0-0
	MOVQ $9, AX
	SUBB $4, AX
	CALL emitLiteral(SB)
	RET
`)
		for _, want := range []string{"sub i8", "insertvalue { ptr, i64, i64 }"} {
			if !strings.Contains(ir, want) {
				t.Fatalf("snappy amd64 forms are missing %q:\n%s", want, ir)
			}
		}
	})

	t.Run("arm64", func(t *testing.T) {
		ir := translateEcosystemScalarForms(t, ArchARM64, "aarch64-unknown-linux-gnu", "arm64", `
TEXT snappy(SB),NOSPLIT,$0-0
	MOVW $0xa7bd, R16
	MOVKW $0x3905, R16
	MOVKW $(0x1e35<<16), R16
	MULW R16, R11, R12
	MULW R16, R11
	RET
`)
		if got := strings.Count(ir, "mul i32"); got != 2 {
			t.Fatalf("MULW i32 multiplication count = %d, want 2:\n%s", got, ir)
		}
	})
}

// These forms come from github.com/pierrec/lz4/v4@v4.1.29. Closely related
// spellings are kept together so adding one member of an instruction family
// cannot leave the other accepted Go assembler forms silently unsupported.
func TestTranslateLZ4ScalarForms(t *testing.T) {
	t.Run("arm64", func(t *testing.T) {
		ir := translateEcosystemScalarForms(t, ArchARM64, "aarch64-unknown-linux-gnu", "arm64", `
TEXT lz4(SB),NOSPLIT,$0-0
	CMP $4, R1
	CCMP HS, R2, $4, $0
	CCMPW LO, R2, R3, $1
	CCMN EQ, R4, $5, $2
	CCMNW NE, R5, R6, $3
	BVS overflow
	BVC clear
	MADDW R3, R4, R5, R6
	MSUBW R3, R4, R5, R6
	clear:
	overflow:
	RET
`)
		for want, count := range map[string]int{"mul i32": 2, "select i1": 16, "br i1": 2} {
			if got := strings.Count(ir, want); got < count {
				t.Fatalf("ARM64 lz4 %q count = %d, want at least %d:\n%s", want, got, count, ir)
			}
		}
	})

	t.Run("arm", func(t *testing.T) {
		ir := translateEcosystemScalarForms(t, ArchARM, "armv7-unknown-linux-gnueabihf", "arm", `
TEXT lz4(SB),NOSPLIT,$0-0
	SUB.S $1, R1
	BPL positive
	BVS overflow
	BVC clear
	positive:
	MOVH (R2), R3
	MOVHU (R2), R3
	clear:
	overflow:
	RET
`)
		if got := strings.Count(ir, "br i1"); got != 3 {
			t.Fatalf("ARM BPL/BVS/BVC branch count = %d, want 3:\n%s", got, ir)
		}
	})
}

// These memory-source bit scans come from github.com/dgryski/go-bits. Both
// widths and directions are covered because the Go x86 encoder exposes the
// same register-or-memory source family for each form.
func TestTranslateGoBitsScalarForms(t *testing.T) {
	ir := translateEcosystemScalarForms(t, ArchAMD64, "x86_64-unknown-linux-gnu", "amd64", `
TEXT bits(SB),NOSPLIT,$0-16
	BSFQ x+0(FP), AX
	BSRQ x+0(FP), BX
	BSFL x+0(FP), CX
	BSRL x+0(FP), DX
	MOVQ AX, ret+8(FP)
	RET
`)
	for want, count := range map[string]int{"call i64 @llvm.cttz.i64": 1, "call i64 @llvm.ctlz.i64": 1, "call i32 @llvm.cttz.i32": 1, "call i32 @llvm.ctlz.i32": 1} {
		if got := strings.Count(ir, want); got != count {
			t.Fatalf("go-bits %q count = %d, want %d:\n%s", want, got, count, ir)
		}
	}
}

// These vector forms are taken from minio/highwayhash, minio/sha256-simd,
// and klauspost/reedsolomon respectively. Keep the related unpack spellings
// together so the source-level aliases cannot drift apart.
func TestTranslateDiscoveredX86VectorForms(t *testing.T) {
	ir := translateEcosystemScalarForms(t, ArchAMD64, "x86_64-unknown-linux-gnu", "amd64", `
TEXT vectors(SB),NOSPLIT,$0-0
	PMULULQ X2, X8
	PUNPCKLLQ X1, X2
	PUNPCKHLQ X1, X3
	VPBROADCASTQ X0, X7
	VPBROADCASTQ (AX), Y8
	VPBROADCASTQ (AX), Z9
	POPCNTQ -8(SI)(BX*1), R11
	POPCNTL 4(AX), R10
	RET
`)
	for _, want := range []string{"mul <2 x i64>", "shufflevector <4 x i32>", "shufflevector <2 x i64>", "@llvm.ctpop.i64", "@llvm.ctpop.i32"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("discovered x86 vector forms are missing %q:\n%s", want, ir)
		}
	}
}

// These forms come from github.com/aead/siphash@v1.0.1,
// github.com/klauspost/crc32@v1.3.0, and github.com/phuslu/log@v1.0.132.
// The packed min/max forms are tested as a family because the Go assembler
// accepts the same register-or-memory source shape for every lane width and
// signedness combination.
func TestTranslateExpandedEcosystemX86VectorForms(t *testing.T) {
	ir := translateEcosystemScalarForms(t, ArchAMD64, "x86_64-unknown-linux-gnu", "amd64", `
TEXT vectors(SB),NOSPLIT,$0-0
	MOVQ $13, AX
	VMOVQ AX, X0
	PSLLQ $13, X0
	PSRLQ $64, X0
	PMINUB X1, X0
	PMINSB X1, X0
	PMINUW X1, X0
	PMINSW X1, X0
	PMINUD X1, X0
	PMINSD X1, X0
	PMAXUB X1, X0
	PMAXSB X1, X0
	PMAXUW X1, X0
	PMAXSW X1, X0
	PMAXUD X1, X0
	PMAXSD 16(BX), X0
	VMOVQ X0, CX
	VZEROUPPER
	RET
`)
	for want, count := range map[string]int{
		"shl <2 x i64>":            1,
		"icmp ult <16 x i8>":       1,
		"icmp slt <16 x i8>":       1,
		"icmp ult <8 x i16>":       1,
		"icmp slt <8 x i16>":       1,
		"icmp ult <4 x i32>":       1,
		"icmp slt <4 x i32>":       1,
		"icmp ugt <16 x i8>":       1,
		"icmp sgt <16 x i8>":       1,
		"icmp ugt <8 x i16>":       1,
		"icmp sgt <8 x i16>":       1,
		"icmp ugt <4 x i32>":       1,
		"icmp sgt <4 x i32>":       1,
		"extractelement <2 x i64>": 1,
	} {
		if got := strings.Count(ir, want); got != count {
			t.Fatalf("expanded ecosystem form %q count = %d, want %d:\n%s", want, got, count, ir)
		}
	}
	if !strings.Contains(ir, "store <16 x i8> zeroinitializer") {
		t.Fatalf("PSRLQ with an oversized count must clear the vector:\n%s", ir)
	}
}

func translateEcosystemScalarForms(t *testing.T, arch Arch, triple, goarch, src string) string {
	t.Helper()
	file, err := Parse(arch, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"snappy": {Name: "snappy", Ret: Void},
			"lz4":    {Name: "lz4", Ret: Void},
			"bits": {
				Name: "bits",
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
			"vectors":     {Name: "vectors", Ret: Void},
			"emitLiteral": {Name: "emitLiteral", Args: []LLVMType{"{ ptr, i64, i64 }", "{ ptr, i64, i64 }"}, Ret: I64},
		},
		Goarch: goarch,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}
