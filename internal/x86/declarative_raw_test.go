package x86

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestDeclarativeVecBinOpLowering(t *testing.T) {
	tests := []struct {
		name   string
		goarch string
		body   string
		want   []string
	}{
		{
			name:   "amd64 VPMULLW XMM",
			goarch: "amd64",
			body:   "VPMULLW X0, X1, X2\nRET",
			want:   []string{"bitcast <16 x i8>", "to <8 x i16>", "mul <8 x i16>", "bitcast <8 x i16>"},
		},
		{
			name:   "386 VPMULLW XMM",
			goarch: "386",
			body:   "VPMULLW X0, X1, X2\nRET",
			want:   []string{"bitcast <16 x i8>", "to <8 x i16>", "mul <8 x i16>"},
		},
		{
			name:   "amd64 VPMULLW YMM",
			goarch: "amd64",
			body:   "VPMULLW Y0, Y1, Y2\nRET",
			want:   []string{"bitcast <32 x i8>", "to <16 x i16>", "mul <16 x i16>"},
		},
		{
			name:   "amd64 VPMULLD ZMM",
			goarch: "amd64",
			body:   "VPMULLD Z0, Z1, Z2\nRET",
			want:   []string{"bitcast <64 x i8>", "to <16 x i32>", "mul <16 x i32>"},
		},
		{
			name:   "amd64 PMULLW SSE2 2op",
			goarch: "amd64",
			body:   "PMULLW X0, X1\nRET",
			want:   []string{"mul <8 x i16>"},
		},
		{
			name:   "amd64 VADDPS YMM",
			goarch: "amd64",
			body:   "VADDPS Y0, Y1, Y2\nRET",
			want:   []string{"fadd <8 x float>"},
		},
		{
			name:   "amd64 VPMINUB XMM",
			goarch: "amd64",
			body:   "VPMINUB X0, X1, X2\nRET",
			want:   []string{"icmp ult <16 x i8>", "select <16 x i1>"},
		},
		{
			name:   "amd64 VPMAXSD YMM",
			goarch: "amd64",
			body:   "VPMAXSD Y0, Y1, Y2\nRET",
			want:   []string{"icmp sgt <8 x i32>", "select <8 x i1>"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, err := asm.Parse(asm.ArchAMD64, "TEXT ·f(SB),NOSPLIT,$0-0\n\t"+tc.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			err = TranslateFunc(&b, file.Funcs[0], asm.FuncSig{Name: "example.f", Ret: asm.Void}, testResolveSym("example"), nil, tc.goarch, "", asm.X87Auto, false)
			if err != nil {
				t.Fatalf("TranslateFunc error = %v", err)
			}
			ir := b.String()
			for _, w := range tc.want {
				if !strings.Contains(ir, w) {
					t.Fatalf("missing %q in IR:\n%s", w, ir)
				}
			}
		})
	}
}

func TestDecodeRawDirectives(t *testing.T) {
	for _, goarch := range []string{"386", "amd64"} {
		t.Run(goarch+"/LONG_VPMULLW", func(t *testing.T) {
			file, err := asm.Parse(asm.ArchAMD64, "TEXT ·f(SB),NOSPLIT,$0-0\n\tLONG $0xd0d5f1c5\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeRawDirectives(file.Funcs[0].Instrs, goarch)
			if err != nil {
				t.Fatalf("DecodeRawDirectives error = %v", err)
			}
			if len(decoded) != 3 {
				t.Fatalf("len(decoded) = %d, want 3: %#v", len(decoded), decoded)
			}
			ins := decoded[1]
			if !ins.DecodedFromRaw || ins.Op != "VPMULLW" || len(ins.Args) != 3 ||
				ins.Args[0].Reg != "X0" || ins.Args[1].Reg != "X1" || ins.Args[2].Reg != "X2" {
				t.Fatalf("decoded LONG $0xd0d5f1c5 = %#v, want VPMULLW X0, X1, X2", ins)
			}
		})
	}

	t.Run("BYTE_AESENC_and_UD2", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-0
	BYTE $0x66; BYTE $0x0f; BYTE $0x38; BYTE $0xdc; BYTE $0xc1
	BYTE $0x0f; BYTE $0x0b
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRawDirectives(file.Funcs[0].Instrs, "amd64")
		if err != nil {
			t.Fatalf("DecodeRawDirectives error = %v", err)
		}
		if len(decoded) != 4 || decoded[1].Op != "AESENC" || decoded[2].Op != "UD2" {
			t.Fatalf("decoded = %#v, want AESENC + UD2", decoded)
		}
	})
}

func TestCheckABI0ResultInitBoundaries(t *testing.T) {
	sig := asm.FuncSig{
		Name: "example.f",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.I64,
		Frame: asm.FrameLayout{
			Params:  []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}},
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0, Field: -1}},
		},
	}

	t.Run("named VPMULLW passes", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	PXOR X0, X0
	PXOR X1, X1
	VPMULLW X0, X1, X2
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(file.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("named VPMULLW rejected: %v", err)
		}
	})

	t.Run("raw LONG VPMULLW rejected with ErrProbeNeedsContext", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	PXOR X0, X0
	PXOR X1, X1
	LONG $0xd0d5f1c5
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CheckABI0ResultInit(file.Funcs[0], sig, "amd64")
		if !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("raw LONG err = %v, want ErrProbeNeedsContext", err)
		}
	})

	t.Run("uninitialized register rejected", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ DX, AX
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CheckABI0ResultInit(file.Funcs[0], sig, "amd64")
		if !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("uninit reg err = %v, want ErrProbeNeedsContext", err)
		}
	})

	t.Run("private SP escape rejected", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$32-16
	MOVQ SP, AX
	MOVQ AX, 0(SP)
	MOVQ a+0(FP), AX
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CheckABI0ResultInit(file.Funcs[0], sig, "amd64")
		if !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("private SP escape err = %v, want ErrProbeNeedsContext", err)
		}
	})

	t.Run("extended sub-registers alias parent GP", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), R8
	MOVB R8B, R9B
	MOVQ a+0(FP), SI
	MOVB SIB, DIB
	MOVQ a+0(FP), R10
	MOVL R10L, R11L
	MOVQ R8, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(file.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("extended sub-register aliases rejected: %v", err)
		}
	})

	t.Run("CFG unreachable write skipped by JMP rejected", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	JMP done
	MOVQ $1, ret+8(FP)
done:
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(file.Funcs[0], sig, "amd64"); !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("JMP-skipped result write err = %v, want ErrProbeNeedsContext", err)
		}
	})

	t.Run("CFG conditional branch leaving one path uninitialized rejected", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	CMPQ AX, $0
	JE done
	MOVQ $1, ret+8(FP)
done:
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(file.Funcs[0], sig, "amd64"); !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("conditional-skipped result write err = %v, want ErrProbeNeedsContext", err)
		}
	})

	t.Run("CFG diamond initializing result on all paths accepted", func(t *testing.T) {
		file, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	CMPQ AX, $0
	JE zero
	MOVQ $1, ret+8(FP)
	JMP done
zero:
	MOVQ $0, ret+8(FP)
done:
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(file.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("complete diamond CFG rejected: %v", err)
		}
	})

	t.Run("byte-level partial result write rejected and complete split write accepted", func(t *testing.T) {
		partial, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	MOVL AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(partial.Funcs[0], sig, "amd64"); !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("partial 4-byte write to i64 result err = %v, want ErrProbeNeedsContext", err)
		}

		split, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	MOVL AX, ret+8(FP)
	SHRQ $32, AX
	MOVL AX, ret+12(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(split.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("complete 4+4 split write to i64 result rejected: %v", err)
		}
	})

	t.Run("implicit register writes and reads tracked", func(t *testing.T) {
		// MULQ/CQO/CPUID/RDTSC initialize DX/AX; REP MOVSQ requires CX/SI/DI initialized.
		okFile, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), AX
	CQO
	MOVQ DX, BX
	MULQ BX
	ADDQ DX, AX
	RDTSC
	ADDQ DX, AX
	CPUID
	ADDQ BX, AX
	ADDQ CX, AX
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(okFile.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("implicit writes rejected: %v", err)
		}

		// REP MOVSQ with uninitialized CX must fail.
		badRep, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	MOVQ a+0(FP), SI
	MOVQ a+0(FP), DI
	REP; MOVSQ
	MOVQ SI, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(badRep.Funcs[0], sig, "amd64"); !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("REP MOVSQ with uninit CX err = %v, want ErrProbeNeedsContext", err)
		}

		// Full implicit read/write matrix: LOCK, MULXQ, DIVB, DIVQ, CDQE, XGETBV,
		// RDTSCP, SYSCALL, LAHF, SAHF, XLAT, CMPXCHGQ, CMPXCHG16B, REP STOSQ/LODSQ/MOVSQ.
		fullImplicit, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$32-16
	MOVQ a+0(FP), AX
	MOVQ AX, BX
	MOVQ AX, CX
	MOVQ AX, DX
	MOVQ AX, SI
	MOVQ AX, DI
	MOVQ AX, 0(SP)
	LOCK; ADDQ $1, 0(SP)
	MULXQ BX, R8, R9
	DIVB BL
	DIVQ BX
	CDQE
	XGETBV
	RDTSCP
	SYSCALL
	MOVQ $1, CX // SYSCALL clobbers the previous count.
	LAHF
	SAHF
	XLAT
	CMPXCHGQ BX, 0(SP)
	CMPXCHG16B 0(SP)
	REP; STOSQ
	REP; LODSQ
	REP; MOVSQ
	MOVQ R8, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(fullImplicit.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("full implicit matrix rejected: %v", err)
		}

		// EffectPreserveUpper (e.g. ROUNDSD into uninitialized X1) defines only the low
		// 8 bytes of X1; reading the full 16-byte X1 (via PEXTRQ $1) into result must fail,
		// while reading only the defined low 8 bytes (MOVQ X1) succeeds.
		badPreserve, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	PXOR X0, X0
	ROUNDSD $0, X0, X1
	PEXTRQ $1, X1, AX
	MOVQ AX, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(badPreserve.Funcs[0], sig, "amd64"); !errors.Is(err, asm.ErrProbeNeedsContext) {
			t.Fatalf("EffectPreserveUpper uninit upper bytes err = %v, want ErrProbeNeedsContext", err)
		}

		okPreserveLow, err := asm.Parse(asm.ArchAMD64, `TEXT ·f(SB),NOSPLIT,$0-16
	PXOR X0, X0
	ROUNDSD $0, X0, X1
	MOVQ X1, ret+8(FP)
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckABI0ResultInit(okPreserveLow.Funcs[0], sig, "amd64"); err != nil {
			t.Fatalf("EffectPreserveUpper defined low 8 bytes rejected: %v", err)
		}
	})

	t.Run("byte-level GP, SP, and FP read/write width tracking", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
			sig  asm.FuncSig
			ok   bool
		}{
			{
				name: "MOVB AL then MOVQ AX rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVB $1, AL\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "MOVB AL + MOVB AH then MOVL AX rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVB $1, AL\nMOVB $2, AH\nMOVL AX, ret+8(FP)\nMOVL $0, ret+12(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "MOVB AL + MOVB AH then MOVW AX accepted for uint16 result",
				src:  "TEXT ·f(SB),NOSPLIT,$0-2\nMOVB $1, AL\nMOVB $2, AH\nMOVW AX, ret+0(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.u16",
					Ret:   asm.I16,
					Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Offset: 0, Type: asm.I16, Index: 0, Field: -1}}},
				},
				ok: true,
			},
			{
				name: "MOVL zero-extends to 64-bit AX on amd64",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVL $1, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "MOVB 0(SP) then MOVQ 0(SP) rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$16-16\nMOVB $1, 0(SP)\nMOVQ 0(SP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "MOVL 0(SP) + MOVL 4(SP) then MOVQ 0(SP) accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$16-16\nMOVL $1, 0(SP)\nMOVL $2, 4(SP)\nMOVQ 0(SP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "MOVB ret+8(FP) then MOVQ ret+8(FP) rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVB $1, ret+8(FP)\nMOVQ ret+8(FP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "MOVQ read of 1-byte param rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name: "example.u8in",
					Args: []asm.LLVMType{asm.I8},
					Ret:  asm.I64,
					Frame: asm.FrameLayout{
						Params:  []asm.FrameSlot{{Offset: 0, Type: asm.I8, Index: 0, Field: -1}},
						Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0, Field: -1}},
					},
				},
				ok: false,
			},
			{
				name: "MOVBQZX read of 1-byte param accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVBQZX a+0(FP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name: "example.u8in",
					Args: []asm.LLVMType{asm.I8},
					Ret:  asm.I64,
					Frame: asm.FrameLayout{
						Params:  []asm.FrameSlot{{Offset: 0, Type: asm.I8, Index: 0, Field: -1}},
						Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0, Field: -1}},
					},
				},
				ok: true,
			},
			{
				name: "MOVB AL then MOVL AX->BX then MOVQ BX rejected (bytes 1..3 uninit)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVB $1, AL\nMOVL AX, BX\nMOVQ BX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "overwriting initialized result with partially initialized AX rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ $0, ret+8(FP)\nMOVB $1, AL\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "MOVB AL then ADDQ $0, AX then MOVB AL rejected for uint8",
				src:  "TEXT ·f(SB),NOSPLIT,$0-1\nMOVB $1, AL\nADDQ $0, AX\nMOVB AL, ret+0(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.u8out",
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Offset: 0, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "dead scratch ADDQ on uninit DI (Go stdlib hash/crc32 idiom) accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nADDQ $0x40, DI\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "TESTQ uninit AX clears CF/OF for ADCXQ/ADOXQ (Go stdlib math/big idiom) accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), BX\nXORQ DI, DI\nTESTQ AX, AX\nADCXQ DI, BX\nADOXQ DI, BX\nMOVQ BX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "TESTQ uninit AX then SETEQ AL rejected (ZF undefined)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-1\nTESTQ AX, AX\nSETEQ AL\nMOVB AL, ret+0(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.u8zf",
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Offset: 0, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "stacked labels without spaces (math/big preprocessed idiom) accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), BX\nl1:l2:TESTQ BX,BX\nMOVQ BX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "Plan 9 AUTO negative SP partial write rejected and full write accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$16-16\nMOVB $1, tmp-8(SP)\nMOVQ tmp-8(SP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "Plan 9 AUTO negative SP full write accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$16-16\nMOVQ $1, tmp-8(SP)\nMOVQ tmp-8(SP), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "indexed SP read cannot satisfy ABI0 result slot",
				src:  "TEXT ·f(SB),NOSPLIT,$64-16\nXORQ SI, SI\nMOVQ $1, 0(SP)\nMOVQ (SP)(SI*1), AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "LOCK CMPXCHGL sets ZF for SETEQ result (internal/runtime/atomic Cas idiom)",
				src:  "TEXT ·Cas(SB),NOSPLIT,$0-17\nMOVQ ptr+0(FP), BX\nMOVL old+8(FP), AX\nMOVL new+12(FP), CX\nLOCK\nCMPXCHGL CX, 0(BX)\nSETEQ ret+16(FP)\nRET\n",
				sig: asm.FuncSig{
					Name: "example.Cas",
					Args: []asm.LLVMType{asm.Ptr, asm.I32, asm.I32},
					Ret:  asm.I8,
					Frame: asm.FrameLayout{
						Params: []asm.FrameSlot{
							{Offset: 0, Type: asm.Ptr, Index: 0, Field: -1},
							{Offset: 8, Type: asm.I32, Index: 1, Field: -1},
							{Offset: 12, Type: asm.I32, Index: 2, Field: -1},
						},
						Results: []asm.FrameSlot{{Offset: 16, Type: asm.I8, Index: 0, Field: -1}},
					},
				},
				ok: true,
			},
			{
				name: "KMOVW k, r32 zero-extends to 64-bit GP (internal/runtime/gc/scan FilterNilAVX512 idiom)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nKMOVW AX, K1\nKMOVW K1, R15\nPOPCNTL R15, R15\nMOVQ R15, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "KMOVW uninitialized K1 rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nKMOVW K1, R15\nPOPCNTL R15, R15\nMOVQ R15, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "STC sets CF only: ADCXQ accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nMOVQ $2, BX\nSTC\nADCXQ BX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "STC sets CF only: ADOXQ rejected (OF uninitialized)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nMOVQ $2, BX\nSTC\nADOXQ BX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "INCQ sets OF only: ADOXQ accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nMOVQ $2, BX\nINCQ BX\nADOXQ BX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "INCQ preserves uninit CF: ADCXQ rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nMOVQ $2, BX\nINCQ BX\nADCXQ BX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "BTQ sets CF only: SETCS accepted and SETO rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nBTQ $0, AX\nSETO ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.bto",
					Args:  []asm.LLVMType{asm.I64},
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}}, Results: []asm.FrameSlot{{Offset: 8, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "BTQ preserves ZF: CMPQ then BTQ then SETEQ accepted",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nBTQ $0, AX\nSETEQ ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.btzf",
					Args:  []asm.LLVMType{asm.I64},
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}}, Results: []asm.FrameSlot{{Offset: 8, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: true,
			},
			{
				name: "BTQ clears SF: CMPQ then BTQ then SETS rejected",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nBTQ $0, AX\nSETS ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.btsf",
					Args:  []asm.LLVMType{asm.I64},
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}}, Results: []asm.FrameSlot{{Offset: 8, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "SHLQ $0 preserves uninit CF (SETCS rejected)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nSHLQ $0, AX\nSETCS ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.shl0cf",
					Args:  []asm.LLVMType{asm.I64},
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}}, Results: []asm.FrameSlot{{Offset: 8, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "SHLQ $64 masked count 0 preserves OF (ADOXQ accepted)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nSHLQ $64, AX\nADOXQ AX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "SHLL $32 masked count 0 preserves uninit CF (SETCS rejected)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nSHLL $32, AX\nSETCS ret+8(FP)\nRET\n",
				sig: asm.FuncSig{
					Name:  "example.shl32cf",
					Args:  []asm.LLVMType{asm.I64},
					Ret:   asm.I8,
					Frame: asm.FrameLayout{Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0, Field: -1}}, Results: []asm.FrameSlot{{Offset: 8, Type: asm.I8, Index: 0, Field: -1}}},
				},
				ok: false,
			},
			{
				name: "RCLB $9 effective count 0 preserves OF and does not require CF",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nRCLB $9, AL\nADOXQ AX, AX\nMOVQ AX, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "JE at entry reads uninitialized ZF (rejected)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nJE alt\nMOVQ $1, ret+8(FP)\nRET\nalt:\nMOVQ $2, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
			{
				name: "BTQ preserves ZF for JE and invalidates SF/OF for JL",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nBTQ $0, AX\nJE alt\nMOVQ $1, ret+8(FP)\nRET\nalt:\nMOVQ $2, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   true,
			},
			{
				name: "BTQ invalidates SF/OF for JL (rejected)",
				src:  "TEXT ·f(SB),NOSPLIT,$0-16\nMOVQ a+0(FP), AX\nCMPQ AX, AX\nBTQ $0, AX\nJL alt\nMOVQ $1, ret+8(FP)\nRET\nalt:\nMOVQ $2, ret+8(FP)\nRET\n",
				sig:  sig,
				ok:   false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				file, err := asm.Parse(asm.ArchAMD64, tc.src)
				if err != nil {
					t.Fatal(err)
				}
				_, err = CheckABI0ResultInit(file.Funcs[0], tc.sig, "amd64")
				if tc.ok && err != nil {
					t.Fatalf("expected accept, got %v", err)
				}
				if !tc.ok && !errors.Is(err, asm.ErrProbeNeedsContext) {
					t.Fatalf("expected ErrProbeNeedsContext, got %v", err)
				}
			})
		}
	})
}

func TestRawVEX3ByteVZEROUPPERAndVZEROALL(t *testing.T) {
	// 3-byte VEX C5 F8 77 = VZEROUPPER, C5 FC 77 = VZEROALL
	file, err := asm.Parse(asm.ArchAMD64, `TEXT ·vzu(SB),NOSPLIT,$0-0
	BYTE $0xC5; BYTE $0xF8; BYTE $0x77
	BYTE $0xC5; BYTE $0xFC; BYTE $0x77
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRawDirectives(file.Funcs[0].Instrs, "amd64")
	if err != nil {
		t.Fatalf("DecodeRawDirectives(3-byte VZEROUPPER/VZEROALL): %v", err)
	}
	var ops []asm.Op
	for _, ins := range decoded {
		if ins.DecodedFromRaw {
			ops = append(ops, ins.Op)
		}
	}
	if len(ops) != 2 || ops[0] != "VZEROUPPER" || ops[1] != "VZEROALL" {
		t.Fatalf("decoded ops = %v, want [VZEROUPPER VZEROALL]", ops)
	}
	// Truncated 3-byte VEX opcode requiring ModRM must fail cleanly.
	trunc, err := asm.Parse(asm.ArchAMD64, "TEXT ·t(SB),NOSPLIT,$0-0\n\tBYTE $0xC5; BYTE $0xF8; BYTE $0x58\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRawDirectives(trunc.Funcs[0].Instrs, "amd64"); err == nil {
		t.Fatalf("expected truncated VEX error")
	}
}

func TestLinuxAMD64HardwareSyscallLowering(t *testing.T) {
	file, err := asm.Parse(asm.ArchAMD64, `TEXT ·raw(SB),NOSPLIT,$0-0
	MOVQ $39, AX
	SYSCALL
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	err = TranslateFunc(&b, file.Funcs[0], asm.FuncSig{Name: "example.raw", Ret: asm.I64}, testResolveSym("example"), nil, "amd64", "x86_64-unknown-linux-gnu", asm.X87Auto, false)
	if err != nil {
		t.Fatalf("TranslateFunc(linux/amd64 SYSCALL) error = %v", err)
	}
	ir := b.String()
	for _, want := range []string{
		`call { i64, i64, i64, i64 } asm sideeffect "syscall"`,
		`={ax},={dx},={cx},={r11},0,{di},{si},1,{r10},{r8},{r9}`,
		`extractvalue { i64, i64, i64, i64 }`,
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("Linux amd64 SYSCALL missing %q:\n%s", want, ir)
		}
	}
}

func TestImplicitRegEffectsAndCanonicalGP(t *testing.T) {
	_, writes := implicitRegByteEffects("SYNTH", asm.OpSpec{
		Implicit: asm.ImplicitAX | asm.ImplicitBX | asm.ImplicitCX | asm.ImplicitDX | asm.ImplicitSI | asm.ImplicitDI,
	}, false, 0xff)
	if len(writes) != 6 {
		t.Fatalf("implicitRegByteEffects fallback writes = %v, want 6 regs", writes)
	}
	if got := canonicalGP("r15b"); got != "R15" {
		t.Fatalf("canonicalGP(r15b) = %q, want R15", got)
	}
	if got := canonicalGP("custom"); got != "CUSTOM" {
		t.Fatalf("canonicalGP(custom) = %q, want CUSTOM", got)
	}
}

func TestABI0NativeSyscallRegisterEffects(t *testing.T) {
	const linux = "x86_64-unknown-linux-gnu"
	const bsd = "x86_64-unknown-freebsd"
	for _, tc := range []struct {
		name, triple, before, after string
		accepted                    bool
	}{
		{"LinuxCarryUnknown", linux, "", "SETCS AL", false},
		{"LinuxCarryPreserved", linux, "CLC", "SETCS AL", true},
		{"BSDCarryProduced", bsd, "", "SETCS AL", true},
		{"LinuxCXClobbered", linux, "MOVQ $25,CX", "MOVQ CX,AX", false},
		{"BSDR11Clobbered", bsd, "MOVQ $25,R11", "MOVQ R11,AX", false},
		{"R11Redefined", bsd, "", "MOVQ $25,R11\nMOVQ R11,AX", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "TEXT probe(SB),4,$0-8\nMOVQ $1,AX\n" + tc.before +
				"\nSYSCALL\n" + tc.after + "\nMOVQ AX,ret+0(FP)\nRET\n"
			file, err := asm.Parse(asm.ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			sig := asm.FuncSig{Name: "probe", Ret: asm.I64, Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Type: asm.I64, Field: -1}}}}
			_, err = CheckABI0ResultInitWithOptions(file.Funcs[0], sig, "amd64", nil, nil, asm.X87Auto, tc.triple)
			if tc.accepted && err != nil || !tc.accepted && !errors.Is(err, asm.ErrProbeNeedsContext) {
				t.Fatalf("accepted=%t, check error=%v", tc.accepted, err)
			}
		})
	}
}

func TestDecodeRawMoveExtendAndReservedVEX(t *testing.T) {
	for _, tc := range []struct {
		bytes []byte
		want  asm.Op
	}{
		{[]byte{0x0f, 0xb7, 0x04, 0x5a}, "MOVWLZX"},
		{[]byte{0x48, 0x0f, 0xb6, 0x00}, "MOVBQZX"},
		{[]byte{0x0f, 0xbe, 0xc1}, "MOVBLSX"},
		{[]byte{0x48, 0x63, 0x00}, "MOVLQSX"},
		{[]byte{0xc5, 0xfd, 0xf4, 0xc2}, "VPMULUDQ"},
	} {
		got, err := DecodeRawBytes(tc.bytes, 64)
		if err != nil || len(got) != 1 || got[0].Op != tc.want {
			t.Errorf("%x: %#v, %v (want %s)", tc.bytes, got, err, tc.want)
		}
	}
	for _, raw := range [][]byte{{0xc5, 0xe8, 0x77}, {0xc5, 0xe9, 0x70, 0xc0, 4}} {
		if _, err := DecodeRawBytes(raw, 64); err == nil {
			t.Errorf("accepted reserved inverted vvvv field in %x", raw)
		}
	}
}
