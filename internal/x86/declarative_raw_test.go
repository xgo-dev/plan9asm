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
		`call { i64, i64 } asm sideeffect "syscall"`,
		`={ax},={dx},0,{di},{si},1,{r10},{r8},{r9},~{rcx},~{r11}`,
		`extractvalue { i64, i64 }`,
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("Linux amd64 SYSCALL missing %q:\n%s", want, ir)
		}
	}
}
