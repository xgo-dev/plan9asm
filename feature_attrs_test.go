package plan9asm

import (
	"strings"
	"testing"
)

func TestInferFuncTargetFeatures(t *testing.T) {
	tests := []struct {
		name string
		arch Arch
		ops  []Op
		want string
	}{
		{
			name: "amd64 crc32",
			arch: ArchAMD64,
			ops:  []Op{"CRC32B", "CRC32Q"},
			want: "+crc32,+sse4.2",
		},
		{
			name: "amd64 pclmul",
			arch: ArchAMD64,
			ops:  []Op{"PCLMULQDQ", "VPCLMULQDQ"},
			want: "+pclmul,+sse4.1",
		},
		{
			name: "amd64 pshufb",
			arch: ArchAMD64,
			ops:  []Op{"PSHUFB", "VPSHUFB"},
			want: "+ssse3",
		},
		{
			name: "amd64 aes",
			arch: ArchAMD64,
			ops:  []Op{"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST", "VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST", "VAESIMC", "VAESKEYGENASSIST"},
			want: "+aes",
		},
		{
			name: "amd64 cmpxchg16b",
			arch: ArchAMD64,
			ops:  []Op{"CMPXCHG16B"},
			want: "+cx16",
		},
		{
			name: "x86 cache line writeback",
			arch: ArchAMD64,
			ops:  []Op{"CLFLUSH", "CLFLUSHOPT", "CLWB"},
			want: "+clflushopt,+clwb",
		},
		{
			name: "amd64 round",
			arch: ArchAMD64,
			ops:  []Op{"ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD", "VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD"},
			want: "+avx,+sse4.1",
		},
		{
			name: "x86 reciprocal14",
			arch: ArchAMD64,
			ops:  []Op{"VRCP14SS", "VRSQRT14PD.Z"},
			want: "+avx512f,+avx512vl",
		},
		{
			name: "x86 raw fp16",
			arch: ArchAMD64,
			ops:  []Op{"VMOVSH", "VADDSH.RU_SAE", "VMAXPH.SAE", "VFMADD213SH", "VFNMADD231PH.Z"},
			want: "+avx512fp16",
		},
		{
			name: "x86 raw BF16 dot product",
			arch: ArchAMD64,
			ops:  []Op{"VDPBF16PS", "VDPBF16PS.BCST.Z"},
			want: "+avx512bf16,+avx512f",
		},
		{
			name: "x86 single float duplicate is not fp16",
			arch: ArchAMD64,
			ops:  []Op{"VMOVSHDUP"},
			want: "",
		},
		{
			name: "amd64 combined sorted deduped",
			arch: ArchAMD64,
			ops:  []Op{"AESENC", "CRC32L", "PCLMULQDQ", "PSHUFB", "CRC32Q", "AESDEC", "VPSHUFB"},
			want: "+aes,+crc32,+pclmul,+sse4.1,+sse4.2,+ssse3",
		},
		{
			name: "arm64 crc32",
			arch: ArchARM64,
			ops:  []Op{"CRC32CX", "CRC32W"},
			want: "+crc",
		},
		{
			name: "no feature attrs",
			arch: ArchAMD64,
			ops:  []Op{"MOVQ", "RET"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := Func{Instrs: make([]Instr, len(tt.ops))}
			for i, op := range tt.ops {
				fn.Instrs[i] = Instr{Op: op}
			}
			if got := inferFuncTargetFeatures(tt.arch, fn); got != tt.want {
				t.Fatalf("inferFuncTargetFeatures(%q, %v) = %q, want %q", tt.arch, tt.ops, got, tt.want)
			}
		})
	}
}

func TestInferFuncTargetFeaturesRawFP16VectorLength(t *testing.T) {
	for _, op := range []Op{"VFMADD132PH", "VFMSUBADD231PH.Z", "VADDPH"} {
		for _, reg := range []Reg{"X1", "Y1", "Z1"} {
			fn := Func{Instrs: []Instr{{Op: op, Args: []Operand{{Kind: OpReg, Reg: reg}}}}}
			want := "+avx512fp16"
			if reg != "Z1" {
				want += ",+avx512vl"
			}
			if got := inferFuncTargetFeatures(ArchAMD64, fn); got != want {
				t.Fatalf("%s %s: features %q, want %q", op, reg, got, want)
			}
		}
	}
}

func TestFeatureAttrRegistry(t *testing.T) {
	r := newFeatureAttrRegistry()
	if got := r.ref(""); got != "" {
		t.Fatalf("ref(\"\") = %q", got)
	}
	if got := r.ref("+aes"); got != "#200" {
		t.Fatalf("ref(+aes) = %q", got)
	}
	if got := r.ref("+crc"); got != "#201" {
		t.Fatalf("ref(+crc) = %q", got)
	}
	if got := r.ref("+aes"); got != "#200" {
		t.Fatalf("ref(+aes repeat) = %q", got)
	}

	var b strings.Builder
	r.emit(&b)
	out := b.String()
	for _, want := range []string{
		`attributes #200 = { "target-features"="+aes" }`,
		`attributes #201 = { "target-features"="+crc" }`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("emit() missing %q in:\n%s", want, out)
		}
	}

	var empty strings.Builder
	newFeatureAttrRegistry().emit(&empty)
	if empty.String() != "" {
		t.Fatalf("emit(empty) = %q", empty.String())
	}
}

func TestInferARMVFPFeatureFromRuntimeSaveRestore(t *testing.T) {
	fn := Func{Instrs: []Instr{
		{Op: "MOVW", Args: []Operand{{Kind: OpIdent, Ident: "FPCR"}, {Kind: OpReg, Reg: Reg("R0")}}},
		{Op: "MOVD", Args: []Operand{{Kind: OpReg, Reg: Reg("F0")}, {Kind: OpMem}}},
	}}
	if got := inferFuncTargetFeaturesForGOARCH(ArchARM, "arm", fn); got != "+vfp2" {
		t.Fatalf("ARM runtime VFP feature = %q, want +vfp2", got)
	}
}
