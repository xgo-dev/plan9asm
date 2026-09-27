package plan9asm

import (
	"strings"
	"testing"
)

func TestX86RawDecoderPreservesGoOpcodeAliasesAndMandatoryPrefixes(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want Op
	}{
		{name: "PACKSSDW is Go PACKSSLW", code: []byte{0x66, 0x0f, 0x6b, 0xca}, want: "PACKSSLW"},
		{name: "PCMPEQD is Go PCMPEQL", code: []byte{0x66, 0x0f, 0x76, 0xca}, want: "PCMPEQL"},
		{name: "PCMPGTD is Go PCMPGTL", code: []byte{0x66, 0x0f, 0x66, 0xca}, want: "PCMPGTL"},
		{name: "PMADDWD is Go PMADDWL", code: []byte{0x66, 0x0f, 0xf5, 0xca}, want: "PMADDWL"},
		{name: "PMULUDQ is Go PMULULQ", code: []byte{0x66, 0x0f, 0xf4, 0xca}, want: "PMULULQ"},
		{name: "PSLLD is Go PSLLL", code: []byte{0x66, 0x0f, 0xf2, 0xca}, want: "PSLLL"},
		{name: "PSRAD is Go PSRAL", code: []byte{0x66, 0x0f, 0xe2, 0xca}, want: "PSRAL"},
		{name: "PSRLD is Go PSRLL", code: []byte{0x66, 0x0f, 0xd2, 0xca}, want: "PSRLL"},
		{name: "PSUBD is Go PSUBL", code: []byte{0x66, 0x0f, 0xfa, 0xca}, want: "PSUBL"},
		{name: "PUNPCKHDQ is Go PUNPCKHLQ", code: []byte{0x66, 0x0f, 0x6a, 0xca}, want: "PUNPCKHLQ"},
		{name: "PUNPCKHWD is Go PUNPCKHWL", code: []byte{0x66, 0x0f, 0x69, 0xca}, want: "PUNPCKHWL"},
		{name: "PUNPCKLDQ is Go PUNPCKLLQ", code: []byte{0x66, 0x0f, 0x62, 0xca}, want: "PUNPCKLLQ"},
		{name: "PUNPCKLWD is Go PUNPCKLWL", code: []byte{0x66, 0x0f, 0x61, 0xca}, want: "PUNPCKLWL"},
		{name: "MOVDQA is Go MOVO", code: []byte{0x66, 0x0f, 0x6f, 0xc1}, want: "MOVO"},
		{name: "MOVDQU is Go MOVOU", code: []byte{0xf3, 0x0f, 0x6f, 0xc1}, want: "MOVOU"},
		{name: "MOVSD XMM is Go MOVSD", code: []byte{0xf2, 0x0f, 0x10, 0xc1}, want: "MOVSD"},
		{name: "CLFLUSHOPT mandatory prefix", code: []byte{0x66, 0x0f, 0xae, 0x38}, want: "CLFLUSHOPT"},
		{name: "CLWB mandatory prefix", code: []byte{0x66, 0x0f, 0xae, 0x30}, want: "CLWB"},
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, test := range tests {
			t.Run(goarch+"/"+test.name, func(t *testing.T) {
				fn := Func{}
				for _, value := range test.code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != test.want {
					t.Fatalf("decoded %#x as %#v, want one %s instruction", test.code, got.Instrs, test.want)
				}
			})
		}
	}
}

func TestX86RawDecoderVBROADCASTI128CompleteFamily(t *testing.T) {
	tests := []struct {
		name   string
		goarch string
		code   []byte
		source MemRef
		dest   Reg
	}{
		{name: "low registers", goarch: "amd64", code: []byte{0xc4, 0xe2, 0x7d, 0x5a, 0x13}, source: MemRef{Base: BX}, dest: "Y2"},
		{name: "extended base", goarch: "amd64", code: []byte{0xc4, 0xc2, 0x7d, 0x5a, 0x13}, source: MemRef{Base: "R11"}, dest: "Y2"},
		{name: "extended destination", goarch: "amd64", code: []byte{0xc4, 0x62, 0x7d, 0x5a, 0x1b}, source: MemRef{Base: BX}, dest: "Y11"},
		{name: "extended base and destination with displacement", goarch: "amd64", code: []byte{0xc4, 0x42, 0x7d, 0x5a, 0x70, 0x10}, source: MemRef{Base: "R8", Off: 16}, dest: "Y14"},
		{name: "extended SIB", goarch: "amd64", code: []byte{0xc4, 0x02, 0x7d, 0x5a, 0x64, 0x88, 0x20}, source: MemRef{Base: "R8", Index: "R9", Scale: 4, Off: 32}, dest: "Y12"},
		{name: "FS segment", goarch: "amd64", code: []byte{0x64, 0xc4, 0xe2, 0x7d, 0x5a, 0x13}, source: MemRef{Segment: FS, Base: BX}, dest: "Y2"},
		{name: "32-bit base", goarch: "386", code: []byte{0xc4, 0xe2, 0x7d, 0x5a, 0x53, 0x7f}, source: MemRef{Base: BX, Off: 127}, dest: "Y2"},
		{name: "32-bit absolute", goarch: "386", code: []byte{0xc4, 0xe2, 0x7d, 0x5a, 0x15, 0x78, 0x56, 0x34, 0x12}, source: MemRef{Off: 0x12345678}, dest: "Y2"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"/"+test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, test.goarch)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 {
				t.Fatalf("decoded %#x as %#v, want one instruction", test.code, got.Instrs)
			}
			ins := got.Instrs[0]
			if ins.Op != "VBROADCASTI128" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[0].Mem != test.source || ins.Args[1].Kind != OpReg || ins.Args[1].Reg != test.dest {
				t.Fatalf("decoded %#x as %#v, want VBROADCASTI128 %#v, %s", test.code, ins, test.source, test.dest)
			}
		})
	}
}

func TestX86RawDecoderNormalizesArchitecturalAliasesToGo127Forms(t *testing.T) {
	code := []byte{
		0x41, 0x0f, 0x90, 0xc1, // SETO R9B -> SETOS R9B
		0x41, 0x0f, 0x92, 0xc1, // SETB R9B -> SETCS R9B
		0x48, 0x0f, 0x4e, 0xc1, // CMOVLE RAX, RCX -> CMOVQLE AX, CX
		0x04, 0x01, // ADD $1, AL -> ADDB $1, AL
	}
	fn := Func{}
	for _, value := range code {
		fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
	}
	got, err := decodeX86RawDirectives(fn, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := []Op{"SETOS", "SETCS", "CMOVQLE", "ADDB"}
	if len(got.Instrs) != len(want) {
		t.Fatalf("decoded %#x as %#v, want %d instructions", code, got.Instrs, len(want))
	}
	for i, op := range want {
		if got.Instrs[i].Op != op {
			t.Errorf("decoded instruction %d as %s, want %s (%q)", i, got.Instrs[i].Op, op, got.Instrs[i].Raw)
		}
	}
	if got.Instrs[0].Args[0].Reg != R9B || got.Instrs[1].Args[0].Reg != R9B {
		t.Errorf("SETcc byte aliases = %s and %s, want R9B", got.Instrs[0].Args[0].Reg, got.Instrs[1].Args[0].Reg)
	}
}

func TestX86RawDecoderNormalizesEveryThreeOperandIMULWidth(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want Op
	}{
		{name: "word imm8 register", code: []byte{0x66, 0x6b, 0xf9, 0x07}, want: "IMUL3W"},
		{name: "long imm8 register", code: []byte{0x6b, 0xf9, 0x07}, want: "IMUL3L"},
		{name: "quad imm8 register", code: []byte{0x48, 0x6b, 0xf9, 0x07}, want: "IMUL3Q"},
		{name: "word imm16 memory", code: []byte{0x66, 0x69, 0x78, 0x08, 0x34, 0x12}, want: "IMUL3W"},
		{name: "long imm32 memory", code: []byte{0x69, 0x78, 0x08, 0x78, 0x56, 0x34, 0x12}, want: "IMUL3L"},
		{name: "quad imm32 memory", code: []byte{0x48, 0x69, 0x78, 0x08, 0x78, 0x56, 0x34, 0x12}, want: "IMUL3Q"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != test.want || len(got.Instrs[0].Args) != 3 {
				t.Fatalf("decoded %#x as %#v, want one three-operand %s", test.code, got.Instrs, test.want)
			}
		})
	}
}

func TestX86RawDecoderNormalizesCompleteBSWAPFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want Op
		reg  Reg
	}{
		{name: "long low register", code: []byte{0x0f, 0xc8}, want: "BSWAPL", reg: AX},
		{name: "long extended register", code: []byte{0x41, 0x0f, 0xcf}, want: "BSWAPL", reg: Reg("R15")},
		{name: "quad low register", code: []byte{0x48, 0x0f, 0xc8}, want: "BSWAPQ", reg: AX},
		{name: "quad extended register", code: []byte{0x49, 0x0f, 0xcf}, want: "BSWAPQ", reg: Reg("R15")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != test.want || len(got.Instrs[0].Args) != 1 || got.Instrs[0].Args[0].Reg != test.reg {
				t.Fatalf("decoded %#x as %#v, want %s %s", test.code, got.Instrs, test.want, test.reg)
			}
		})
	}
}

func TestX86RawDecoderNormalizesCompleteScalarIntegerFloatFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want Op
	}{
		{name: "long to float register", code: []byte{0xf3, 0x0f, 0x2a, 0xc8}, want: "CVTSL2SS"},
		{name: "long to float memory", code: []byte{0xf3, 0x0f, 0x2a, 0x48, 0x08}, want: "CVTSL2SS"},
		{name: "quad to float register", code: []byte{0xf3, 0x48, 0x0f, 0x2a, 0xc8}, want: "CVTSQ2SS"},
		{name: "quad to float memory", code: []byte{0xf3, 0x48, 0x0f, 0x2a, 0x48, 0x08}, want: "CVTSQ2SS"},
		{name: "long to double register", code: []byte{0xf2, 0x0f, 0x2a, 0xc8}, want: "CVTSL2SD"},
		{name: "long to double memory", code: []byte{0xf2, 0x0f, 0x2a, 0x48, 0x08}, want: "CVTSL2SD"},
		{name: "quad to double register", code: []byte{0xf2, 0x48, 0x0f, 0x2a, 0xc8}, want: "CVTSQ2SD"},
		{name: "quad to double memory", code: []byte{0xf2, 0x48, 0x0f, 0x2a, 0x48, 0x08}, want: "CVTSQ2SD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != test.want || len(got.Instrs[0].Args) != 2 {
				t.Fatalf("decoded %#x as %#v, want one %s", test.code, got.Instrs, test.want)
			}
		})
	}
}

func TestX86RawDecoderNormalizesCompleteScalarFloatIntegerFamily(t *testing.T) {
	for _, goarch := range []string{"386", "amd64"} {
		for _, precision := range []struct {
			name   string
			prefix byte
		}{
			{name: "SS", prefix: 0xf3},
			{name: "SD", prefix: 0xf2},
		} {
			for _, conversion := range []struct {
				name   string
				opcode byte
			}{
				{name: "CVT", opcode: 0x2d},
				{name: "CVTT", opcode: 0x2c},
			} {
				for _, width := range []struct {
					name string
					rex  []byte
				}{
					{name: "L"},
					{name: "Q", rex: []byte{0x48}},
				} {
					if goarch == "386" && width.name == "Q" {
						continue
					}
					for _, source := range []struct {
						name  string
						modRM byte
						disp  []byte
					}{
						{name: "register", modRM: 0xc1},
						{name: "memory", modRM: 0x43, disp: []byte{0x08}},
					} {
						name := goarch + "/" + conversion.name + precision.name + "2S" + width.name + "/" + source.name
						t.Run(name, func(t *testing.T) {
							code := []byte{precision.prefix}
							code = append(code, width.rex...)
							code = append(code, 0x0f, conversion.opcode, source.modRM)
							code = append(code, source.disp...)
							fn := Func{}
							for _, value := range code {
								fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
							}
							got, err := decodeX86RawDirectives(fn, goarch)
							if err != nil {
								t.Fatal(err)
							}
							want := Op(conversion.name + precision.name + "2S" + width.name)
							if len(got.Instrs) != 1 || got.Instrs[0].Op != want || len(got.Instrs[0].Args) != 2 {
								t.Fatalf("decoded %#x as %#v, want one %s", code, got.Instrs, want)
							}
						})
					}
				}
			}
		}
	}
}

func TestTranslateX86RawScalarFloatIntegerReportedEncoding(t *testing.T) {
	const source = `TEXT rawScalarFloatInteger(SB),$0-0
	LONG $0x2c0f48f2
	BYTE $0xc0 // CVTTSD2SQ X0, AX
	RET
`
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"rawScalarFloatInteger": {Name: "rawScalarFloatInteger", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "fptosi double") || !strings.Contains(ir, " to i64") {
				t.Fatalf("raw CVTTSD2SQ semantics missing:\n%s", ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "raw-scalar-float-integer.ll", "raw-scalar-float-integer.o", ir)
		})
	}
}

func TestX86RawDecoderNormalizesCompleteMOVNTDQFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		reg  Reg
		base Reg
	}{
		{name: "low vector and base registers", code: []byte{0x66, 0x0f, 0xe7, 0x13}, reg: Reg("X2"), base: BX},
		{name: "extended vector register", code: []byte{0x66, 0x44, 0x0f, 0xe7, 0x1b}, reg: Reg("X11"), base: BX},
		{name: "extended base register", code: []byte{0x66, 0x41, 0x0f, 0xe7, 0x13}, reg: Reg("X2"), base: Reg("R11")},
		{name: "extended vector and base registers", code: []byte{0x66, 0x45, 0x0f, 0xe7, 0x1b}, reg: Reg("X11"), base: Reg("R11")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || got.Instrs[0].Op != "MOVNTO" || len(got.Instrs[0].Args) != 2 || got.Instrs[0].Args[0].Reg != test.reg || got.Instrs[0].Args[1].Mem.Base != test.base {
				t.Fatalf("decoded %#x as %#v, want MOVNTO %s, (%s)", test.code, got.Instrs, test.reg, test.base)
			}
		})
	}
}

func TestTranslateAMD64MOVNTOCompleteOperandForm(t *testing.T) {
	const source = `TEXT movnto(SB),$0-0
	MOVNTO X2, 32(BX)(R8*1)
	MOVNTO X11, sink<>(SB)
	RET

GLOBL sink<>(SB),$16
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"movnto": {Name: "movnto", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(ir, "store <16 x i8> %"); count != 2 {
		t.Fatalf("MOVNTO emitted %d vector stores, want 2:\n%s", count, ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-movnto.ll", "amd64-movnto.o", ir)
}

func TestDecodedX86CacheLineWritebackCoversMemoryEncodingsWithoutFalsePositives(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
		ok   bool
	}{
		{name: "CLFLUSHOPT displacement", code: []byte{0x67, 0x66, 0x0f, 0xae, 0x78, 0x08}, want: "CLFLUSHOPT", ok: true},
		{name: "CLWB SIB displacement", code: []byte{0x66, 0x0f, 0xae, 0xb4, 0x24, 0x78, 0x56, 0x34, 0x12}, want: "CLWB", ok: true},
		{name: "CLWB REX base", code: []byte{0x66, 0x41, 0x0f, 0xae, 0x30}, want: "CLWB", ok: true},
		{name: "plain CLFLUSH", code: []byte{0x0f, 0xae, 0x38}},
		{name: "plain XSAVEOPT", code: []byte{0x0f, 0xae, 0x30}},
		{name: "register ModRM", code: []byte{0x66, 0x0f, 0xae, 0xf8}},
		{name: "opcode bytes in displacement", code: []byte{0x66, 0x8b, 0x80, 0x0f, 0xae, 0x38, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := decodedX86CacheLineWriteback(test.code)
			if got != test.want || ok != test.ok {
				t.Fatalf("decodedX86CacheLineWriteback(%#x) = %q, %v; want %q, %v", test.code, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestDecodeX86RawDirectiveGroupReportedWencodeCLFLUSHOPT(t *testing.T) {
	code := []byte{0x41, 0x66, 0x0f, 0xae, 0x3c, 0x09}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "wencode CLFLUSHOPT sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "CLFLUSHOPT" || len(decoded[0].Args) != 1 || decoded[0].Args[0].String() != "0(CX)(CX*1)" {
		t.Fatalf("decoded %x as %#v, want CLFLUSHOPT 0(CX)(CX*1)", code, decoded)
	}
}

func encodeX86RawCacheLineWriteback(op Op, mode, base, index int) []byte {
	extension := byte(7)
	mandatory := op != "CLFLUSH"
	if op == "CLWB" {
		extension = 6
	}
	var prefixes []byte
	if mode == 64 {
		rex := byte(0x40 | base/8 | index/8<<1)
		if mandatory {
			prefixes = append(prefixes, 0x66)
		}
		prefixes = append(prefixes, rex)
	} else if mandatory {
		prefixes = append(prefixes, 0x66)
	}
	mod := byte(0)
	if base&7 == 5 {
		mod = 1
	}
	modRM := mod<<6 | extension<<3 | 4
	sib := byte(2<<6 | (index&7)<<3 | base&7)
	code := append(prefixes, 0x0f, 0xae, modRM, sib)
	if mod == 1 {
		code = append(code, 0)
	}
	return code
}

func TestDecodedX86RawCacheLineWritebackCompleteRegisterAddressFamily(t *testing.T) {
	operations := []Op{"CLFLUSH", "CLFLUSHOPT", "CLWB"}
	count := 0
	for _, mode := range []int{32, 64} {
		registers := 8
		if mode == 64 {
			registers = 16
		}
		for _, op := range operations {
			for base := 0; base < registers; base++ {
				for index := 0; index < registers; index++ {
					if index == 4 {
						continue // SIB index 4 without X is the no-index encoding.
					}
					code := encodeX86RawCacheLineWriteback(op, mode, base, index)
					got, length, ok, err := decodedX86CacheLineWritebackInstruction(code, mode)
					baseReg, _ := decodedX86GeneralRegister(base)
					indexReg, _ := decodedX86GeneralRegister(index)
					wantMemory := MemRef{Base: baseReg, Index: indexReg, Scale: 4}
					if err != nil || !ok || length != len(code) || got.Op != op || len(got.Args) != 1 || got.Args[0].Kind != OpMem || got.Args[0].Mem != wantMemory {
						t.Fatalf("decode mode=%d %x = %+v, length=%d, ok=%v, err=%v; want %s %+v", mode, code, got, length, ok, err, op, wantMemory)
					}
					count++
				}
			}
		}
	}
	if count != 888 {
		t.Fatalf("covered %d cache-line register-address encodings, want 888", count)
	}
}

func TestDecodedX86RawCacheLineWritebackMemoryAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
		op   Op
		mem  MemRef
	}{
		{name: "CLFLUSH base", code: []byte{0x0f, 0xae, 0x3b}, mode: 64, op: "CLFLUSH", mem: MemRef{Base: BX}},
		{name: "CLFLUSHOPT disp8", code: []byte{0x66, 0x0f, 0xae, 0x7e, 0x7f}, mode: 64, op: "CLFLUSHOPT", mem: MemRef{Base: SI, Off: 127}},
		{name: "CLWB disp32", code: []byte{0x66, 0x0f, 0xae, 0xb7, 0x78, 0x56, 0x34, 0x12}, mode: 64, op: "CLWB", mem: MemRef{Base: DI, Off: 0x12345678}},
		{name: "CLFLUSHOPT ineffective REX before 66", code: []byte{0x41, 0x66, 0x0f, 0xae, 0x3c, 0x09}, mode: 64, op: "CLFLUSHOPT", mem: MemRef{Base: CX, Index: CX, Scale: 1}},
		{name: "CLFLUSHOPT effective REX after 66", code: []byte{0x66, 0x41, 0x0f, 0xae, 0x3c, 0x09}, mode: 64, op: "CLFLUSHOPT", mem: MemRef{Base: "R9", Index: CX, Scale: 1}},
		{name: "CLWB FS extended SIB", code: []byte{0x64, 0x66, 0x43, 0x0f, 0xae, 0x74, 0x8b, 0x20}, mode: 64, op: "CLWB", mem: MemRef{Segment: FS, Base: "R11", Index: "R9", Scale: 4, Off: 32}},
		{name: "CLFLUSHOPT 386 absolute", code: []byte{0x66, 0x0f, 0xae, 0x3d, 0x78, 0x56, 0x34, 0x12}, mode: 32, op: "CLFLUSHOPT", mem: MemRef{Off: 0x12345678}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86CacheLineWritebackInstruction(test.code, test.mode)
			if err != nil || !ok || length != len(test.code) || got.Op != test.op || len(got.Args) != 1 || got.Args[0].Kind != OpMem || got.Args[0].Mem != test.mem {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %s %+v", test.code, got, length, ok, err, test.op, test.mem)
			}
		})
	}

	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{name: "address override", code: []byte{0x67, 0x66, 0x0f, 0xae, 0x38}, mode: 64},
		{name: "REX.W", code: []byte{0x66, 0x48, 0x0f, 0xae, 0x38}, mode: 64},
		{name: "REX.R", code: []byte{0x66, 0x44, 0x0f, 0xae, 0x38}, mode: 64},
		{name: "register operand", code: []byte{0x66, 0x0f, 0xae, 0xf8}, mode: 64},
		{name: "RIP relative", code: []byte{0x66, 0x0f, 0xae, 0x3d, 0, 0, 0, 0}, mode: 64},
		{name: "truncated SIB", code: []byte{0x66, 0x0f, 0xae, 0x3c}, mode: 64},
		{name: "truncated disp8", code: []byte{0x66, 0x0f, 0xae, 0x78}, mode: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86CacheLineWritebackInstruction(test.code, test.mode)
			if !ok || err == nil {
				t.Fatalf("invalid encoding %x returned ok=%v err=%v", test.code, ok, err)
			}
		})
	}
	for _, code := range [][]byte{
		{0x0f, 0xae, 0x30},                         // XSAVEOPT, not CLWB.
		{0x66, 0x0f, 0xae, 0x28},                   // unrelated ModRM extension.
		{0x66, 0x0f, 0xaf, 0x38},                   // unrelated opcode.
		{0x66, 0x0f},                               // truncated before the opcode can be identified.
		{0xf2, 0x66, 0x0f, 0xae, 0x38},             // unsupported mandatory prefix combination.
		{0x66, 0x0f, 0xae, 0x38, 0x0f, 0xae, 0x38}, // only the first instruction is consumed.
	} {
		_, length, ok, err := decodedX86CacheLineWritebackInstruction(code, 64)
		if len(code) == 7 {
			if err != nil || !ok || length != 4 {
				t.Fatalf("concatenated encoding %x returned length=%d ok=%v err=%v", code, length, ok, err)
			}
			continue
		}
		if ok || err != nil {
			t.Fatalf("unrelated encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateX86RawAliasesThroughLLVM22(t *testing.T) {
	const source = `TEXT rawaliases(SB),$0-0
	BYTE $0x66; BYTE $0x0f; BYTE $0x6b; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x76; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x66; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xf5; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xf4; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xf2; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xe2; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xd2; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0xfa; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x6a; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x69; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x62; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x61; BYTE $0xca
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xc1
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0xc1
	BYTE $0xf2; BYTE $0x0f; BYTE $0x10; BYTE $0xc1
	BYTE $0x66; BYTE $0x0f; BYTE $0xae; BYTE $0x38
	BYTE $0x66; BYTE $0x0f; BYTE $0xae; BYTE $0x30
	RET
`
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawaliases": {Name: "rawaliases", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"clflushopt $0", "clwb $0", "+clflushopt,+clwb"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw alias lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "x86-raw-aliases.ll", "x86-raw-aliases.o", ir)
		})
	}
}
