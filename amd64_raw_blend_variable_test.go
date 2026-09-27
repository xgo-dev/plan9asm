package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var x86VariableBlendTestFamilies = []struct {
	legacy, vector string
	bits           int
	legacyCode     byte
	vectorCode     byte
}{
	{"BLENDVPS", "VBLENDVPS", 32, 0x14, 0x4a},
	{"BLENDVPD", "VBLENDVPD", 64, 0x15, 0x4b},
	{"PBLENDVB", "VPBLENDVB", 8, 0x10, 0x4c},
}

func TestX86VariableBlendGrammarMatchesGoEncoder(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	vector, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, grammar := range []struct {
		text, table string
		operands    []string
	}{
		{string(legacy), "yblendvpd", []string{"Yxr0, Yxm, Yxr"}},
		{string(vector), "_yvblendvpd", []string{"Yxr, Yxm, Yxr, Yxr", "Yyr, Yym, Yyr, Yyr"}},
	} {
		pattern := `(?s)var ` + grammar.table + ` = \[\]ytab\{(.*?)\n\}`
		rows := regexp.MustCompile(pattern).FindStringSubmatch(grammar.text)
		if len(rows) != 2 || strings.Count(rows[1], "argList{") != len(grammar.operands) {
			t.Fatalf("Go %s operand grammar changed", grammar.table)
		}
		for _, operands := range grammar.operands {
			if !strings.Contains(rows[1], "argList{"+operands+"}") {
				t.Fatalf("Go %s is missing %s", grammar.table, operands)
			}
		}
	}
	for _, family := range x86VariableBlendTestFamilies {
		for _, vex := range []bool{false, true} {
			op, opcode := family.legacy, family.legacyCode
			if vex {
				op, opcode = family.vector, family.vectorCode
			}
			spec, ok := amd64VariableBlendSpecs[Op(op)]
			if !ok || spec.laneBits != family.bits || spec.vector != vex || spec.opcode != int(opcode) {
				t.Fatalf("incorrect typed spec for %s: %+v", op, spec)
			}
			if !vex {
				row := fmt.Sprintf("{A%s, yblendvpd, Pq4, opBytes{0x%02x}}", op, opcode)
				if !strings.Contains(string(legacy), row) {
					t.Fatalf("Go %s opcode changed", op)
				}
				continue
			}
			pattern := `(?s)\{as: A` + op + `, ytab: (\w+), prefix: Pavx, op: opBytes\{(.*?)\}\}`
			rows := regexp.MustCompile(pattern).FindAllStringSubmatch(string(vector), -1)
			if len(rows) != 1 || rows[0][1] != "_yvblendvpd" {
				t.Fatalf("Go %s opcode grammar changed", op)
			}
			entries := strings.Split(strings.TrimSpace(rows[0][2]), "\n")
			if len(entries) != 2 {
				t.Fatalf("Go %s must have exactly X/Y forms", op)
			}
			for i, width := range []int{128, 256} {
				want := fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F3A | vexW0, 0x%02X,", width, opcode)
				if strings.TrimSpace(entries[i]) != want {
					t.Fatalf("Go %s encoding = %s, want %s", op, entries[i], want)
				}
			}
		}
	}
	if len(amd64VariableBlendSpecs) != 6 {
		t.Fatal("variable-blend specs must cover all six Go mnemonics")
	}
}

func TestX86RawVariableBlendEncodingFields(t *testing.T) {
	for _, family := range x86VariableBlendTestFamilies {
		for _, length := range []byte{0, 1} {
			for selector := 0; selector < 256; selector++ {
				code := []byte{0xc4, 0xe3, 0x69 | length<<2, family.vectorCode, 0xd9, byte(selector)}
				for _, mode := range []int{32, 64} {
					got, size, matched, err := decodedX86VariableBlendInstruction(code, mode)
					mask := selector >> 4
					if mode == 32 {
						mask &= 7
					}
					prefix := "X"
					if length != 0 {
						prefix = "Y"
					}
					want := []Operand{
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, mask))},
						{Kind: OpReg, Reg: Reg(prefix + "1")},
						{Kind: OpReg, Reg: Reg(prefix + "2")},
						{Kind: OpReg, Reg: Reg(prefix + "3")},
					}
					if err != nil || !matched || size != len(code) || got.Op != Op(family.vector) || !reflect.DeepEqual(got.Args, want) {
						t.Fatalf("decode %x mode=%d: %+v %v, want %+v", code, mode, got, err, want)
					}
				}
			}
		}
	}
}

func TestX86RawVariableBlend386IgnoredRegisterBits(t *testing.T) {
	// Intel XED's XMM/YMM_N_32 and XMM/YMM_B_32 tables ignore the high
	// vvvv and B selectors. R/X must still distinguish VEX from legacy LES.
	for _, family := range x86VariableBlendTestFamilies {
		for _, length := range []byte{0, 1} {
			for _, modRM := range []byte{0xd9, 0x1b} {
				canonical := []byte{0xc4, 0xe3, 0x69 | length<<2, family.vectorCode, modRM, 0x70}
				want, _, matched, err := decodedX86VariableBlendInstruction(canonical, 32)
				if !matched || err != nil {
					t.Fatalf("canonical %x: %v", canonical, err)
				}
				for bits := 0; bits < 4; bits++ {
					code := append([]byte(nil), canonical...)
					if bits&1 != 0 {
						code[1] &^= 0x20
					}
					if bits&2 != 0 {
						code[2] &^= 0x40
					}
					code[5] = 0xff
					got, size, matched, err := decodedX86VariableBlendInstruction(code, 32)
					if !matched || err != nil || size != len(code) || !reflect.DeepEqual(got.Args, want.Args) {
						t.Fatalf("386 ignored fields %x: %+v %v, want %+v", code, got, err, want)
					}
				}
			}
		}
	}
}

func TestX86RawVariableBlendInvalidAndMemoryForms(t *testing.T) {
	for _, family := range x86VariableBlendTestFamilies {
		code := []byte{0xc4, 0xe3, 0x69, family.vectorCode, 0xd9, 0x00}
		for _, mutate := range []func([]byte) []byte{
			func(b []byte) []byte { b[2] |= 0x80; return b }, // W1 is reserved.
			func(b []byte) []byte { b[2] &^= 3; return b },   // No 66 prefix.
			func(b []byte) []byte { return b[:4] },           // Missing ModRM.
			func(b []byte) []byte { return b[:5] },           // Missing selector.
			func(b []byte) []byte { b[4] = 0x04; return b[:5] },
			func(b []byte) []byte { b[4] = 0x80; return b[:5] },
			func(b []byte) []byte { return append([]byte{0x67}, b...) },
			func(b []byte) []byte { return []byte{0x62, 0xf3, 0x6d, 0x08, b[3], b[4], b[5]} },
		} {
			invalid := mutate(append([]byte(nil), code...))
			if _, _, matched, err := decodedX86VariableBlendInstruction(invalid, 64); !matched || err == nil {
				t.Fatalf("accepted reserved/truncated encoding %x", invalid)
			}
		}
		if _, _, matched, err := decodedX86VariableBlendInstruction(code, 16); !matched || err == nil {
			t.Fatal("accepted unsupported mode")
		}
		for _, segment := range []struct {
			prefix byte
			reg    Reg
		}{{0x64, FS}, {0x65, GS}} {
			memory := []byte{segment.prefix, 0xc4, 0x03, 0x69, family.vectorCode, 0x64, 0x88, 0xf9, 0xf7}
			got, size, matched, err := decodedX86VariableBlendInstruction(memory, 64)
			want := []Operand{
				{Kind: OpReg, Reg: "X15"},
				{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: -7}},
				{Kind: OpReg, Reg: "X2"},
				{Kind: OpReg, Reg: "X12"},
			}
			if err != nil || !matched || size != len(memory) || !reflect.DeepEqual(got.Args, want) {
				t.Fatalf("decode %x: %+v %v, want %+v", memory, got, err, want)
			}
			if _, _, matched, err := decodedX86VariableBlendInstruction(memory, 32); !matched || err == nil {
				t.Fatal("accepted legacy LES as a 32-bit VEX instruction")
			}
		}
		rip := []byte{0xc4, 0xe3, 0x69, family.vectorCode, 0x05, 0, 0, 0, 0, 0}
		if _, _, matched, err := decodedX86VariableBlendInstruction(rip, 64); !matched || err == nil {
			t.Fatal("accepted source-layout-unsafe RIP addressing")
		}
		if _, size, matched, err := decodedX86VariableBlendInstruction(rip, 32); !matched || err != nil || size != len(rip) {
			t.Fatalf("absolute 32-bit addressing: matched=%t size=%d err=%v", matched, size, err)
		}
	}
	for _, code := range [][]byte{nil, {0xc4}, {0xc4, 0xe2, 0x69, 0x4b, 0xc0, 0}, {0xc4, 0xe3, 0x69, 0x4d, 0xc0, 0}} {
		if _, _, matched, _ := decodedX86VariableBlendInstruction(code, 64); matched {
			t.Fatalf("matched unrelated instruction %x", code)
		}
	}
}

func TestX86RawVariableBlendSourceLocalRIPData(t *testing.T) {
	for _, family := range x86VariableBlendTestFamilies {
		for vectorLength, width := range []int{16, 32} {
			code := []byte{
				0xc4, 0xe3, byte(0x69 | vectorLength<<2), family.vectorCode,
				0x05, 0x01, 0, 0, 0, 0x70, 0xc3,
			}
			for value := 0; value < width; value++ {
				code = append(code, byte(value))
			}
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "variable blend RIP", map[string]bool{})
			if err != nil {
				t.Fatalf("%s width %d: %v", family.vector, width, err)
			}
			if len(decoded) != 2 || decoded[0].Op != Op(family.vector) ||
				len(decoded[0].x86RIPLiteralData) != width ||
				decoded[0].Args[1].Kind != OpSym {
				t.Fatalf("%s width %d: %#v", family.vector, width, decoded)
			}
		}
	}
}

func TestX86VariableBlendGoRejectedForms(t *testing.T) {
	for _, family := range x86VariableBlendTestFamilies {
		for _, form := range []struct {
			op   string
			args []string
		}{
			{family.legacy, []string{" X0,X1", " X1,X2,X3", " X0,(AX),(BX)", " X0,Y1,X2", " X0,X1,X16", ".Z X0,X1,X2"}},
			{family.vector, []string{" X0,X1,X2", " (AX),X1,X2,X3", " X0,X1,(AX),X3", " X0,X1,X2,(AX)",
				" X0,Y1,X2,X3", " X0,X1,Y2,X3", " X0,X1,X2,Y3", " Z0,Z1,Z2,Z3", " X16,X1,X2,X3",
				" X0,X16,X2,X3", " X0,X1,X16,X3", " X0,X1,X2,X16", ".Z X0,X1,X2,X3", ".BCST X0,(AX),X2,X3", ".SAE X0,X1,X2,X3"}},
		} {
			for _, args := range form.args {
				line := form.op + args
				requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),4,$0-0\n"+line+"\nRET\n", false)
				assertX86VariableBlendRejected(t, "amd64", "x86_64-unknown-linux-gnu", line)
			}
		}
	}
}

func TestX86RawVariableBlendGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, family := range x86VariableBlendTestFamilies {
			for _, width := range []int{0, 16, 32} {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, family.vector, width), func(t *testing.T) {
					limit := 16
					if arch == "386" {
						limit = 8
					}
					prefix, op := "X", family.legacy
					if width != 0 {
						op = family.vector
					}
					if width == 32 {
						prefix = "Y"
					}
					memories := []string{"(AX)", "-7(BP)(CX*4)", "8192(SP)"}
					if arch == "amd64" {
						memories = append(memories, "(R8)", "-7(R13)(R15*8)")
					}
					var source strings.Builder
					source.WriteString("TEXT blend(SB),4,$0-0\n")
					for reg := 0; reg < limit; reg++ {
						if width == 0 {
							fmt.Fprintf(&source, "%s X0,X%d,X2\n%s X0,X1,X%d\n", op, reg, op, reg)
						} else {
							// Vary the four register fields independently, not as a
							// redundant Cartesian product of the same grammar.
							for field := 0; field < 4; field++ {
								args := []string{prefix + "0", prefix + "1", prefix + "2", prefix + "3"}
								args[field] = fmt.Sprintf("%s%d", prefix, reg)
								fmt.Fprintf(&source, "%s %s\n", op, strings.Join(args, ","))
							}
						}
						for _, memory := range memories {
							if width == 0 {
								fmt.Fprintf(&source, "%s X0,%s,X%d\n", op, memory, reg)
							} else {
								fmt.Fprintf(&source, "%s %s%d,%s,%s2,%s%d\n", op, prefix, reg, memory, prefix, prefix, reg)
							}
						}
					}
					source.WriteString("RET\n")
					encoderArch := arch
					if arch == "386" && width != 0 {
						// Go's 386 parser rejects four operands before the shared
						// VEX encoder. The same low-register/address encodings
						// are valid on i386; decode and compile them there too.
						requireX86GoAssemblerResult(t, arch, "TEXT bad(SB),4,$0-0\n"+op+" X0,X1,X2,X3\nRET\n", false)
						encoderArch = "amd64"
					}
					code := assembleX87ControlBytes(t, encoderArch, source.String())
					decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
					if err != nil {
						t.Fatal(err)
					}
					named, err := Parse(ArchAMD64, source.String())
					if err != nil {
						t.Fatal(err)
					}
					want := named.Funcs[0].Instrs[1:]
					if len(decoded.Instrs) != len(want) {
						t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
					}
					for i, got := range decoded.Instrs {
						if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
							t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
						}
					}
					var raw strings.Builder
					raw.WriteString("TEXT blend(SB),4,$0-0\n")
					for _, b := range code {
						fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
					}
					file, err := Parse(ArchAMD64, raw.String())
					if err != nil {
						t.Fatal(err)
					}
					triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
					if arch == "386" {
						triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
					}
					for _, triple := range triples {
						ir, err := Translate(file, Options{
							Goarch: arch, TargetTriple: triple,
							Sigs: map[string]FuncSig{"blend": {Name: "blend", Ret: Void}},
						})
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "raw-blend.ll", "raw-blend.o", ir)
					}
					t.Logf("checked %d actual Go encodings", len(want)-1)
				})
			}
		}
	}
}
