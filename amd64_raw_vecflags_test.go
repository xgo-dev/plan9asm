package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawVectorTestCompleteGo127EncodingFamily(t *testing.T) {
	if len(x86RawVectorTestOpcodes) != len(amd64VectorTestSpecs)-1 {
		t.Fatalf("raw VEX vector-test opcode table has %d entries, named grammar has %d VEX entries", len(x86RawVectorTestOpcodes), len(amd64VectorTestSpecs)-1)
	}
	for _, op := range x86RawVectorTestOpcodes {
		if spec, ok := amd64VectorTestSpecs[op]; !ok || !spec.vector {
			t.Fatalf("raw opcode %s has no matching named VEX grammar", op)
		}
	}

	type form struct {
		name string
		op   Op
		code []byte
		src  Operand
		dst  Reg
	}
	var forms []form
	for _, spec := range []struct {
		name   Op
		opcode byte
		legacy bool
	}{
		{"PTEST", 0x17, true},
		{"VPTEST", 0x17, false},
		{"VTESTPS", 0x0e, false},
		{"VTESTPD", 0x0f, false},
	} {
		for _, width := range []struct {
			name string
			vex3 byte
		}{
			{"X", 0x79},
			{"Y", 0x7d},
		} {
			if spec.legacy && width.name == "Y" {
				continue
			}
			for _, source := range []struct {
				name  string
				modRM byte
				value Operand
			}{
				{"register", 0xc1, Operand{Kind: OpReg, Reg: Reg(width.name + "1")}},
				{"memory", 0x08, Operand{Kind: OpMem, Mem: MemRef{Base: AX}}},
			} {
				code := []byte{0xc4, 0xe2, width.vex3, spec.opcode, source.modRM}
				if spec.legacy {
					code = []byte{0x66, 0x0f, 0x38, spec.opcode, source.modRM}
				}
				dest := Reg(width.name + "0")
				if source.name == "memory" {
					dest = Reg(width.name + "1")
				}
				forms = append(forms, form{
					name: string(spec.name) + "/" + width.name + "/" + source.name,
					op:   spec.name, code: code, src: source.value, dst: dest,
				})
			}
		}
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, form := range forms {
			t.Run(goarch+"/"+form.name, func(t *testing.T) {
				fn := Func{}
				for _, value := range form.code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != form.op || len(got.Instrs[0].Args) != 2 {
					t.Fatalf("decoded %#x as %#v, want %s", form.code, got.Instrs, form.op)
				}
				ins := got.Instrs[0]
				if ins.Args[0].Kind != form.src.Kind || ins.Args[0].Reg != form.src.Reg || ins.Args[0].Mem != form.src.Mem || ins.Args[1].Reg != form.dst {
					t.Fatalf("decoded %#x operands as %#v, want %#v, %s", form.code, ins.Args, form.src, form.dst)
				}
			})
		}
	}
}

func TestX86RawVectorTestRejectsReservedEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"missing-66", []byte{0xc4, 0xe2, 0x78, 0x17, 0xc1}, 64},
		{"nonzero-vvvv", []byte{0xc4, 0xe2, 0x71, 0x17, 0xc1}, 64},
		{"address-override", []byte{0x67, 0xc4, 0xe2, 0x79, 0x17, 0x08}, 64},
		{"missing-modrm", []byte{0xc4, 0xe2, 0x79, 0x17}, 64},
		{"extended-386", []byte{0xc4, 0x62, 0x79, 0x17, 0xc1}, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86VEXVectorTestInstruction(tc.code, tc.mode); !recognized || err == nil {
				t.Fatalf("reserved encoding %#x: recognized=%v error=%v", tc.code, recognized, err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		want Operand
	}{
		{"W-ignored", []byte{0xc4, 0xe2, 0xf9, 0x17, 0xc1}, Operand{Kind: OpReg, Reg: "X1"}},
		{"SIB-memory", []byte{0xc4, 0xe2, 0x7d, 0x0f, 0x44, 0x88, 0x20}, Operand{Kind: OpMem, Mem: MemRef{Base: AX, Index: CX, Scale: 4, Off: 32}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, length, recognized, err := decodedX86VEXVectorTestInstruction(tc.code, 64)
			if !recognized || err != nil || length != len(tc.code) {
				t.Fatalf("encoding %#x: instruction=%+v length=%d recognized=%v error=%v", tc.code, got, length, recognized, err)
			}
			if !reflect.DeepEqual(got.Args[0], tc.want) {
				t.Fatalf("source = %+v, want %+v", got.Args[0], tc.want)
			}
		})
	}
}

func TestX86RawVectorTestCompilesEveryForm(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawvectortest(SB),NOSPLIT,$0-0\n")
			for _, spec := range []struct {
				opcode byte
				legacy bool
			}{
				{0x17, true}, {0x17, false}, {0x0e, false}, {0x0f, false},
			} {
				for _, width := range []byte{0x79, 0x7d} {
					if spec.legacy && width == 0x7d {
						continue
					}
					for _, modRM := range []byte{0xc1, 0x08} {
						code := []byte{0xc4, 0xe2, width, spec.opcode, modRM}
						if spec.legacy {
							code = []byte{0x66, 0x0f, 0x38, spec.opcode, modRM}
						}
						for _, value := range code {
							fmt.Fprintf(&source, "\tBYTE $%d\n", value)
						}
						source.WriteString("\tNOP\n")
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawvectortest": {Name: "rawvectortest", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vector-test.ll", "raw-vector-test.o", ir)
		})
	}
}
