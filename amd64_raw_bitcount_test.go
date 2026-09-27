package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86RawBitCountCompleteGo127EncodingFamily(t *testing.T) {
	type form struct {
		name string
		op   Op
		code []byte
		mem  bool
	}
	var forms []form
	for _, family := range []struct {
		name   string
		opcode byte
	}{
		{"LZCNT", 0xbd},
		{"TZCNT", 0xbc},
	} {
		for _, width := range []struct {
			suffix string
			prefix []byte
		}{
			{"W", []byte{0x66, 0xf3}},
			{"L", []byte{0xf3}},
			{"Q", []byte{0xf3, 0x48}},
		} {
			for _, source := range []struct {
				name  string
				modRM byte
				mem   bool
			}{
				{"register", 0xc1, false},
				{"memory", 0x08, true},
			} {
				code := append(append([]byte{}, width.prefix...), 0x0f, family.opcode, source.modRM)
				forms = append(forms, form{
					name: family.name + width.suffix + "/" + source.name,
					op:   Op(family.name + width.suffix), code: code, mem: source.mem,
				})
			}
		}
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, form := range forms {
			if goarch == "386" && strings.Contains(form.name, "Q/") {
				continue
			}
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
					t.Fatalf("decoded %#x as %#v, want one %s", form.code, got.Instrs, form.op)
				}
				ins := got.Instrs[0]
				wantDestination := AX
				if form.mem {
					wantDestination = CX
				}
				if ins.Args[1].Kind != OpReg || ins.Args[1].Reg != wantDestination {
					t.Fatalf("decoded destination %#v, want %s", ins.Args[1], wantDestination)
				}
				if form.mem {
					if ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != AX {
						t.Fatalf("decoded memory source %#v, want (AX)", ins.Args[0])
					}
				} else if ins.Args[0].Kind != OpReg || ins.Args[0].Reg != CX {
					t.Fatalf("decoded register source %#v, want CX", ins.Args[0])
				}
			})
		}
	}
}

func TestX86RawBitCountExtendedRegisters(t *testing.T) {
	for _, family := range []struct {
		opcode byte
		op     Op
	}{
		{0xbc, "TZCNTQ"},
		{0xbd, "LZCNTQ"},
	} {
		for _, test := range []struct {
			name   string
			code   []byte
			source Operand
			dest   Reg
		}{
			{
				name:   "extended register",
				code:   []byte{0xf3, 0x4d, 0x0f, family.opcode, 0xc1},
				source: Operand{Kind: OpReg, Reg: "R9"}, dest: "R8",
			},
			{
				name:   "extended memory base",
				code:   []byte{0xf3, 0x49, 0x0f, family.opcode, 0x08},
				source: Operand{Kind: OpMem, Mem: MemRef{Base: "R8"}}, dest: CX,
			},
		} {
			t.Run(string(family.op)+"/"+test.name, func(t *testing.T) {
				fn := Func{}
				for _, value := range test.code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != family.op || len(got.Instrs[0].Args) != 2 {
					t.Fatalf("decoded %#x as %#v, want %s", test.code, got.Instrs, family.op)
				}
				ins := got.Instrs[0]
				if ins.Args[0].Kind != test.source.Kind || ins.Args[0].Reg != test.source.Reg || ins.Args[0].Mem != test.source.Mem || ins.Args[1].Reg != test.dest {
					t.Fatalf("decoded %#x operands as %#v, want %#v, %s", test.code, ins.Args, test.source, test.dest)
				}
			})
		}
	}
}

func TestX86RawBitCountCompilesAllForms(t *testing.T) {
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
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawbitcount(SB),NOSPLIT,$0-0\n")
			for _, opcode := range []byte{0xbc, 0xbd} {
				for _, prefix := range [][]byte{{0x66, 0xf3}, {0xf3}, {0xf3, 0x48}} {
					if target.goarch == "386" && len(prefix) == 2 && prefix[1] == 0x48 {
						continue
					}
					for _, modRM := range []byte{0xc1, 0x08} {
						for _, value := range append(append([]byte{}, prefix...), 0x0f, opcode, modRM) {
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
				Sigs: map[string]FuncSig{"rawbitcount": {Name: "rawbitcount", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-bitcount.ll", "raw-bitcount.o", ir)
		})
	}
}

func TestX86RawBitCountRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution requires amd64; required amd64 CI covers this host-inapplicable test")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawbitcountsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x12340000, AX
	BYTE $0x66; BYTE $0xf3; BYTE $0x0f; BYTE $0xbc; BYTE $0xc0 // TZCNTW AX, AX
	MOVQ AX, 0(DI)
	SETCS 8(DI)
	SETEQ 9(DI)
	MOVQ $0x1122334480000000, AX
	BYTE $0xf3; BYTE $0x0f; BYTE $0xbd; BYTE $0xc0 // LZCNTL AX, AX
	MOVQ AX, 16(DI)
	SETCS 24(DI)
	SETEQ 25(DI)
	MOVQ $0, AX
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xbc; BYTE $0xc0 // TZCNTQ AX, AX
	MOVQ AX, 32(DI)
	SETCS 40(DI)
	SETEQ 41(DI)
	MOVQ $0x100, 48(DI)
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xbd; BYTE $0x4f; BYTE $0x30 // LZCNTQ 48(DI), CX
	MOVQ CX, 56(DI)
	SETCS 64(DI)
	SETEQ 65(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"rawbitcountsemantics": {
				Name: "rawbitcountsemantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawbitcountsemantics(uint8_t *);
int main(void) {
  uint8_t out[72] = {0};
  rawbitcountsemantics(out);
  if (*(uint64_t *)(out+0) != UINT64_C(0x12340010)) return 10;
  if (out[8] != 1 || out[9] != 0) return 11;
  if (*(uint64_t *)(out+16) != 0) return 12;
  if (out[24] != 0 || out[25] != 1) return 13;
  if (*(uint64_t *)(out+32) != 64) return 14;
  if (out[40] != 1 || out[41] != 0) return 15;
  if (*(uint64_t *)(out+56) != 55) return 16;
  if (out[64] != 0 || out[65] != 0) return 17;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_bitcount_semantics", triple, ir, mainC, runPrefix)
}
