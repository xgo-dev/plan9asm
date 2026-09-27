package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86RawParallelBitsGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			regs := []string{"AX", "SP", "DI"}
			if arch == "amd64" {
				regs = append(regs, "R8", "R15")
			}
			var source strings.Builder
			source.WriteString("TEXT parallelbits(SB),4,$0-0\n")
			// Go _yandnl: one register/memory mask, source GP, destination GP
			// row, independently encoded by each of PDEPL/Q and PEXTL/Q.
			for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
				for _, dst := range regs {
					for _, mask := range []string{dst, "(BX)", "-7(BP)(CX*4)", "8192(SI)"} {
						fmt.Fprintf(&source, "%s %s,%s,%s\n", op, mask, dst, dst)
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
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
				t.Fatalf("got %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if arch == "386" && strings.HasSuffix(string(want[i].Op), "Q") {
					want[i].Op = Op(strings.TrimSuffix(string(want[i].Op), "Q") + "L")
				}
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
			var raw strings.Builder
			raw.WriteString("TEXT parallelbits(SB),4,$0-0\n")
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
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"parallelbits": {Name: "parallelbits", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-parallel-bits.ll", "raw-parallel-bits.o", ir)
			}
			t.Logf("checked %d Go encodings", len(want)-1)
		})
	}
}

func TestX86RawParallelBitsEncodingAxes(t *testing.T) {
	count := 0
	for _, deposit := range []bool{false, true} {
		for _, wide := range []bool{false, true} {
			pp, op := 2, "PEXT"
			if deposit {
				pp, op = 3, "PDEP"
			}
			for mask := 0; mask < 16; mask++ {
				for src := 0; src < 16; src++ {
					for dst := 0; dst < 16; dst++ {
						code := encodeRawScalarMove(false, pp, 0xf5, mask, src, dst, 0, false)
						code[1] = code[1]&0xe0 | 2
						if wide {
							code[2] |= 0x80
						}
						for _, mode := range []int{32, 64} {
							got, n, matched, err := decodedX86ParallelBitsInstruction(code, mode)
							if mode == 32 && (mask >= 8 || src >= 8 || dst >= 8) {
								if !matched || err == nil {
									t.Fatalf("386 accepted %x", code)
								}
								continue
							}
							width := "L"
							if wide && mode == 64 {
								width = "Q"
							}
							mr, _ := decodedX86GeneralRegister(mask)
							sr, _ := decodedX86GeneralRegister(src)
							dr, _ := decodedX86GeneralRegister(dst)
							want := []Operand{{Kind: OpReg, Reg: mr}, {Kind: OpReg, Reg: sr}, {Kind: OpReg, Reg: dr}}
							if err != nil || !matched || n != len(code) || got.Op != Op(op+width) || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x mode=%d: %+v %v, want %s %+v", code, mode, got, err, op+width, want)
							}
						}
						count++
					}
				}
			}
		}
	}
	if count != 16384 {
		t.Fatalf("covered %d encodings", count)
	}
}

func TestX86RawParallelBitsInvalidAndSegmentForms(t *testing.T) {
	for _, code := range [][]byte{
		{0xc4, 0xe2, 0x7a, 0xf5}, {0xc4, 0xe2, 0x7a, 0xf5, 0x04}, {0xc4, 0xe2, 0x7a, 0xf5, 0x45},
		{0xc4, 0xe2, 0x7e, 0xf5, 0xc0},       // Reserved L=1.
		{0x62, 0xf2, 0x7e, 0x08, 0xf5, 0xc0}, // Not a Go EVEX family.
		{0x67, 0xc4, 0xe2, 0x7a, 0xf5, 0x00},
	} {
		if _, _, matched, err := decodedX86ParallelBitsInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x", code)
		}
	}
	if _, _, matched, err := decodedX86ParallelBitsInstruction([]byte{0xc4, 0xe2, 0x7a, 0xf5, 0xc0}, 16); !matched || err == nil {
		t.Fatal("accepted invalid mode")
	}
	for _, code := range [][]byte{nil, {0xc4}, {0xc4, 0xe2, 0x78, 0xf5, 0xc0}, {0xc4, 0xe1, 0x7a, 0xf5, 0xc0}} {
		if _, _, matched, _ := decodedX86ParallelBitsInstruction(code, 64); matched {
			t.Fatalf("matched unrelated encoding %x", code)
		}
	}
	for _, seg := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		code := []byte{seg.prefix, 0xc4, 0x02, 0xb2, 0xf5, 0x64, 0x88, 0xf9}
		got, n, matched, err := decodedX86ParallelBitsInstruction(code, 64)
		want := []Operand{{Kind: OpMem, Mem: MemRef{Segment: seg.reg, Base: "R8", Index: "R9", Scale: 4, Off: -7}}, {Kind: OpReg, Reg: "R9"}, {Kind: OpReg, Reg: "R12"}}
		if err != nil || !matched || n != len(code) || got.Op != "PEXTQ" || !reflect.DeepEqual(got.Args, want) {
			t.Fatalf("decode %x=%+v %v, want %+v", code, got, err, want)
		}
	}
}

func TestX86ParallelBitsGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			for _, args := range []string{" AX,BX", " X0,AX,BX", " AX,X0,BX", " AX,BX,X0", " AX,(BX),CX", " AX,BX,(CX)", " $1,BX,CX", ".Z AX,BX,CX", ".BCST (AX),BX,CX"} {
				source := "TEXT invalid(SB),4,$0-0\n" + op + args + "\nRET\n"
				dir := t.TempDir()
				path := filepath.Join(dir, "invalid.s")
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				if output, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("Go %s accepted %s%s: %s", arch, op, args, output)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}}); err == nil {
					t.Fatalf("translator accepted %s%s on %s", op, args, arch)
				}
			}
		}
	}
}

func TestX86ParallelBitsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; separate five-target object tests are required")
	}
	var source, decl, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		for _, memory := range []bool{false, true} {
			for dst := 8; dst <= 10; dst++ {
				name := fmt.Sprintf("parallelbits%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ value+0(FP),R8\nMOVQ mask+8(FP),SI\nMOVQ (SI),R9\nMOVQ out+16(FP),DI\nMOVQ $-1,R10\nMOVL $2147483647,CX\nADDL $1,CX\n", name)
				mask := "R9"
				if memory {
					mask = "(SI)"
				}
				code := assembleX87ControlBytes(t, "amd64", fmt.Sprintf("TEXT probe(SB),4,$0-0\n%s %s,R8,R%d\nRET\n", op, mask, dst))
				for _, b := range code[:len(code)-1] {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
				fmt.Fprintf(&source, "MOVQ R%d,(DI)\nSETCS 8(DI)\nSETEQ 9(DI)\nSETPS 10(DI)\nSETMI 11(DI)\nSETOS 12(DI)\nRET\n", dst)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}}}}
				fmt.Fprintf(&decl, "extern void %s(uint64_t,const void *,void *);\n", name)
				bits, deposit := 32, 0
				if strings.HasSuffix(op, "Q") {
					bits = 64
				}
				if strings.HasPrefix(op, "PDEP") {
					deposit = 1
				}
				fmt.Fprintf(&checks, "if(check(%s,%d,%d)) return %d;\n", name, bits, deposit, index)
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + decl.String() + `
static uint64_t reference(uint64_t value,uint64_t mask,int bits,int deposit) {
 if(bits==32) {value=(uint32_t)value;mask=(uint32_t)mask;}
 uint64_t result=0,cursor=1;
 while(mask) {uint64_t low=mask&(-mask);if(deposit ? (value&cursor)!=0 : (value&low)!=0) result|=deposit?low:cursor;mask&=mask-1;cursor<<=1;}
 return result;
}
static int check(void (*fn)(uint64_t,const void *,void *),int bits,int deposit) {
 uint64_t state=0x9e3779b97f4a7c15ULL;
 for(int i=0;i<256;i++) {
  state^=state<<13;state^=state>>7;state^=state<<17;uint64_t value=state;
  state^=state<<13;state^=state>>7;state^=state<<17;uint64_t mask=state;
  if(i==0)mask=0;if(i==1)mask=~(uint64_t)0;if(i>=2&&i<66)mask=(uint64_t)1<<(i-2);
  uint8_t storage[9],out[16]={0};memcpy(storage+1,&mask,8);
  fn(value,storage+1,out);uint64_t actual;memcpy(&actual,out,8);
  const uint8_t flags[5]={0,0,1,1,1};
  if(actual!=reference(value,mask,bits,deposit)||memcmp(out+8,flags,5)) {fprintf(stderr,"parallel bits mismatch bits=%d deposit=%d case=%d\n",bits,deposit,i);return 1;}
 }
 return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "parallel_bits", triple, ir, mainC, prefix)
}

func TestX86ParallelBits386IgnoresW(t *testing.T) {
	// Intel XED hsw-bmi-vex-isa.xed.txt has unconstrained W in not64
	// mode: both Go-accepted L and Q spellings access only a 32-bit mask.
	for _, op := range []string{"PDEPQ", "PEXTQ"} {
		source := "TEXT width386(SB),4,$0-0\n" + op + " (AX),BX,CX\nRET\n"
		assembleX87ControlBytes(t, "386", source)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{"width386": {Name: "width386", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ir, "lshr i64") || !strings.Contains(ir, "lshr i32") || !strings.Contains(ir, "load i32, ptr") {
			t.Fatalf("386 %s failed to normalize width", op)
		}
	}
}
