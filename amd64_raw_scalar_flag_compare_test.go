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

func TestX86RawScalarFlagCompareGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// Go 1.27 _yvcomisd has one VEX and one EVEX X/m,X row for
	// each of the four opcodes. Only EVEX register sources permit SAE.
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			regs := []int{0, 7}
			if arch == "amd64" {
				regs = append(regs, 8, 15, 16, 31)
			}
			var source strings.Builder
			source.WriteString("TEXT flagcompare(SB),4,$0-0\n")
			for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
				for _, dst := range regs {
					for _, src := range regs {
						fmt.Fprintf(&source, "%s X%d,X%d\n%s.SAE X%d,X%d\n", op, src, dst, op, src, dst)
					}
					for _, mem := range []string{"(AX)", "12(BX)(CX*4)", "-32(SI)", "8192(DI)"} {
						fmt.Fprintf(&source, "%s %s,X%d\n", op, mem, dst)
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
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
			var raw strings.Builder
			raw.WriteString("TEXT flagcompare(SB),4,$0-0\n")
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
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"flagcompare": {Name: "flagcompare", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-flag-compare.ll", "raw-flag-compare.o", ir)
			}
			t.Logf("checked %d Go encodings", len(want)-1)
		})
	}
}

func TestX86RawScalarFlagCompareEncodingAxes(t *testing.T) {
	count := 0
	for _, evex := range []bool{false, true} {
		limit, variants := 16, 4 // VEX.W/L are ignored.
		if evex {
			limit, variants = 32, 8 // EVEX.LL ignored, SAE on/off.
		}
		for _, double := range []bool{false, true} {
			for _, unordered := range []bool{false, true} {
				pp, opcode, op := 0, 0x2f, Op("VCOMISS")
				if unordered {
					opcode, op = 0x2e, "VUCOMISS"
				}
				if double {
					pp, op = 1, op[:len(op)-1]+"D"
				}
				for src := 0; src < limit; src++ {
					for dst := 0; dst < limit; dst++ {
						for variant := 0; variant < variants; variant++ {
							code := encodeRawScalarMove(evex, pp, opcode, src, 0, dst, 0, false)
							wantOp := op
							if evex {
								code[2] &^= 0x80
								if double {
									code[2] |= 0x80
								}
								code[3] |= byte(variant&3) << 5
								if variant&4 != 0 {
									code[3] |= 0x10
									wantOp += ".SAE"
								}
							} else {
								code[2] |= byte(variant&1)<<2 | byte(variant>>1)<<7
							}
							got, size, matched, err := decodedX86ScalarFlagCompareInstruction(code, 64)
							want := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", src))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", dst))}}
							if err != nil || !matched || size != len(code) || got.Op != wantOp || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x=%+v size=%d matched=%v err=%v; want %s %+v", code, got, size, matched, err, wantOp, want)
							}
							_, _, matched, err = decodedX86ScalarFlagCompareInstruction(code, 32)
							if !matched || (err != nil) != (src >= 8 || dst >= 8) {
								t.Fatalf("386 decode %x matched=%v err=%v", code, matched, err)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("tested %d encodings, want 36864", count)
	}
}

func TestX86RawScalarFlagCompareInvalidAndMemoryForms(t *testing.T) {
	for _, code := range [][]byte{nil, {0xc5}, {0xc4, 0xe2, 0x78, 0x2e, 0xc0}, {0xc5, 0xf8, 0x58, 0xc0}} {
		if _, _, matched, _ := decodedX86ScalarFlagCompareInstruction(code, 64); matched {
			t.Fatalf("matched unrelated encoding %x", code)
		}
	}
	if _, _, matched, err := decodedX86ScalarFlagCompareInstruction([]byte{0xc5, 0xf8, 0x2e, 0xc0}, 16); !matched || err == nil {
		t.Fatalf("accepted unsupported mode: matched=%v err=%v", matched, err)
	}
	for _, code := range [][]byte{
		{0xc5, 0xf8, 0x2e},
		{0xc5, 0xf8, 0x2e, 0x04}, // Missing SIB.
		{0xc5, 0xf8, 0x2e, 0x45}, // Missing displacement.
		{0xc5, 0xfa, 0x2e, 0xc0}, // Wrong pp.
		{0xc5, 0xfb, 0x2e, 0xc0},
		{0xc5, 0xf0, 0x2e, 0xc0}, // Reserved vvvv.
		{0x67, 0xc5, 0xf8, 0x2e, 0x00},
		{0x62, 0xf1, 0x78, 0x08, 0x2e, 0xc0}, // Missing fixed bit.
		{0x62, 0xf1, 0xfc, 0x08, 0x2e, 0xc0}, // SS W1.
		{0x62, 0xf1, 0x7d, 0x08, 0x2e, 0xc0}, // SD W0.
		{0x62, 0xf1, 0x7c, 0x00, 0x2e, 0xc0}, // Reserved V'.
		{0x62, 0xf1, 0x7c, 0x88, 0x2e, 0xc0}, // Zeroing.
		{0x62, 0xf1, 0x7c, 0x09, 0x2e, 0xc0}, // Masking.
		{0x62, 0xf1, 0x7c, 0x18, 0x2e, 0x00}, // SAE with memory.
	} {
		if _, _, matched, err := decodedX86ScalarFlagCompareInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x matched=%v err=%v", code, matched, err)
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		for _, double := range []bool{false, true} {
			for _, evex := range []bool{false, true} {
				code := []byte{segment.prefix, 0xc4, 0x01, 0x78, 0x2e, 0x64, 0x88, 0xf9}
				wantOff, op := int64(-7), Op("VUCOMISS")
				if double {
					code[3] |= 1
					op = "VUCOMISD"
				}
				if evex {
					code = []byte{segment.prefix, 0x62, 0x01, 0x7c, 0x08, 0x2e, 0x64, 0x88, 0xf9}
					wantOff *= 4
					if double {
						code[3] |= 0x81
						wantOff *= 2
					}
				}
				dst := Reg("X12")
				if evex {
					dst = "X28"
				}
				want := []Operand{{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: wantOff}}, {Kind: OpReg, Reg: dst}}
				got, size, matched, err := decodedX86ScalarFlagCompareInstruction(code, 64)
				if err != nil || !matched || size != len(code) || got.Op != op || !reflect.DeepEqual(got.Args, want) {
					t.Fatalf("decode %x=%+v %v; want %s %+v", code, got, err, op, want)
				}
			}
		}
	}
}

func TestX86ScalarFlagCompareGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
			for _, args := range []string{" Y0,X1", " X0,Y1", " Z0,X1", " (AX),(BX)", " X0,K1,X1", ".Z X0,X1", ".BCST (AX),X1", ".SAE (AX),X1", ".RN_SAE X0,X1"} {
				line := op + args
				source := "TEXT rejected(SB),4,$0-0\n" + line + "\nRET\n"
				dir := t.TempDir()
				path := filepath.Join(dir, "rejected.s")
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "rejected.o"), path)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				if output, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("Go %s accepted %s: %s", arch, line, output)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"rejected": {Name: "rejected", Ret: Void}}}); err == nil {
					t.Fatalf("translator accepted %s for %s", line, arch)
				}
			}
		}
	}
}

func TestX86ScalarFlagCompareRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; separate five-target object tests are required")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, reg := range []int{0, 16} {
			for _, form := range []string{"register", "memory", "sae"} {
				name := fmt.Sprintf("flagcompare%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),DI\nVMOVUPS (AX),Z%d\nVMOVUPS (BX),Z%d\nMOVL $2147483647,CX\nADDL $1,CX\n", name, reg, reg+1)
				input, suffix := fmt.Sprintf("X%d", reg+1), ""
				if form == "memory" {
					input = "(BX)"
				}
				if form == "sae" {
					suffix = ".SAE"
				}
				code := assembleX87ControlBytes(t, "amd64", fmt.Sprintf("TEXT probe(SB),4,$0-0\n%s%s %s,X%d\nRET\n", op, suffix, input, reg))
				for _, b := range code[:len(code)-1] {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
				source.WriteString("SETEQ (DI)\nSETCS 1(DI)\nSETPS 2(DI)\nSETMI 3(DI)\nSETOS 4(DI)\n")
				fmt.Fprintf(&source, "VMOVUPS Z%d,8(DI)\nVMOVUPS Z%d,72(DI)\nRET\n", reg, reg+1)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", name)
				double := 0
				if strings.HasSuffix(op, "SD") {
					double = 1
				}
				fmt.Fprintf(&checks, "if(check(%s,%d)) return %d;\n", name, double, index)
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var commandPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		commandPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	// Compare EFLAGS with native UCOMIS{S,D}. This oracle checks comparison,
	// NaN, signed-zero and register-preservation semantics, not MXCSR exception
	// delivery or SAE suppression, which require a separate floating-state audit.
	mainC := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static const uint64_t doubles[]={0,0x8000000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,0x4004000000000000ULL,0xc004000000000000ULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000000001ULL,0x7ff0000000000001ULL,1,0x7fefffffffffffffULL};
static const uint32_t singles[]={0,0x80000000,0x3f800000,0xbf800000,0x40200000,0xc0200000,0x7f800000,0xff800000,0x7fc00001,0x7f800001,1,0x7f7fffff};
static int check(void (*fn)(const void *,const void *,void *),int isDouble) {
 for(int i=0;i<12;i++) for(int j=0;j<12;j++) {
  uint8_t a[64],b[64],out[136]={0},want[5];
  for(int k=0;k<64;k++) {a[k]=(uint8_t)(k*7+91);b[k]=(uint8_t)(k*31+5);}
  if(isDouble) {
   double x,y;memcpy(a,&doubles[i],8);memcpy(b,&doubles[j],8);memcpy(&x,a,8);memcpy(&y,b,8);
   __asm__ volatile("ucomisd %6,%5; sete %0; setb %1; setp %2; sets %3; seto %4":"=qm"(want[0]),"=qm"(want[1]),"=qm"(want[2]),"=qm"(want[3]),"=qm"(want[4]):"x"(x),"x"(y):"cc");
  } else {
   float x,y;memcpy(a,&singles[i],4);memcpy(b,&singles[j],4);memcpy(&x,a,4);memcpy(&y,b,4);
   __asm__ volatile("ucomiss %6,%5; sete %0; setb %1; setp %2; sets %3; seto %4":"=qm"(want[0]),"=qm"(want[1]),"=qm"(want[2]),"=qm"(want[3]),"=qm"(want[4]):"x"(x),"x"(y):"cc");
  }
  fn(a,b,out);
  if(memcmp(out,want,5)||memcmp(out+8,a,64)||memcmp(out+72,b,64)) {
   fprintf(stderr,"flag compare mismatch double=%d i=%d j=%d\n",isDouble,i,j);return 1;
  }
 }
 return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_flag_compare", triple, ir, mainC, commandPrefix)
}
