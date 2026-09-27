package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var x86PackedCompareTestOps = []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"}

func TestX86PackedCompareGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?s)\{as: A(\w+), ytab: _yvpcmpeqb, prefix: Pavx, op: opBytes\{(.*?)\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 8 || len(rows) != len(amd64PackedIntegerCompareSpecs) {
		t.Fatalf("Go has %d family entries, grammar has %d", len(rows), len(amd64PackedIntegerCompareSpecs))
	}
	for _, row := range rows {
		spec, ok := amd64PackedIntegerCompareSpecs[Op(row[1])]
		if !ok {
			t.Fatalf("missing Go family member %s", row[1])
		}
		width := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[row[1][len(row[1])-1]]
		if spec.laneBits != width || spec.greater != strings.Contains(row[1], "GT") {
			t.Fatalf("incorrect semantics for %s: %+v", row[1], spec)
		}
		opcodes := regexp.MustCompile(`0x[0-9A-F]+`).FindAllString(row[2], -1)
		if len(opcodes) != 5 {
			t.Fatalf("Go %s has %d encodings", row[1], len(opcodes))
		}
		for _, opcode := range opcodes {
			if opcode != fmt.Sprintf("0x%X", spec.opcode) {
				t.Fatalf("Go opcode %s != spec %+v", opcode, spec)
			}
		}
		if strings.Contains(row[2], "0F38") != (spec.mapNumber == 2) || strings.Contains(row[2], "evexBcst") != (width >= 32) {
			t.Fatalf("Go map/broadcast does not match %+v: %s", spec, row[2])
		}
	}
	table := regexp.MustCompile(`(?s)var _yvpcmpeqb = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(data))
	if len(table) != 2 {
		t.Fatal("missing Go operand table")
	}
	args := regexp.MustCompile(`argList\{([^}]+)\}`).FindAllStringSubmatch(table[1], -1)
	want := []string{"Yxm, Yxr, Yxr", "Yym, Yyr, Yyr", "YxmEvex, YxrEvex, Yk", "YxmEvex, YxrEvex, Yknot0, Yk", "YymEvex, YyrEvex, Yk", "YymEvex, YyrEvex, Yknot0, Yk", "Yzm, Yzr, Yk", "Yzm, Yzr, Yknot0, Yk"}
	if len(args) != len(want) {
		t.Fatalf("Go operand rows %d != %d", len(args), len(want))
	}
	for i, arg := range args {
		if arg[1] != want[i] {
			t.Fatalf("Go row %d=%s, want %s", i, arg[1], want[i])
		}
	}
}

func TestX86RawPackedCompareEncodingAxes(t *testing.T) {
	count := 0
	for _, op := range x86PackedCompareTestOps {
		// The test's encoding map is independent of the implementation spec.
		opcode := map[string]byte{"VPCMPEQB": 0x74, "VPCMPEQW": 0x75, "VPCMPEQD": 0x76, "VPCMPEQQ": 0x29, "VPCMPGTB": 0x64, "VPCMPGTW": 0x65, "VPCMPGTD": 0x66, "VPCMPGTQ": 0x37}[op]
		mapNumber := byte(1)
		if strings.HasSuffix(op, "Q") {
			mapNumber = 2
		}
		for _, evex := range []bool{false, true} {
			limit, destLimit, widths := 16, 16, 2
			if evex {
				limit, destLimit, widths = 32, 8, 3
			}
			for width := 0; width < widths; width++ {
				for src1 := 0; src1 < limit; src1++ {
					for src2 := 0; src2 < limit; src2++ {
						for dst := 0; dst < destLimit; dst++ {
							code := encodeRawScalarMove(evex, 1, int(opcode), src2, src1, dst, 0, false)
							code[1] = code[1]&0xe0 | mapNumber
							if evex {
								// Preserve R' (K destination extension) when replacing map.
								code[1] |= 0x10
								code[2] &^= 0x80
								if mapNumber == 2 {
									code[2] |= 0x80
								}
								code[3] |= byte(width)<<5 | byte(dst)
							} else {
								code[2] |= byte(width) << 2
							}
							variants := 1
							if !evex {
								variants = 2
							}
							for variant := 0; variant < variants; variant++ {
								if variant != 0 {
									code[2] |= 0x80
								}
								got, size, matched, err := decodedX86PackedIntegerCompareInstruction(code, 64)
								prefix := []string{"X", "Y", "Z"}[width]
								args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src2))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src1))}}
								dest := Reg(fmt.Sprintf("%s%d", prefix, dst))
								if evex {
									dest = Reg(fmt.Sprintf("K%d", dst))
									if dst != 0 {
										args = append(args, Operand{Kind: OpReg, Reg: dest})
									}
								}
								args = append(args, Operand{Kind: OpReg, Reg: dest})
								if err != nil || !matched || size != len(code) || got.Op != Op(op) || !reflect.DeepEqual(got.Args, args) {
									t.Fatalf("decode %x: %+v %d %v %v; want %s %+v", code, got, size, matched, err, op, args)
								}
								_, _, matched, err = decodedX86PackedIntegerCompareInstruction(code, 32)
								if !matched || (err != nil) != (src1 >= 8 || src2 >= 8 || !evex && dst >= 8) {
									t.Fatalf("386 decode %x: matched=%v err=%v", code, matched, err)
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 327680 {
		t.Fatalf("covered %d encodings, want 327680", count)
	}
}

func TestX86RawPackedCompareInvalidAndMemoryForms(t *testing.T) {
	valid := []byte{0x62, 0xf1, 0x75, 0x0b, 0x76, 0xe0} // VPCMPEQD X0,X1,K3,K4.
	for name, mutate := range map[string]func([]byte){
		"fixed": func(b []byte) { b[2] &^= 4 }, "length": func(b []byte) { b[3] |= 0x60 },
		"zero": func(b []byte) { b[3] |= 0x80 }, "broadcast-register": func(b []byte) { b[3] |= 0x10 },
		"width": func(b []byte) { b[2] |= 0x80 }, "mask-dest-r": func(b []byte) { b[1] &^= 0x80 },
		"mask-dest-rprime": func(b []byte) { b[1] &^= 0x10 }, "prefix": func(b []byte) { b[2] &^= 3 },
	} {
		b := append([]byte(nil), valid...)
		mutate(b)
		if _, _, matched, err := decodedX86PackedIntegerCompareInstruction(b, 64); !matched || err == nil {
			t.Fatalf("accepted %s %x", name, b)
		}
	}
	for _, b := range [][]byte{valid[:5], {0x62, 0xf1, 0x75, 0x0b, 0x76, 0x04}, {0x62, 0xf1, 0x75, 0x0b, 0x76, 0x40}, append([]byte{0x67}, valid...), {0x62, 0xf1, 0x75, 0x1b, 0x74, 0x00}, {0xc5, 0xf9, 0x74}, {0xc4, 0xe1, 0x79, 0x76, 0x05, 0, 0, 0, 0}} {
		if _, _, matched, err := decodedX86PackedIntegerCompareInstruction(b, 64); !matched || err == nil {
			t.Fatalf("accepted invalid %x", b)
		}
	}
	if _, _, matched, err := decodedX86PackedIntegerCompareInstruction(valid, 16); !matched || err == nil {
		t.Fatal("accepted mode16")
	}
	for _, b := range [][]byte{nil, {0x62}, {0x90}, {0xc5, 0xf9, 0x73, 0xc0}} {
		if _, _, matched, err := decodedX86PackedIntegerCompareInstruction(b, 64); matched || err != nil {
			t.Fatalf("claimed unrelated %x", b)
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		for _, broadcast := range []bool{false, true} {
			b := []byte{segment.prefix, 0x62, 0x91, 0x75, 0x4b, 0x76, 0x64, 0x88, 0xfe}
			offset := int64(-128)
			op := Op("VPCMPEQD")
			if broadcast {
				b[4] |= 0x10
				offset = -8
				op += ".BCST"
			}
			got, size, matched, err := decodedX86PackedIntegerCompareInstruction(b, 64)
			want := MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: offset}
			if err != nil || !matched || size != len(b) || got.Op != op || !reflect.DeepEqual(got.Args[0].Mem, want) {
				t.Fatalf("decode %x=%+v: %v", b, got, err)
			}
		}
	}
	// Byte/word EVEX.W is ignored, whereas dword and qword W is fixed.
	for _, opcode := range []byte{0x74, 0x75, 0x64, 0x65} {
		b := append([]byte(nil), valid...)
		b[4] = opcode
		b[2] |= 0x80
		if _, _, matched, err := decodedX86PackedIntegerCompareInstruction(b, 64); !matched || err != nil {
			t.Fatalf("ignored W: %x %v", b, err)
		}
	}
}

func TestX86RawPackedCompareGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			last := 7
			if arch == "amd64" {
				last = 31
			}
			var source strings.Builder
			source.WriteString("TEXT compare(SB),4,$0-0\n")
			for _, op := range x86PackedCompareTestOps {
				for _, width := range []string{"X", "Y", "Z"} {
					for _, reg := range []int{0, last} {
						inputs := []string{fmt.Sprintf("%s%d", width, last-reg), "(AX)", "-7(BX)(CX*4)", "64(SI)", "8192(DI)"}
						for _, input := range inputs {
							fmt.Fprintf(&source, "%s %s,%s%d,K0\n", op, input, width, reg)
							if arch == "amd64" {
								fmt.Fprintf(&source, "%s %s,%s%d,K7,K7\n", op, input, width, reg)
							}
						}
						if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
							for _, input := range []string{"(AX)", "-8(BX)(CX*4)", "64(SI)", "8192(DI)"} {
								fmt.Fprintf(&source, "%s.BCST %s,%s%d,K7\n", op, input, width, reg)
								if arch == "amd64" {
									fmt.Fprintf(&source, "%s.BCST %s,%s%d,K1,K0\n", op, input, width, reg)
								}
							}
						}
					}
					if width != "Z" {
						for _, input := range []string{width + "0", "(AX)", "-7(BX)(CX*4)", "8192(DI)"} {
							fmt.Fprintf(&source, "%s %s,%s6,%s7\n", op, input, width, width)
						}
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
			got, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(got.Instrs) != len(want) {
				t.Fatalf("got %d instructions, want %d", len(got.Instrs), len(want))
			}
			for i, instruction := range got.Instrs {
				if instruction.Op != want[i].Op || !reflect.DeepEqual(instruction.Args, want[i].Args) {
					t.Fatalf("instruction %d: %+v, want %+v", i, instruction, want[i])
				}
			}
			var raw strings.Builder
			raw.WriteString("TEXT compare(SB),4,$0-0\n")
			for _, b := range code {
				fmt.Fprintf(&raw, "BYTE $%#x\n", b)
			}
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"compare": {Name: "compare", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "compare.ll", "compare.o", ir)
			}
			t.Logf("%s: %d actual Go encodings", arch, len(want)-1)
		})
	}
}

func TestX86PackedCompareGo386HighRegisters(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT compare(SB),4,$0-0\n")
	for _, op := range x86PackedCompareTestOps {
		for _, width := range []string{"X", "Y"} {
			for _, regs := range [][3]int{{8, 0, 1}, {0, 8, 1}, {0, 1, 8}, {15, 14, 13}} {
				fmt.Fprintf(&source, "%s %s%d,%s%d,%s%d\n", op, width, regs[0], width, regs[1], width, regs[2])
			}
		}
	}
	source.WriteString("RET\n")
	assembleX87ControlBytes(t, "386", source.String())
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"compare": {Name: "compare", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "compare-compat.ll", "compare-compat.o", ir)
	}
}

func TestX86PackedCompareGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86PackedCompareTestOps {
			lines := []string{op + " X0,Y1,Y2", op + " Z0,Z1,Z2", op + " X16,X1,X2", op + " X0,X1,(AX)", op + ".Z X0,X1,K1", op + ".SAE X0,X1,K1", op + " X0,X1,K0,K2", op + ".BCST X0,X1,K2"}
			if strings.HasSuffix(op, "B") || strings.HasSuffix(op, "W") {
				lines = append(lines, op+".BCST (AX),X1,K2")
			}
			if arch == "386" {
				lines = append(lines, op+" Z8,Z0,K1", op+" X0,X1,K1,K2")
			}
			for _, line := range lines {
				dir := t.TempDir()
				path := filepath.Join(dir, "invalid.s")
				if err := os.WriteFile(path, []byte("TEXT bad(SB),4,$0-0\n"+line+"\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("Go %s accepted %s: %s", arch, line, out)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				assertX86PackedSignedGreaterThanRejected(t, arch, triple, line)
			}
		}
	}
}

func TestX86PackedCompareMemoryAndViewsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	cross := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !cross {
		t.Skip("execution requires amd64 or Rosetta; five-target object tests remain required")
	}
	var source, decl strings.Builder
	checks := map[string]*strings.Builder{"views": {}, "memory": {}}
	sigs := map[string]FuncSig{}
	index := 0
	for _, op := range x86PackedCompareTestOps {
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		greater := 0
		if strings.Contains(op, "GT") {
			greater = 1
		}
		for w, width := range []string{"X", "Y", "Z"} {
			for mode := 0; mode < 5; mode++ { // VEX reg/mem; EVEX reg/mem/broadcast.
				if mode < 2 && w == 2 || mode == 4 && bits < 32 {
					continue
				}
				for alias := 0; alias < 2; alias++ {
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("compare%d", index)
						index++
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),DI\nVMOVUPS (AX),Z0\n", name)
						input := "(BX)"
						if mode == 0 || mode == 2 {
							source.WriteString("VMOVUPS (BX),Z1\n")
							input = width + "1"
						}
						dst := width + "0"
						if alias == 1 {
							dst = width + "1"
						}
						if mode < 2 {
							emitX86GoEncodedTestInstruction(t, &source, fmt.Sprintf("%s %s,%s0,%s", op, input, width, dst), raw)
							fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\n", alias, alias, alias)
						} else {
							dst = "K7"
							if alias == 1 {
								dst = "K1"
							}
							suffix := ""
							if mode == 4 {
								suffix = ".BCST"
							}
							source.WriteString("KMOVQ mask+24(FP),K1\n")
							emitX86GoEncodedTestInstruction(t, &source, fmt.Sprintf("%s%s %s,%s0,K1,%s", op, suffix, input, width, dst), raw)
							fmt.Fprintf(&source, "KMOVQ %s,(DI)\nVMOVUPS Z0,16(DI)\n", dst)
						}
						source.WriteString("RET\n")
						sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1}}}}
						fmt.Fprintf(&decl, "extern void %s(const void*,const void*,void*,uint64_t);\n", name)
						kind := "views"
						if mode >= 2 {
							kind = "memory"
						}
						fmt.Fprintf(checks[kind], "if(check(%s,%d,%d,%d,%d)) {fprintf(stderr,\"%s failed\\n\");return 1;}\n", name, 16<<w, bits/8, greater, mode, name)
					}
				}
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if cross {
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
` + x86TestGuardPagesC + decl.String() + `
static uint64_t lane(const uint8_t *p,int bytes) {uint64_t v=0;memcpy(&v,p,bytes);return v;}
static int cmp(const uint8_t *a,const uint8_t *b,int bytes,int gt) {
 uint64_t x=lane(a,bytes),y=lane(b,bytes),sign=UINT64_C(1)<<(bytes*8-1);
 return gt ? (x^sign)>(y^sign) : x==y;
}
static int check(void(*fn)(const void*,const void*,void*,uint64_t),int width,int bytes,int gt,int mode) {
 for(int n=0;n<64;n++) {
  uint8_t ab[65],bb[65],out[128],want[112]={0};uint8_t *a=ab+1,*b=bb+1;
  for(int i=0;i<64;i++) {a[i]=(uint8_t)(i*37+n*19);b[i]=(n%3==0)?a[i]:(uint8_t)(i*13-n*7);}
  uint64_t mask=(n==0)?0:(n==1)?UINT64_C(1)<<63:(n==2)?UINT64_MAX:UINT64_C(0x5a5a01239876cdef)>>(n%32),expected=0;
  int lanes=width/bytes;
  if(mode<2) {
   for(int i=0;i<lanes;i++) memset(want+i*bytes,cmp(a+i*bytes,b+i*bytes,bytes,gt)?255:0,bytes);
   memcpy(want+64,want,32);memcpy(want+96,want,16);
   fn(a,b,out,mask);
   if(memcmp(out,want,112)) {fprintf(stderr,"vector compare mismatch mode=%d width=%d bytes=%d n=%d\n",mode,width,bytes,n);return 1;}
  } else {
   uint64_t active=lanes==64?mask:mask&((UINT64_C(1)<<lanes)-1);
   for(int i=0;i<lanes;i++) if((active>>i)&1) expected|=(uint64_t)cmp(a+i*bytes,b+(mode==4?0:i*bytes),bytes,gt)<<i;
   fn(a,(mode>=3 && !active)?NULL:b,out,mask);
   if(lane(out,8)!=expected || memcmp(out+16,a,64)) {fprintf(stderr,"mask compare mismatch mode=%d width=%d bytes=%d n=%d\n",mode,width,bytes,n);return 1;}
  }
 }
 if(mode>=3) {
  // Only the enabled source lanes are accessible. This detects an eager
  // full-width read even when the mask is nonzero, not just NULL/zero mask.
  uint8_t a[64],out[128];memset(a,0,64);
  int lanes=width/bytes;
  for(int enabled=1;enabled<=lanes;enabled++) {
   int readable=(mode==4)?bytes:enabled*bytes;
   uint8_t *b=guard+page-readable;memset(b,0,(size_t)readable);
   uint64_t mask=enabled==64?UINT64_MAX:(UINT64_C(1)<<enabled)-1;
   fn(a,b,out,mask);
   if(lane(out,8)!=(gt?0:mask) || memcmp(out+16,a,64))return 1;
  }
 }
 return 0;
}
`
	for _, kind := range []string{"views", "memory"} {
		t.Run(kind, func(t *testing.T) {
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_compare_"+kind, triple, ir, mainC+"int main(void) {\nif(setup_guard())return 2;\n"+checks[kind].String()+"return free_guard();\n}\n", prefix)
		})
	}
}

func TestX86RawPackedCompare386Mask(t *testing.T) {
	// Raw instructions have architectural operands, not Go's textual 386
	// frontend three-operand limit. Both source vectors are physical X0-7.
	code := assembleX87ControlBytes(t, "amd64", "TEXT compare(SB),4,$0-0\nVPCMPEQB (AX),X1,K2,K3\nRET\n")
	var source strings.Builder
	source.WriteString("TEXT compare(SB),4,$0-0\n")
	for _, b := range code {
		fmt.Fprintf(&source, "BYTE $%#x\n", b)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"compare": {Name: "compare", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "masked-386.ll", "masked-386.o", ir)
	}
}

func TestX86PackedCompareFrameSpanValidation(t *testing.T) {
	for _, op := range x86PackedCompareTestOps {
		for w, width := range []string{"X", "Y", "Z"} {
			for _, masked := range []bool{false, true} {
				mask := ""
				if masked {
					mask = "K1,"
				}
				file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT frame(SB),4,$0-8\n%s a+0(FP),%s0,%sK7\nRET\n", op, width, mask))
				if err != nil {
					t.Fatal(err)
				}
				for _, valid := range []bool{false, true} {
					chunks := 1
					if valid {
						chunks = (16 << w) / 8
					}
					sig := FuncSig{Name: "frame", Ret: Void}
					for i := 0; i < chunks; i++ {
						sig.Args = append(sig.Args, I64)
						sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i * 8), Type: I64, Index: i, Field: -1})
					}
					ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"frame": sig}})
					if valid && err != nil || !valid && (err == nil || !strings.Contains(err.Error(), "undeclared FP vector slot")) {
						t.Fatalf("%s %s masked=%v valid=%v: %v", op, width, masked, valid, err)
					}
					if valid && strings.Contains(ir, " = call <") && strings.Contains(ir, "@llvm.masked.load.") {
						t.Fatalf("FP slots must not be loaded through a contiguous native pointer")
					}
				}
			}
		}
	}
}
