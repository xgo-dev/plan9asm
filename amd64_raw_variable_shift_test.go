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

var x86VariableShiftTestOps = []string{"VPSLLVW", "VPSLLVD", "VPSLLVQ", "VPSRLVW", "VPSRLVD", "VPSRLVQ", "VPSRAVW", "VPSRAVD", "VPSRAVQ"}

func TestX86VariableShiftGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?s)\{as: A(VPS(?:LL|RL|RA)V[WDQ]), ytab: (\w+), prefix: Pavx, op: opBytes\{(.*?)\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 9 || len(rows) != len(amd64PerLaneVariableShiftSpecs) {
		t.Fatalf("Go entries=%d, grammar=%d", len(rows), len(amd64PerLaneVariableShiftSpecs))
	}
	for _, row := range rows {
		spec, ok := amd64PerLaneVariableShiftSpecs[row[1]]
		if !ok {
			t.Fatalf("missing %s", row[1])
		}
		bits := map[byte]int{'W': 16, 'D': 32, 'Q': 64}[row[1][len(row[1])-1]]
		operation := "shl"
		if strings.HasPrefix(row[1], "VPSRL") {
			operation = "lshr"
		}
		if strings.HasPrefix(row[1], "VPSRA") {
			operation = "ashr"
		}
		if spec.laneBits != bits || spec.operation != operation || spec.arithmetic != (operation == "ashr") {
			t.Fatalf("Go semantics differ for %s: %+v", row[1], spec)
		}
		vex := bits != 16 && row[1] != "VPSRAVQ"
		if spec.vex != vex || (row[2] == "_yvandnpd") != vex || strings.Contains(row[3], "| vex128") != vex || strings.Contains(row[3], "evexBcst") != (bits != 16) {
			t.Fatalf("Go encoding surface changed for %s: %s", row[1], row[3])
		}
		for _, opcode := range regexp.MustCompile(`0x[0-9A-F]+`).FindAllString(row[3], -1) {
			if opcode != fmt.Sprintf("0x%X", spec.opcode) {
				t.Fatalf("Go opcode %s != spec %+v", opcode, spec)
			}
		}
	}
}

func TestX86RawVariableShiftGoEncoderForms(t *testing.T) {
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
			source.WriteString("TEXT shifts(SB),4,$0-0\n")
			for _, op := range x86VariableShiftTestOps {
				for _, width := range []string{"X", "Y", "Z"} {
					for _, reg := range []int{0, last} {
						for _, input := range []string{fmt.Sprintf("%s%d", width, last-reg), "(AX)", "-7(BX)(CX*4)", "64(SI)", "8192(DI)"} {
							fmt.Fprintf(&source, "%s %s,%s%d,%s%d\n", op, input, width, reg, width, last-reg)
							if arch == "amd64" {
								fmt.Fprintf(&source, "%s %s,%s%d,K1,%s%d\n%s.Z %s,%s%d,K7,%s%d\n", op, input, width, reg, width, last-reg, op, input, width, reg, width, last-reg)
							}
						}
						if !strings.HasSuffix(op, "W") {
							for _, input := range []string{"-8(BX)(CX*4)", "64(SI)"} {
								fmt.Fprintf(&source, "%s.BCST %s,%s%d,%s%d\n", op, input, width, reg, width, last-reg)
								if arch == "amd64" {
									fmt.Fprintf(&source, "%s.BCST %s,%s%d,K1,%s%d\n%s.BCST.Z %s,%s%d,K7,%s%d\n", op, input, width, reg, width, last-reg, op, input, width, reg, width, last-reg)
								}
							}
						}
					}
					// Low registers force the VEX row where available, even when the
					// high-register rows above necessarily select EVEX on amd64.
					if width != "Z" {
						fmt.Fprintf(&source, "%s %s0,%s1,%s2\n%s (AX),%s1,%s2\n", op, width, width, width, op, width, width)
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
			raw.WriteString("TEXT shifts(SB),4,$0-0\n")
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
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "shifts.ll", "shifts.o", ir)
			}
			t.Logf("%s: %d actual Go encodings", arch, len(want)-1)
		})
	}
}

func TestX86VariableShiftGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86VariableShiftTestOps {
			lines := []string{op + " X0,Y1,Y2", op + " X0,X1,(AX)", op + ".Z X0,X1,X2", op + ".SAE X0,X1,X2", op + " X0,X1,K0,X2", op + ".BCST X0,X1,X2", op + ".Z.BCST (AX),X1,K1,X2", op + " $1,X1,X2"}
			if strings.HasSuffix(op, "W") {
				lines = append(lines, op+".BCST (AX),X1,X2")
			}
			if arch == "386" {
				lines = append(lines, op+" Z8,Z0,Z1", op+" X0,X1,K1,X2")
			}
			for _, line := range lines {
				// Go 1.20 emitted reserved zeroing/K0 for maskless .Z. Preserve
				// the strict named/raw rejection even for that historical encoder.
				{
					dir := t.TempDir()
					path := filepath.Join(dir, "invalid.s")
					if err := os.WriteFile(path, []byte("TEXT bad(SB),4,$0-0\n"+line+"\nRET\n"), 0600); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
					cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
					out, err := cmd.CombinedOutput()
					historicalZero := strings.HasPrefix(runtime.Version(), "go1.20") && strings.Contains(line, ".Z X0")
					if historicalZero && err != nil || !historicalZero && err == nil {
						t.Fatalf("Go %s unexpected acceptance for %s (historical zeroing=%v): %v %s", arch, line, historicalZero, err, out)
					}
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				assertX86PerLaneVariableShiftRejected(t, arch, triple, line)
			}
		}
	}
}

func TestX86RawVariableShiftEncodingAxes(t *testing.T) {
	count := 0
	for _, op := range x86VariableShiftTestOps {
		bits := map[byte]int{'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		opcode := map[string]int{"VPSLLVW": 0x12, "VPSLLVD": 0x47, "VPSLLVQ": 0x47, "VPSRLVW": 0x10, "VPSRLVD": 0x45, "VPSRLVQ": 0x45, "VPSRAVW": 0x11, "VPSRAVD": 0x46, "VPSRAVQ": 0x46}[op]
		for _, evex := range []bool{false, true} {
			if !evex && (bits == 16 || op == "VPSRAVQ") {
				continue
			}
			limit, widths := 16, 2
			if evex {
				limit, widths = 32, 3
			}
			for width := 0; width < widths; width++ {
				for src1 := 0; src1 < limit; src1++ {
					for src2 := 0; src2 < limit; src2++ {
						for dst := 0; dst < limit; dst++ {
							mask := 0
							zero := false
							if evex {
								mask = (dst + src1 + src2) % 8
								zero = mask != 0 && src2&1 != 0
							}
							code := encodeRawScalarMove(evex, 1, 0, src2, src1, dst, mask, zero)
							code[len(code)-2] = byte(opcode)
							code[1] = code[1]&0xf0 | 2
							code[2] &^= 0x80
							if bits != 32 {
								code[2] |= 0x80
							}
							if evex {
								code[3] |= byte(width) << 5
							} else {
								code[2] |= byte(width) << 2
							}
							got, size, matched, err := decodedX86PerLaneVariableShiftInstruction(code, 64)
							prefix := []string{"X", "Y", "Z"}[width]
							wantOp := Op(op)
							if zero {
								wantOp += ".Z"
							}
							args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src2))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src1))}}
							if mask != 0 {
								args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
							}
							args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, dst))})
							if err != nil || !matched || size != len(code) || got.Op != wantOp || !reflect.DeepEqual(got.Args, args) {
								t.Fatalf("decode %x: %+v %d %v %v; want %s %+v", code, got, size, matched, err, wantOp, args)
							}
							_, _, matched, err = decodedX86PerLaneVariableShiftInstruction(code, 32)
							if !matched || (err != nil) != (src1 >= 8 || src2 >= 8 || dst >= 8) {
								t.Fatalf("386 decode %x matched=%v err=%v", code, matched, err)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 925696 {
		t.Fatalf("covered %d encodings, want 925696", count)
	}
}

func TestX86RawVariableShiftInvalidAndMemoryForms(t *testing.T) {
	valid := []byte{0x62, 0xf2, 0xf5, 0x0b, 0x47, 0xe0}
	for name, mutate := range map[string]func([]byte){"fixed": func(b []byte) { b[2] &^= 4 }, "length": func(b []byte) { b[3] |= 0x60 }, "zero-mask": func(b []byte) { b[3] = 0x88 }, "broadcast-register": func(b []byte) { b[3] |= 0x10 }, "prefix": func(b []byte) { b[2] &^= 3 }} {
		b := append([]byte(nil), valid...)
		mutate(b)
		if _, _, matched, err := decodedX86PerLaneVariableShiftInstruction(b, 64); !matched || err == nil {
			t.Fatalf("accepted %s %x", name, b)
		}
	}
	for _, b := range [][]byte{valid[:5], {0x62, 0xf2, 0xf5, 0x0b, 0x47, 0x04}, {0x62, 0xf2, 0xf5, 0x0b, 0x47, 0x40}, append([]byte{0x67}, valid...), {0x62, 0xf2, 0xf5, 0x1b, 0x12, 0x00}, {0x62, 0xf2, 0x75, 0x0b, 0x12, 0xc0}, {0xc4, 0xe2, 0xf9, 0x46, 0xc0}, {0xc4, 0xe2, 0xf9, 0x12, 0xc0}, {0xc4, 0xe2, 0xf9, 0x47, 0x05, 0, 0, 0, 0}} {
		if _, _, matched, err := decodedX86PerLaneVariableShiftInstruction(b, 64); !matched || err == nil {
			t.Fatalf("accepted invalid %x", b)
		}
	}
	if _, _, matched, err := decodedX86PerLaneVariableShiftInstruction(valid, 16); !matched || err == nil {
		t.Fatal("accepted mode16")
	}
	for _, b := range [][]byte{nil, {0x62}, {0x90}, {0xc4, 0xe1, 0xf9, 0x47, 0xc0}, {0xc4, 0xe2, 0xf9, 0x48, 0xc0}} {
		if _, _, matched, err := decodedX86PerLaneVariableShiftInstruction(b, 64); matched || err != nil {
			t.Fatalf("claimed unrelated %x", b)
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		for _, broadcast := range []bool{false, true} {
			b := []byte{segment.prefix, 0x62, 0x92, 0xf5, 0xcb, 0x47, 0x64, 0x88, 0xfe}
			offset := int64(-128)
			op := Op("VPSLLVQ.Z")
			if broadcast {
				b[4] |= 0x10
				offset = -16
				op = "VPSLLVQ.BCST.Z"
			}
			got, size, matched, err := decodedX86PerLaneVariableShiftInstruction(b, 64)
			want := MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: offset}
			if err != nil || !matched || size != len(b) || got.Op != op || !reflect.DeepEqual(got.Args[0].Mem, want) {
				t.Fatalf("decode %x=%+v: %v", b, got, err)
			}
		}
	}
}

func TestX86RawVariableShift386MaskedObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT shifts(SB),4,$0-0\n")
	for _, op := range x86VariableShiftTestOps {
		for _, width := range []string{"X", "Y", "Z"} {
			for _, input := range []string{width + "0", "(AX)"} {
				for _, suffix := range []string{"", ".Z"} {
					emitX86GoEncodedTestInstruction(t, &source, fmt.Sprintf("%s%s %s,%s1,K7,%s2", op, suffix, input, width, width), true)
				}
			}
			if !strings.HasSuffix(op, "W") {
				emitX86GoEncodedTestInstruction(t, &source, fmt.Sprintf("%s.BCST.Z (AX),%s1,K7,%s2", op, width, width), true)
			}
		}
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "masked-shifts-386.ll", "masked-shifts-386.o", ir)
	}
}

func TestX86VariableShiftMemoryAndViewsRuntime(t *testing.T) {
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
	for _, op := range x86VariableShiftTestOps {
		bits := map[byte]int{'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		operation := 0
		if strings.HasPrefix(op, "VPSRL") {
			operation = 1
		}
		if strings.HasPrefix(op, "VPSRA") {
			operation = 2
		}
		for w, width := range []string{"X", "Y", "Z"} {
			for mode := 0; mode < 5; mode++ { // reg/mem unmasked, reg/mem masked, broadcast masked.
				if mode == 4 && bits == 16 {
					continue
				}
				for _, zero := range []bool{false, true} {
					if zero && mode < 2 {
						continue
					}
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("shift%d", index)
						index++
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ data+0(FP),AX\nMOVQ counts+8(FP),BX\nMOVQ out+16(FP),DI\nVMOVUPS (AX),Z0\n", name)
						input := "(BX)"
						if mode == 0 || mode == 2 {
							source.WriteString("VMOVUPS (BX),Z1\n")
							input = width + "1"
						} else if raw {
							source.WriteString("VMOVUPS (AX),Z1\n")
						}
						suffix, mask := "", ""
						if mode == 4 {
							suffix = ".BCST"
						}
						if zero {
							suffix += ".Z"
						}
						if mode >= 2 {
							source.WriteString("KMOVQ mask+24(FP),K1\n")
							mask = "K1,"
						}
						dst := 0
						if raw {
							dst = 1
						}
						emitX86GoEncodedTestInstruction(t, &source, fmt.Sprintf("%s%s %s,%s0,%s%s%d", op, suffix, input, width, mask, width, dst), raw)
						fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\nRET\n", dst, dst, dst)
						sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1}}}}
						fmt.Fprintf(&decl, "extern void %s(const void*,const void*,void*,uint64_t);\n", name)
						kind := "views"
						if mode >= 2 {
							kind = "memory"
						}
						z := 0
						if zero {
							z = 1
						}
						oldCounts := 0
						if raw && (mode == 0 || mode == 2) {
							oldCounts = 1
						}
						fmt.Fprintf(checks[kind], "if(check(%s,%d,%d,%d,%d,%d,%d)){fprintf(stderr,\"%s failed\\n\");return 1;}\n", name, 16<<w, bits/8, operation, mode, z, oldCounts, name)
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
static uint64_t lane(const uint8_t *p,int bytes){uint64_t v=0;memcpy(&v,p,bytes);return v;}
static uint64_t shifted(uint64_t value,uint64_t count,int bits,int op){
 uint64_t limit=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1,sign=UINT64_C(1)<<(bits-1);
 if(count>=(uint64_t)bits)return op==2 && (value&sign)?limit:0;
 if(op==0)return (value<<count)&limit;
 uint64_t result=value>>count;
 if(op==2 && (value&sign) && count)result|=limit^(limit>>count);
 return result;
}
static int check(void(*fn)(const void*,const void*,void*,uint64_t),int width,int bytes,int op,int mode,int zero,int oldCounts){
 for(int n=0;n<96;n++){
  uint8_t ab[65],bb[65],out[112],want[112]={0};uint8_t *a=ab+1,*b=bb+1;
  uint64_t counts[]={0,1,(uint64_t)bytes*8-1,(uint64_t)bytes*8,(uint64_t)bytes*8+1,UINT64_MAX,UINT64_C(1)<<(bytes*8-1)};
  for(int i=0;i<64;i++)a[i]=(uint8_t)(i*31+n*17);
  for(int i=0;i<64/bytes;i++){uint64_t count=counts[(n+i)%7];memcpy(b+i*bytes,&count,bytes);}
  int lanes=width/bytes;uint64_t mask=n==0?0:n==1?UINT64_C(1)<<63:n==2?UINT64_MAX:UINT64_C(0x5a5a01239876cdef)>>(n%32);
  uint64_t active=mask&((UINT64_C(1)<<lanes)-1);
  for(int i=0;i<lanes;i++){
   uint64_t value=lane(a+i*bytes,bytes),count=lane(b+(mode==4?0:i*bytes),bytes);
   uint64_t result=mode<2 || ((mask>>i)&1)?shifted(value,count,bytes*8,op):zero?0:oldCounts?lane(b+i*bytes,bytes):value;
   memcpy(want+i*bytes,&result,bytes);
  }
  memcpy(want+64,want,32);memcpy(want+96,want,16);
  fn(a,mode>=3 && !active?NULL:b,out,mask);
  if(memcmp(out,want,112)){fprintf(stderr,"width=%d bytes=%d op=%d mode=%d zero=%d n=%d\n",width,bytes,op,mode,zero,n);return 1;}
 }
 if(mode>=3){
  int lanes=width/bytes;
  for(int enabled=1;enabled<=lanes;enabled++){
   uint8_t a[64],out[112],want[112]={0};memset(a,0xff,64);
   int readable=mode==4?bytes:enabled*bytes;uint8_t *b=guard+page-readable;
   memset(b,0,(size_t)readable);
   uint64_t mask=(UINT64_C(1)<<enabled)-1;
   for(int i=0;i<lanes;i++)if(i<enabled || !zero)memset(want+i*bytes,255,(size_t)bytes);
   memcpy(want+64,want,32);memcpy(want+96,want,16);
   fn(a,b,out,mask);if(memcmp(out,want,112))return 1;
  }
 }
 return 0;
}
`
	for _, kind := range []string{"views", "memory"} {
		t.Run(kind, func(t *testing.T) {
			compileAndRunRuntimeTestForTarget(t, llc, clang, "variable_shift_"+kind, triple, ir, mainC+"int main(void){\nif(setup_guard())return 2;\n"+checks[kind].String()+"return free_guard();}\n", prefix)
		})
	}
}
