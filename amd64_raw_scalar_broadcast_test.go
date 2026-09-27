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

func TestX86RawScalarBroadcastGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// Go 1.27 _yvbroadcastss has 2 VEX + 6 EVEX rows;
	// _yvbroadcastsd has 1 VEX + 4 EVEX rows (no X destination).
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT broadcasts(SB),4,$0-0\n")
			regs := []int{0, 7}
			if arch == "amd64" {
				regs = append(regs, 15, 16, 31)
			}
			for _, op := range []string{"VBROADCASTSS", "VBROADCASTSD"} {
				for _, width := range []string{"X", "Y", "Z"} {
					if op == "VBROADCASTSD" && width == "X" {
						continue
					}
					for _, reg := range regs {
						for _, input := range []string{fmt.Sprintf("X%d", reg), "(AX)", "16(BX)(CX*4)", "-64(SI)"} {
							for _, form := range []struct{ suffix, mask string }{{"", ""}, {"", "K1,"}, {".Z", "K7,"}} {
								fmt.Fprintf(&source, "%s%s %s,%s%s%d\n", op, form.suffix, input, form.mask, width, reg)
							}
						}
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
			raw.WriteString("TEXT broadcasts(SB),4,$0-0\n")
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
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"broadcasts": {Name: "broadcasts", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-scalar-broadcast.ll", "raw-scalar-broadcast.o", ir)
			}
		})
	}
}

func TestX86RawScalarBroadcastEncodingAxes(t *testing.T) {
	count := 0
	for _, evex := range []bool{false, true} {
		limit, widths := 16, 2
		if evex {
			limit, widths = 32, 3
		}
		for _, double := range []bool{false, true} {
			for width := 0; width < widths; width++ {
				if double && width == 0 {
					continue
				}
				for src := 0; src < limit; src++ {
					for dst := 0; dst < limit; dst++ {
						mask, zero := 0, false
						if evex {
							mask = (src + dst) & 7
							zero = mask != 0 && dst&1 != 0
						}
						code := encodeRawScalarMove(evex, 1, 0x10, src, 0, dst, mask, zero)
						op, opcode := Op("VBROADCASTSS"), byte(0x18)
						if double {
							op, opcode = "VBROADCASTSD", 0x19
						}
						if evex {
							code[1] = code[1]&0xf0 | 2
							code[3] |= byte(width) << 5
							code[4] = opcode
							if double {
								code[2] |= 0x80
							}
						} else {
							code[1] = code[1]&0xe0 | 2
							code[2] |= byte(width) << 2
							code[3] = opcode
						}
						got, size, ok, err := decodedX86ScalarBroadcastInstruction(code, 64)
						if zero {
							op += ".Z"
						}
						args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", src))}}
						if mask != 0 {
							args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
						}
						args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", []string{"X", "Y", "Z"}[width], dst))})
						if err != nil || !ok || size != len(code) || got.Op != op || !reflect.DeepEqual(got.Args, args) {
							t.Fatalf("decode %x=%+v size=%d ok=%v err=%v; want %s %+v", code, got, size, ok, err, op, args)
						}
						count++
					}
				}
			}
		}
	}
	if count != 5888 {
		t.Fatalf("tested %d encodings, want 5888", count)
	}
}

func TestX86RawScalarBroadcastRejectsReservedEncodings(t *testing.T) {
	for _, code := range [][]byte{
		{0xc4, 0xe2, 0x79, 0x18},       // Missing ModRM.
		{0xc4, 0xe2, 0x79, 0x18, 0x04}, // Missing SIB.
		{0xc4, 0xe2, 0x79, 0x18, 0x45}, // Missing displacement.
		{0xc4, 0xe2, 0x79, 0x19, 0xc0}, // SD has no 128-bit output.
		{0xc4, 0xe2, 0xf9, 0x18, 0xc0}, // VEX.W must be zero.
		{0xc4, 0xe2, 0x71, 0x18, 0xc0}, // Reserved vvvv.
		{0x67, 0xc4, 0xe2, 0x79, 0x18, 0x00},
		{0x62, 0xf2, 0x79, 0x08, 0x18, 0xc0}, // Missing EVEX fixed bit.
		{0x62, 0xf2, 0xfd, 0x08, 0x18, 0xc0}, // SS W1.
		{0x62, 0xf2, 0x7d, 0x28, 0x19, 0xc0}, // SD W0.
		{0x62, 0xf2, 0x7d, 0x00, 0x18, 0xc0}, // Reserved V'.
		{0x62, 0xf2, 0x7d, 0x68, 0x18, 0xc0}, // Reserved LL.
		{0x62, 0xf2, 0x7d, 0x18, 0x18, 0xc0}, // Reserved EVEX.b.
		{0x62, 0xf2, 0x7d, 0x88, 0x18, 0xc0}, // Zeroing with K0.
	} {
		if _, _, matched, err := decodedX86ScalarBroadcastInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x matched=%v err=%v", code, matched, err)
		}
	}
}

func TestX86ScalarBroadcastGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VBROADCASTSS", "VBROADCASTSD"} {
			instructions := []string{op + " AX,Y0", op + " Y0,Y1", op + " X0,AX", op + " X0,K0,Y0", op + ".Z X0,Y0", op + ".SAE X0,Y0", op + " X0,K1,(AX)"}
			if op == "VBROADCASTSD" {
				instructions = append(instructions, op+" X0,X1")
			}
			if arch == "386" {
				instructions = append(instructions, op+" X0,Z8")
			}
			for _, instruction := range instructions {
				source := "TEXT invalidbroadcast(SB),4,$0-0\n" + instruction + "\nRET\n"
				dir := t.TempDir()
				name := filepath.Join(dir, "invalid.s")
				if err := os.WriteFile(name, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), name)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				if output, err := cmd.CombinedOutput(); err == nil {
					if instruction != op+".Z X0,Y0" || goToolchainAtLeast(runtime.Version(), 1, 27) {
						t.Fatalf("Go %s accepted %s; repair the oracle expectation: %s", arch, instruction, output)
					}
					// Old Go accepts maskless .Z but emits a reserved EVEX
					// zeroing/K0 encoding. Verify both that exact historical
					// mismatch and the raw decoder's rejection, then require
					// the named translator's rejection below too.
					code := assembleX87ControlBytes(t, arch, source)
					mode := 64
					if arch == "386" {
						mode = 32
					}
					p, prefixMatched := decodeX86RawVectorEncoding(code)
					_, _, matched, err := decodedX86ScalarBroadcastInstruction(code, mode)
					if !prefixMatched || !p.evex || !p.zero || p.mask != 0 || !matched || err == nil || !strings.Contains(err.Error(), "zeroing requires a nonzero mask") {
						t.Fatalf("historical maskless .Z did not emit rejected EVEX zeroing/K0: %x %v", code, err)
					}
					t.Logf("%s/%s emits reserved zeroing/K0; both translators reject it", runtime.Version(), arch)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					continue
				}
				_, err = Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"invalidbroadcast": {Name: "invalidbroadcast", Ret: Void}}})
				if err == nil {
					t.Errorf("%s accepted Go-rejected %s", arch, instruction)
				}
			}
		}
	}
}

func TestX86ScalarBroadcastMemoryAndViewsRuntime(t *testing.T) {
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
	for _, spec := range []struct {
		op   string
		bits int
	}{{"VBROADCASTSS", 32}, {"VBROADCASTSD", 64}} {
		for width, reg := range []string{"X0", "Y0", "Z0"} {
			if spec.bits == 64 && width == 0 {
				continue
			}
			for form := 0; form < 6; form++ {
				name := fmt.Sprintf("broadcast%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ old+0(FP),BX\nMOVQ mem+8(FP),AX\nMOVQ out+16(FP),DI\nMOVQ mask+24(FP),CX\nKMOVQ CX,K7\nVMOVUPS (BX),Z0\n", name)
				input := "(AX)"
				if form >= 3 {
					source.WriteString("VMOVUPS (AX),X1\n")
					input = "X1"
				}
				op, mask := spec.op, ""
				if form%3 != 0 {
					mask = "K7,"
				}
				if form%3 == 2 {
					op += ".Z"
				}
				fmt.Fprintf(&source, "%s %s,%s%s\nVMOVUPS Z0,(DI)\nVMOVUPS Y0,64(DI)\nVMOVUPS X0,96(DI)\nRET\n", op, input, mask, reg)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1}}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *,uint64_t);\n", name)
				faultcheck := 0
				if form < 3 && form%3 != 0 {
					faultcheck = 1
				}
				fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d,%d)) return %d;\n", name, 16<<width, spec.bits/8, form%3, faultcheck, index)
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
` + declarations.String() + `
static int check(void (*fn)(const void *,const void *,void *,uint64_t),int bytes,int lane,int form,int faultcheck) {
  uint64_t masks[]={0,1,2,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX,UINT64_C(1)<<63};
  for(int m=0;m<6;m++) {
    _Alignas(64) uint8_t old[64],mem[16],out[112];
    for(int i=0;i<64;i++) old[i]=(uint8_t)(197-i*3);
    for(int i=0;i<16;i++) mem[i]=(uint8_t)(17+i*7);
    uint64_t active=masks[m]&((UINT64_C(1)<<(bytes/lane))-1);
    fn(old,faultcheck && !active ? 0 : mem,out,masks[m]);
    for(int view=0;view<3;view++) for(int i=0;i<(64>>view);i++) {
      int enabled=form==0 || ((masks[m]>>(i/lane))&1);
      uint8_t want=i>=bytes ? 0 : enabled ? mem[i%lane] : form==2 ? 0 : old[i];
      int offset=view==0 ? 0 : view==1 ? 64 : 96;
      if(out[offset+i]!=want) {fprintf(stderr,"broadcast mismatch bytes=%d lane=%d form=%d mask=%d view=%d byte=%d\n",bytes,lane,form,m,view,i);return 1;}
    }
  }
  return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_broadcast", triple, ir, mainC, prefix)
}
