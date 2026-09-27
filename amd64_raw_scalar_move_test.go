package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestDecodeX86RawScalarMoveCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT scalarmoves(SB),4,$0-0\n")
	var lines []string
	for _, op := range []string{"VMOVSS", "VMOVSD"} {
		for _, registers := range [][]int{{0, 1, 7}, {8, 9, 15}, {16, 23, 31}} {
			for _, mask := range []string{"", "K1, ", "K7, "} {
				for _, suffix := range []string{"", ".Z"} {
					if mask == "" && suffix != "" {
						continue
					}
					for _, memory := range []string{"(AX)", "-8(R11)(R9*4)", "1024(R11)"} {
						lines = append(lines, fmt.Sprintf("%s%s %s, %sX%d", op, suffix, memory, mask, registers[2]))
						if suffix == "" {
							lines = append(lines, fmt.Sprintf("%s X%d, %s%s", op, registers[0], mask, memory))
						}
					}
					lines = append(lines, fmt.Sprintf("%s%s X%d, X%d, %sX%d", op, suffix, registers[0], registers[1], mask, registers[2]))
				}
			}
		}
	}
	source.WriteString(strings.Join(lines, "\n") + "\nRET\n")
	code := assembleX87ControlBytes(t, "amd64", source.String())
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	want := file.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
	}
	for i, ins := range decoded.Instrs {
		if ins.Op != want[i].Op || !reflect.DeepEqual(ins.Args, want[i].Args) {
			t.Fatalf("instruction %d decoded %+v, want %+v", i, ins, want[i])
		}
	}
	var raw strings.Builder
	raw.WriteString("TEXT scalarmoves(SB),4,$0-0\n")
	for _, b := range code {
		fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
	}
	rawFile, err := Parse(ArchAMD64, raw.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		ir, err := Translate(rawFile, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"scalarmoves": {Name: "scalarmoves", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "raw-scalar-moves.ll", "raw-scalar-moves.o", ir)
	}
}

func TestTranslate386VectorScalarMoveCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT moves386(SB),4,$0-0\n")
	for _, op := range []string{"VMOVSS", "VMOVSD"} {
		for _, x := range []string{"X1", "X15", "X31"} {
			fmt.Fprintf(&source, "%s (AX),%s\n%s %s,(BX)\n%s %s,X2,X3\n%s (AX),K7,%s\n%s.Z (AX),K7,%s\n%s %s,K7,(BX)\n", op, x, op, x, op, x, op, x, op, x, op, x)
		}
	}
	source.WriteString("RET\n")
	requireX86GoAssemblerResult(t, "386", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"moves386": {Name: "moves386", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "scalar-moves386.ll", "scalar-moves386.o", ir)
	}
	// Raw 32-bit encodings use the architectural X0-X7 range; named Go
	// compatibility rows above also expose high EVEX register classes.
	rawSource := strings.NewReplacer("X15", "X1", "X31", "X1").Replace(source.String())
	code := assembleX87ControlBytes(t, "386", rawSource)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "386")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Parse(ArchAMD64, rawSource)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("386 raw instruction count=%d, want %d", len(decoded.Instrs), len(want))
	}
	for i, got := range decoded.Instrs {
		if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
			t.Fatalf("386 instruction %d=%+v, want %+v", i, got, want[i])
		}
	}
}

// Unlike Go's canonical encoder, exercise both equivalent register directions
// and every independent R/R'/B/X/vvvv/V' bit, including EVEX masking.
func encodeRawScalarMove(evex bool, pp, opcode, low, upper, dst, mask int, zero bool) []byte {
	reg, rm := dst, low
	if opcode == 0x11 {
		reg, rm = low, dst
	}
	modrm := byte(0xc0 | (reg&7)<<3 | rm&7)
	if !evex {
		return []byte{0xc4, byte((^reg>>3&1)<<7 | 0x40 | (^rm>>3&1)<<5 | 1), byte((^upper&15)<<3 | pp), byte(opcode), modrm}
	}
	p0 := byte((^reg>>3&1)<<7 | (^rm>>4&1)<<6 | (^rm>>3&1)<<5 | (^reg>>4&1)<<4 | 1)
	p1 := byte((^upper&15)<<3 | 4 | pp)
	if pp == 3 {
		p1 |= 0x80
	}
	p2 := byte((^upper>>4&1)<<3 | mask)
	if zero {
		p2 |= 0x80
	}
	return []byte{0x62, p0, p1, p2, byte(opcode), modrm}
}

func TestDecodedX86RawScalarMoveRegisterEncodings(t *testing.T) {
	count := 0
	for _, evex := range []bool{false, true} {
		limit := 16
		if evex {
			limit = 32
		}
		for pp, op := range map[int]Op{2: "VMOVSS", 3: "VMOVSD"} {
			for _, opcode := range []int{0x10, 0x11} {
				for low := 0; low < limit; low++ {
					for upper := 0; upper < limit; upper++ {
						for dst := 0; dst < limit; dst++ {
							mask, zero := 0, false
							if evex {
								mask = (low + upper + dst) & 7
								zero = mask != 0 && dst&1 != 0
							}
							code := encodeRawScalarMove(evex, pp, opcode, low, upper, dst, mask, zero)
							got, size, ok, err := decodedX86ScalarMoveInstruction(code, 64)
							wantOp := op
							if zero {
								wantOp += ".Z"
							}
							want := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", low))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", upper))}}
							if mask != 0 {
								want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
							}
							want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", dst))})
							if err != nil || !ok || size != len(code) || got.Op != wantOp || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x = %+v, size=%d, ok=%v, err=%v; want %s %+v", code, got, size, ok, err, wantOp, want)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 147456 {
		t.Fatalf("covered %d encodings, want 147456", count)
	}
}

func TestDecodedX86RawScalarMoveMemoryAndInvalidForms(t *testing.T) {
	for pp, op := range map[int]Op{2: "VMOVSS", 3: "VMOVSD"} {
		for _, segment := range []byte{0x64, 0x65} {
			code := []byte{segment, 0x62, 0x01, byte(0x7c | pp), 0x08, 0x10, 0x7c, 0x8b, 0xff}
			scale := int64(4)
			if pp == 3 {
				code[3] |= 0x80
				scale = 8
			}
			got, size, ok, err := decodedX86ScalarMoveInstruction(code, 64)
			seg := FS
			if segment == 0x65 {
				seg = GS
			}
			wantMem := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: -scale, Segment: seg}
			if err != nil || !ok || size != len(code) || got.Op != op || len(got.Args) != 2 || !reflect.DeepEqual(got.Args[0].Mem, wantMem) || got.Args[1].Reg != "X31" {
				t.Fatalf("decode %x = %+v, size=%d, ok=%v, err=%v; want memory %+v", code, got, size, ok, err, wantMem)
			}
		}
	}
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"missing-modrm", []byte{0xc5, 0xfa, 0x10}, 64},
		{"missing-sib", []byte{0xc5, 0xfa, 0x10, 0x04}, 64},
		{"missing-displacement", []byte{0xc5, 0xfa, 0x10, 0x45}, 64},
		{"address-override", []byte{0x67, 0xc5, 0xfa, 0x10, 0xc0}, 64},
		{"vex-length", []byte{0xc5, 0xfe, 0x10, 0xc0}, 64},
		{"vex-memory-vvvv", []byte{0xc5, 0xf2, 0x10, 0x00}, 64},
		{"evex-fixed", []byte{0x62, 0xf1, 0x7a, 0x08, 0x10, 0xc0}, 64},
		{"evex-ss-width", []byte{0x62, 0xf1, 0xfe, 0x08, 0x10, 0xc0}, 64},
		{"evex-sd-width", []byte{0x62, 0xf1, 0x7f, 0x08, 0x10, 0xc0}, 64},
		{"evex-length", []byte{0x62, 0xf1, 0x7e, 0x28, 0x10, 0xc0}, 64},
		{"evex-broadcast", []byte{0x62, 0xf1, 0x7e, 0x18, 0x10, 0xc0}, 64},
		{"zero-k0", []byte{0x62, 0xf1, 0x7e, 0x88, 0x10, 0xc0}, 64},
		{"memory-vprime", []byte{0x62, 0xf1, 0x7e, 0x00, 0x10, 0x00}, 64},
		{"zero-store", []byte{0x62, 0xf1, 0x7e, 0x89, 0x11, 0x00}, 64},
		{"386-high-register", []byte{0xc5, 0x7a, 0x10, 0xc0}, 32},
		{"wrong-mode", []byte{0xc5, 0xfa, 0x10, 0xc0}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok, err := decodedX86ScalarMoveInstruction(tc.code, tc.mode); !ok || err == nil {
				t.Fatalf("invalid %x: matched=%v, err=%v", tc.code, ok, err)
			}
		})
	}
	for _, code := range [][]byte{nil, {0x64}, {0xc5}, {0xc4, 0xe1}, {0x62, 0xf1, 0x7e}, {0xc5, 0xf9, 0x10, 0xc0}, {0xc5, 0xfa, 0x5a, 0xc0}} {
		if _, _, ok, err := decodedX86ScalarMoveInstruction(code, 64); ok || err != nil {
			t.Fatalf("unrelated/truncated prefix %x: matched=%v, err=%v", code, ok, err)
		}
	}
}

func TestX86RawScalarMoveRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; three-target object coverage is required separately")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, pp := range []int{2, 3} {
		width := 4
		if pp == 3 {
			width = 8
		}
		for _, kind := range []string{"merge10", "merge11", "load", "store"} {
			for _, encoding := range []string{"vex", "evex", "masked", "zero"} {
				if kind == "store" && encoding == "zero" {
					continue
				}
				mask, zero := 0, encoding == "zero"
				if encoding == "masked" || zero {
					mask = 1
				}
				opcode := 0x10
				if kind == "merge11" || kind == "store" {
					opcode = 0x11
				}
				code := encodeRawScalarMove(encoding != "vex", pp, opcode, 0, 1, 2, mask, zero)
				if kind == "load" || kind == "store" {
					// Memory is (AX), destination/source X2. vvvv/V' must be reserved.
					code = encodeRawScalarMove(encoding != "vex", pp, opcode, 2, 0, 2, mask, zero)
					code[len(code)-1] = 0x10
				}
				name := fmt.Sprintf("rawscalarmove%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ in+8(FP),SI\nMOVQ mem+16(FP),AX\nMOVQ mask+24(FP),CX\nKMOVQ CX,K1\nVMOVUPS 32(SI),Y2\nVMOVUPS 32(SI),Z2\nMOVOU (SI),X0\nMOVOU 16(SI),X1\nMOVOU 32(SI),X2\n", name)
				for _, b := range code {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
				source.WriteString("MOVOU X2,(DI)\nVMOVUPS Y2,16(DI)\nVMOVUPS Z2,48(DI)\nRET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(void *,const void *,void *,uint64_t);\n", name)
				zeroFlag := 0
				if zero {
					zeroFlag = 1
				}
				fmt.Fprintf(&calls, "if (check(%s,%q,%d,%d,%d)) return %d;\n", name, kind, width, mask, zeroFlag, index)
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple, runPrefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int check(void (*fn)(void *,const void *,void *,uint64_t), const char *kind, int width, int masked, int zero) {
  for (int m=0;m<4;m++) {
    uint8_t in[96], out[112], want[16], mem[32], old[32];
    for (int i=0;i<96;i++) in[i]=(uint8_t)(17+i*3);
    for (int i=0;i<32;i++) mem[i]=old[i]=(uint8_t)(255-i*7);
    int active=!masked || (m&1), store=strcmp(kind,"store")==0, load=strcmp(kind,"load")==0;
    memcpy(want,in+32,16);
    if (!store) {
      if (load) memset(want,0,16); else memcpy(want,in+16,16);
      if (active) memcpy(want,load ? mem+1 : in,width);
      else if (zero) memset(want,0,width); else memcpy(want,in+32,width);
    }
    fn(out,in,mem+1,(uint64_t)m);
    if (memcmp(out,want,16)) { fprintf(stderr,"%s width=%d mask=%d zero=%d register mismatch\n",kind,width,m,zero); return 1; }
    for (int v=0;v<2;v++) {
      int start=v ? 48 : 16, bytes=v ? 64 : 32;
      for (int b=0;b<bytes;b++) {
        uint8_t expected=store ? in[32+b] : b<16 ? want[b] : 0;
        if (out[start+b]!=expected) { fprintf(stderr,"%s width=%d mask=%d alias byte=%d mismatch\n",kind,width,m,b); return 1; }
      }
    }
    if (store && active) memcpy(old+1,in+32,width);
    if (memcmp(mem,old,32)) { fprintf(stderr,"unexpected scalar memory write\n"); return 1; }
    // A cleared low mask bit suppresses the access, regardless of high bits.
    if (masked && !(m&1) && (load || store)) {
      fn(out,in,0,(uint64_t)m);
      if (memcmp(out,want,16)) return 1;
    }
  }
  return 0;
}
int main(void) {
` + calls.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_scalar_move", triple, ir, mainC, runPrefix)
}
