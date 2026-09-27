package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func rawScalarFloatToIntBytes(spec amd64ScalarFloatToIntSpec, memory, evex bool) []byte {
	opcode := byte(0x2d)
	if spec.truncating {
		opcode = 0x2c
	}
	if spec.unsigned {
		opcode = 0x79
		if spec.truncating {
			opcode = 0x78
		}
	}
	pp := byte(2) // F3: single precision.
	if spec.inputBits == 64 {
		pp = 3 // F2: double precision.
	}
	modRM := byte(0xc1) // X1 -> AX.
	if memory {
		modRM = 0x08 // (AX) -> CX.
	}
	if evex {
		p1 := byte(0x7c) | pp
		if spec.outputBits == 64 {
			p1 |= 0x80
		}
		return []byte{0x62, 0xf1, p1, 0x08, opcode, modRM}
	}
	if spec.outputBits == 64 {
		return []byte{0xc4, 0xe1, 0xf8 | pp, opcode, modRM}
	}
	return []byte{0xc5, 0xf8 | pp, opcode, modRM}
}

func TestX86RawScalarFloatToIntegerCompleteGo127Family(t *testing.T) {
	count := 0
	for op, spec := range amd64ScalarFloatToIntSpecs {
		if !spec.vector {
			continue
		}
		for _, evex := range []bool{false, true} {
			if spec.unsigned && !evex {
				continue // Go has no unsigned VEX encoding.
			}
			for _, memory := range []bool{false, true} {
				name := fmt.Sprintf("%s/evex=%t/memory=%t", op, evex, memory)
				t.Run(name, func(t *testing.T) {
					code := rawScalarFloatToIntBytes(spec, memory, evex)
					fn := Func{}
					for _, value := range code {
						fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
					}
					got, err := decodeX86RawDirectives(fn, "amd64")
					if err != nil {
						t.Fatal(err)
					}
					if len(got.Instrs) != 1 || got.Instrs[0].Op != op || len(got.Instrs[0].Args) != 2 {
						t.Fatalf("decoded %#x as %#v, want %s", code, got.Instrs, op)
					}
					wantSource := Operand{Kind: OpReg, Reg: "X1"}
					wantDestination := AX
					if memory {
						wantSource = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
						wantDestination = CX
					}
					args := got.Instrs[0].Args
					if args[0].Kind != wantSource.Kind || args[0].Reg != wantSource.Reg || args[0].Mem != wantSource.Mem || args[1].Reg != wantDestination {
						t.Fatalf("decoded %#x operands as %#v, want %+v, %s", code, args, wantSource, wantDestination)
					}
				})
				count++
			}
		}
	}
	if count != 48 {
		t.Fatalf("tested %d raw VEX/EVEX forms, want 48", count)
	}
}

func TestX86RawScalarFloatToIntegerRoundingAndEncodingAxes(t *testing.T) {
	base := []byte{0x62, 0xf1, 0x7f, 0x08, 0x2d, 0xc1}
	for _, tc := range []struct {
		name string
		p2   byte
		want Op
	}{
		{"round-nearest", 0x18, "VCVTSD2SI.RN_SAE"},
		{"round-down", 0x38, "VCVTSD2SI.RD_SAE"},
		{"round-up", 0x58, "VCVTSD2SI.RU_SAE"},
		{"round-zero", 0x78, "VCVTSD2SI.RZ_SAE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := append([]byte(nil), base...)
			code[3] = tc.p2
			got, length, recognized, err := decodedX86ScalarFloatToIntegerInstruction(code, 64)
			if !recognized || err != nil || length != len(code) || got.Op != tc.want {
				t.Fatalf("decode %#x = %+v, %d, %v, %v; want %s", code, got, length, recognized, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		want Op
		src  Reg
		dst  Reg
	}{
		{"signed-SAE", []byte{0x62, 0xf1, 0x7f, 0x18, 0x2c, 0xc1}, "VCVTTSD2SI.SAE", "X1", AX},
		{"unsigned-SAE", []byte{0x62, 0xf1, 0x7f, 0x18, 0x78, 0xc1}, "VCVTTSD2USIL.SAE", "X1", AX},
		{"extended-vector", []byte{0x62, 0xb1, 0x7f, 0x08, 0x78, 0xc1}, "VCVTTSD2USIL", "X17", AX},
		{"extended-GP", []byte{0x62, 0x71, 0x7f, 0x08, 0x78, 0xc1}, "VCVTTSD2USIL", "X1", "R8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, length, recognized, err := decodedX86ScalarFloatToIntegerInstruction(tc.code, 64)
			if !recognized || err != nil || length != len(tc.code) || got.Op != tc.want ||
				got.Args[0].Reg != tc.src || got.Args[1].Reg != tc.dst {
				t.Fatalf("decode %#x = %+v, %d, %v, %v; want %s %s, %s", tc.code, got, length, recognized, err, tc.want, tc.src, tc.dst)
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		off  int64
	}{
		{"SS-disp8-scale", []byte{0x62, 0xf1, 0x7e, 0x08, 0x79, 0x48, 0x02}, 8},
		{"SD-disp8-scale", []byte{0x62, 0xf1, 0x7f, 0x08, 0x79, 0x48, 0x02}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, recognized, err := decodedX86ScalarFloatToIntegerInstruction(tc.code, 64)
			if !recognized || err != nil || got.Args[0].Kind != OpMem || got.Args[0].Mem.Off != tc.off {
				t.Fatalf("decode %#x = %+v, %v, %v; want displacement %d", tc.code, got, recognized, err, tc.off)
			}
		})
	}
}

func TestX86RawScalarFloatToIntegerRejectsReservedEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"VEX-vector-length", []byte{0xc5, 0xff, 0x2c, 0xc1}, 64},
		{"VEX-vvvv", []byte{0xc5, 0xeb, 0x2c, 0xc1}, 64},
		{"VEX-Q-in-386", []byte{0xc4, 0xe1, 0xfb, 0x2c, 0xc1}, 32},
		{"EVEX-mask", []byte{0x62, 0xf1, 0x7f, 0x09, 0x2c, 0xc1}, 64},
		{"EVEX-zero", []byte{0x62, 0xf1, 0x7f, 0x88, 0x2c, 0xc1}, 64},
		{"EVEX-vvvv", []byte{0x62, 0xf1, 0x6f, 0x08, 0x2c, 0xc1}, 64},
		{"EVEX-LL-without-rounding", []byte{0x62, 0xf1, 0x7f, 0x28, 0x2d, 0xc1}, 64},
		{"EVEX-SAE-memory", []byte{0x62, 0xf1, 0x7f, 0x18, 0x2c, 0x00}, 64},
		{"address-override", []byte{0x67, 0xc5, 0xfb, 0x2c, 0xc1}, 64},
		{"missing-ModRM", []byte{0xc5, 0xfb, 0x2c}, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86ScalarFloatToIntegerInstruction(tc.code, tc.mode); !recognized || err == nil {
				t.Fatalf("reserved encoding %#x: recognized=%v error=%v", tc.code, recognized, err)
			}
		})
	}
}

func TestX86RawScalarFloatToIntegerCompilesEveryGoForm(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawscalarconvert(SB),4,$0-0\n")
			for _, spec := range amd64ScalarFloatToIntSpecs {
				if !spec.vector || target.goarch == "386" && spec.outputBits == 64 {
					continue
				}
				for _, evex := range []bool{false, true} {
					if spec.unsigned && !evex {
						continue
					}
					for _, memory := range []bool{false, true} {
						for _, value := range rawScalarFloatToIntBytes(spec, memory, evex) {
							fmt.Fprintf(&source, "\tBYTE $%d\n", value)
						}
						source.WriteString("\tNOP\n")
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawscalarconvert": {Name: "rawscalarconvert", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scalar-convert.ll", "raw-scalar-convert.o", ir)
		})
	}
}

func TestX86RawScalarFloatToIntegerRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT rawfloattointsemantics(SB),4,$0-16
	MOVQ input+0(FP), BX
	MOVQ out+8(FP), DI
	BYTE $0xc5; BYTE $0xfb; BYTE $0x2c; BYTE $0x03
	MOVL AX, 0(DI)
	BYTE $0xc5; BYTE $0xfb; BYTE $0x2d; BYTE $0x03
	MOVL AX, 4(DI)
	BYTE $0x62; BYTE $0xf1; BYTE $0x7f; BYTE $0x08; BYTE $0x78; BYTE $0x03
	MOVL AX, 8(DI)
	BYTE $0x62; BYTE $0xf1; BYTE $0x7f; BYTE $0x08; BYTE $0x79; BYTE $0x03
	MOVL AX, 12(DI)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
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
		Sigs: map[string]FuncSig{"rawfloattointsemantics": {
			Name: "rawfloattointsemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloattointsemantics(const double *, uint32_t *);
int main(void) {
  double input = 2.75;
  uint32_t out[4] = {0};
  rawfloattointsemantics(&input, out);
  if (out[0] != 2) return 1;
  if (out[1] != 3) return 2;
  if (out[2] != 2) return 3;
  if (out[3] != 3) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_float_to_integer", triple, ir, mainC, runPrefix)
}
