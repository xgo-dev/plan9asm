package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86RawHorizontalIntegerEncodingAxes(t *testing.T) {
	count := 0
	for _, form := range []struct {
		op     Op
		opcode byte
	}{
		{"VPHADDW", 0x01}, {"VPHADDD", 0x02}, {"VPHADDSW", 0x03},
		{"VPHSUBW", 0x05}, {"VPHSUBD", 0x06}, {"VPHSUBSW", 0x07},
	} {
		for width, prefix := range []string{"X", "Y"} {
			for _, w := range []bool{false, true} {
				for dst := 0; dst < 16; dst++ {
					for src1 := 0; src1 < 16; src1++ {
						for src2 := 0; src2 < 16; src2++ {
							code := encodeX86VEXHorizontalFloat(form.opcode, 1, true, width == 1, w, dst, src1, src2)
							code[1] = code[1]&0xe0 | 2
							got, size, matched, err := decodedX86VEXHorizontalIntegerInstruction(code, 64)
							want := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src2))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, src1))}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, dst))}}
							if err != nil || !matched || size != len(code) || got.Op != form.op || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x=%+v size=%d matched=%v err=%v; want %s %+v", code, got, size, matched, err, form.op, want)
							}
							_, _, matched, err = decodedX86VEXHorizontalIntegerInstruction(code, 32)
							if !matched || (err != nil) != (dst >= 8 || src1 >= 8 || src2 >= 8) {
								t.Fatalf("386 decode %x matched=%v err=%v", code, matched, err)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 98304 {
		t.Fatalf("covered %d encodings, want 98304", count)
	}
}

func TestX86RawHorizontalIntegerInvalidAndSegmentForms(t *testing.T) {
	for _, code := range [][]byte{
		{0xc4, 0xe2, 0x79, 0x02},             // Missing ModRM.
		{0xc4, 0xe2, 0x79, 0x02, 0x04},       // Missing SIB.
		{0xc4, 0xe2, 0x79, 0x02, 0x45},       // Missing disp8.
		{0xc4, 0xe2, 0x78, 0x02, 0xc0},       // pp=none.
		{0xc4, 0xe2, 0x7a, 0x02, 0xc0},       // pp=F3.
		{0xc4, 0xe2, 0x7b, 0x02, 0xc0},       // pp=F2.
		{0x62, 0xf2, 0x7d, 0x08, 0x02, 0xc0}, // No EVEX variant.
		{0x67, 0xc4, 0xe2, 0x79, 0x02, 0x00},
	} {
		if _, _, matched, err := decodedX86VEXHorizontalIntegerInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x matched=%v err=%v", code, matched, err)
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		code := []byte{segment.prefix, 0xc4, 0x02, 0xe5, 0x06, 0x64, 0x88, 0x20}
		got, size, matched, err := decodedX86VEXHorizontalIntegerInstruction(code, 64)
		want := []Operand{{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: 32}}, {Kind: OpReg, Reg: "Y3"}, {Kind: OpReg, Reg: "Y12"}}
		if err != nil || !matched || size != len(code) || got.Op != "VPHSUBD" || !reflect.DeepEqual(got.Args, want) {
			t.Fatalf("decode %x=%+v %v", code, got, err)
		}
	}
}

func TestX86HorizontalIntegerGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPHADDW", "VPHADDD", "VPHADDSW", "VPHSUBW", "VPHSUBD", "VPHSUBSW"} {
			lines := []string{op + " X0,Y1,Y2", op + " Z0,Z1,Z2", op + " X0,X1,K1,X2", op + " X0,X1,(AX)", op + ".Z X0,X1,X2", op + ".SAE X0,X1,X2", op + " X16,X0,X1"}
			for _, line := range lines {
				dir := t.TempDir()
				path := filepath.Join(dir, "invalid.s")
				if err := os.WriteFile(path, []byte("TEXT invalid(SB),4,$0-0\n"+line+"\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				if output, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("Go %s accepted %s; repair oracle: %s", arch, line, output)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				assertX86HorizontalIntegerRejected(t, arch, triple, line)
			}
		}
	}
}

func TestTranslateX86HorizontalIntegerGo386RegisterCompatibility(t *testing.T) {
	// Go's VEX Yxr/Yyr classes accept X/Y8-15 even for its 386 frontend.
	// This named compatibility grammar is distinct from architectural raw
	// 32-bit decoding, which still rejects extended register fields.
	var source strings.Builder
	source.WriteString("TEXT compat(SB),4,$0-0\n")
	for _, op := range []string{"VPHADDW", "VPHADDD", "VPHADDSW", "VPHSUBW", "VPHSUBD", "VPHSUBSW"} {
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
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"compat": {Name: "compat", Ret: Void}}}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Go frontend acceptance invented high physical mode32 registers: %v", err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("direct module invented mode32 high registers", err)
			}
			translated, err := translateGoModuleInContext(ctx, x86SADGoPackage(t, "386", "()"), []byte(strings.Replace(source.String(), "compat(SB)", "·sad(SB)", 1)), GoModuleOptions{GOARCH: "386", TargetTriple: triple})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("typed module invented mode32 high registers", err)
			}
		})
	}
}

// All six VEX instructions share Go's two _yvaddsubpd rows (X/Y).
// The legacy siblings use yxm_q4, except PHADDD's MMX-capable ymmxmm0f38.
func TestX86RawHorizontalIntegerGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			last := 7
			if arch == "amd64" {
				last = 15
			}
			var source strings.Builder
			source.WriteString("TEXT horizontal(SB),4,$0-0\nPHADDD M0,M7\nPHADDD -7(BX)(CX*4),M0\n")
			for _, op := range []string{"PHADDD", "PHADDSW", "PHADDW", "PHSUBD", "PHSUBSW", "PHSUBW"} {
				for _, reg := range []int{0, last} {
					for _, input := range []string{fmt.Sprintf("X%d", last-reg), "(AX)", "-7(BX)(CX*4)", "8192(SI)"} {
						fmt.Fprintf(&source, "%s %s,X%d\n", op, input, reg)
					}
					for _, width := range []string{"X", "Y"} {
						for _, input := range []string{fmt.Sprintf("%s%d", width, last-reg), "(AX)", "-7(BX)(CX*4)", "8192(SI)"} {
							fmt.Fprintf(&source, "V%s %s,%s%d,%s%d\n", op, input, width, last-reg, width, reg)
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
			if len(want) != 147 || len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions; expected %d, including RET", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
			file := x86RawUnprovedReturnFormProbeFile(t, arch, "horizontal", code)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				// A terminal UD2 removes only the return obligation. It does
				// not initialize the preceding MMX/vector/address inputs.
				// Keep all original formats as private objects, independently
				// of the three public APIs' required Context observations.
				ir := x86UnboundVoidRawProbeObject(t, file, arch, triple)
				compileLLVMToObject(t, llc, triple, "raw-horizontal.ll", "raw-horizontal.o", ir)
			}
		})
	}
}

func TestX86HorizontalIntegerInitializedMMXRegionKeepsRawBoundary(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const declaration = "func horizontalMMX(a,b uint64) uint64\n"
	const source = "TEXT ·horizontalMMX(SB),4,$0-24\nMOVQ a+0(FP),M0\nMOVQ b+8(FP),M7\nPHADDD M0,M7\nMOVQ M7,ret+16(FP)\nEMMS\nRET\n"
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			arch := "amd64"
			if strings.HasPrefix(triple, "i") {
				arch = "386"
			}
			x86LEAActualTargetGoObject(t, arch, triple, source)
			code := assembleX87ControlBytes(t, arch, "TEXT row(SB),4,$0-0\nPHADDD M0,M7\nRET\n")
			if !reflect.DeepEqual(code, []byte{0x0f, 0x38, 0x02, 0xf8, 0xc3}) {
				t.Fatal("initialized counterpart lost the original MMX row identity", code)
			}
			var bytes strings.Builder
			for _, value := range code[:len(code)-1] {
				fmt.Fprintf(&bytes, "BYTE $0x%02x\n", value)
			}
			raw := strings.Replace(source, "PHADDD M0,M7\n", bytes.String(), 1)
			x86LEAActualTargetGoObject(t, arch, triple, raw)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
				if err != nil {
					t.Fatal("complete named MMX region lost its bounded inputs/EMMS", api, err)
				}
				if !strings.Contains(ir, "phaddd") || !strings.Contains(ir, "emms") {
					t.Fatal("initialized counterpart lost the physical MMX operation/tag closure", api)
				}
				compileLLVMToObject(t, llc, triple, "initialized-horizontal-mmx-"+api+".ll", "initialized-horizontal-mmx-"+api+".o", ir)
				if ir, err := x86ScalarFPBitViewAPI(t, raw, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("typed values and EMMS invented an authenticated raw MMX region", api, err)
				}
			}
		})
	}
}

func TestX86HorizontalIntegerViewsRuntime(t *testing.T) {
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
		op                       string
		bits, subtract, saturate int
	}{{"VPHADDW", 16, 0, 0}, {"VPHADDD", 32, 0, 0}, {"VPHADDSW", 16, 0, 1}, {"VPHSUBW", 16, 1, 0}, {"VPHSUBD", 32, 1, 0}, {"VPHSUBSW", 16, 1, 1}} {
		for width, prefix := range []string{"X", "Y"} {
			for _, memory := range []bool{false, true} {
				for dst := 0; dst < 3; dst++ {
					name := fmt.Sprintf("horizontal%d", index)
					index++
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),DI\nMOVQ old+24(FP),SI\nVMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (SI),Z2\n", name)
					input := prefix + "1"
					if memory {
						input = "(BX)"
					}
					fmt.Fprintf(&source, "%s %s,%s0,%s%d\nVMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\nRET\n", spec.op, input, prefix, prefix, dst, dst, dst, dst)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1}}}}
					fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *,const void *);\n", name)
					fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d,%d)) return %d;\n", name, 16<<width, spec.bits/8, spec.subtract, spec.saturate, index)
				}
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
	mainC := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int64_t lane(const uint8_t *p,int bytes) {
  if(bytes==2) {int16_t v;memcpy(&v,p,2);return v;}
  int32_t v;memcpy(&v,p,4);return v;
}
static int check(void (*fn)(const void *,const void *,void *,const void *),int bytes,int laneBytes,int sub,int sat) {
  for(int seed=0;seed<128;seed++) {
    uint8_t a[64],b[64],old[64],out[112],want[64]={0};
    for(int i=0;i<64;i++) {a[i]=(uint8_t)(seed*17+i*31);b[i]=(uint8_t)(seed*43+i*7);old[i]=(uint8_t)(193-i);}
    for(int i=0;i<bytes/laneBytes;i++) {
      int per128=16/laneBytes,pos=i%per128,block=i-pos;
      const uint8_t *input=pos<per128/2?a:b;
      int pair=block+2*(pos%(per128/2));
      int64_t left=lane(input+pair*laneBytes,laneBytes),right=lane(input+(pair+1)*laneBytes,laneBytes);
      int64_t result=sub?left-right:left+right;
      if(sat) {if(result<-32768)result=-32768;if(result>32767)result=32767;}
      uint64_t bits=(uint64_t)result;
      for(int j=0;j<laneBytes;j++) want[i*laneBytes+j]=(uint8_t)(bits>>(j*8));
    }
    fn(a,b,out,old);
    for(int view=0;view<3;view++) {
      int offset=view==0?0:view==1?64:96;
      for(int i=0;i<(64>>view);i++) if(out[offset+i]!=want[i]) {
        fprintf(stderr,"horizontal mismatch bytes=%d lane=%d sub=%d sat=%d seed=%d view=%d byte=%d\n",bytes,laneBytes,sub,sat,seed,view,i);return 1;
      }
    }
  }
  return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "horizontal_integer", triple, ir, mainC, commandPrefix)
}
