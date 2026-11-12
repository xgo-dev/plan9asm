package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86VectorZeroRawPairedStateAndOrigin(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, code := range []string{
			"WORD $0xf8c5\nBYTE $0x77", "WORD $0xfcc5\nBYTE $0x77",
			"LONG $0x77f8e1c4", "LONG $0x77fce1c4",
			"LONG $0x7778e1c4", "LONG $0x777ce1c4",
		} {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+code+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawVectorZeroSource(ins, arch) {
				t.Fatal("original zero-operand encoding lost its source identity", arch, code)
			}
			t.Run(arch+"/"+code, func(t *testing.T) {
				state := x86ResultState{flags: x86ByteFlagsAll}
				for register := 0; register < 32; register++ {
					state.writeVector(register, 64, uint64(0x8123456789abcdef)>>uint(register%8), false)
				}
				before, want := state.clone(), state.clone()
				last, first := 16, 16
				if arch == "386" {
					last = 8
				}
				if ins.Op == "VZEROALL" {
					first = 0
				}
				for register := 0; register < last; register++ {
					want.writeVector(register, 64, want.vectorBytes(register)|(^uint64(0)<<uint(first)), false)
				}
				accepted, known := x86LoweredVectorZeroResultStep(ins, &state, nil, 0, arch)
				if !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("complete implicit bank/preserved unknown/FLAGS effect differs", accepted, known)
				}
				for _, control := range []struct {
					name   string
					change func(*Instr)
				}{
					{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"opcode", func(ins *Instr) {
						ins.Op = "VZEROALL"
						if ins.x86SourceRaw.op == "VZEROALL" {
							ins.Op = "VZEROUPPER"
						}
					}},
					{"operand", func(ins *Instr) { ins.Args = []Operand{{Kind: OpReg, Reg: AX}} }},
					{"source-operand", func(ins *Instr) { ins.x86SourceRaw.args = []Operand{{Kind: OpReg, Reg: AX}} }},
					{"vector", func(ins *Instr) { ins.x86VectorBytes = 16 }},
					{"address", func(ins *Instr) { ins.x86AddressBits = 32 }},
					{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
					{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
					{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
				} {
					t.Run(control.name, func(t *testing.T) {
						changed, state := ins, before.clone()
						origin := *ins.x86SourceRaw
						changed.x86SourceRaw = &origin
						control.change(&changed)
						accepted, known := x86LoweredVectorZeroResultStep(changed, &state, nil, 0, arch)
						if accepted || known != (control.name != "origin") ||
							x86RawVectorZeroSource(changed, arch) || !reflect.DeepEqual(state, before) {
							t.Fatal("changed zero-operand source acquired a native continuation", accepted, known)
						}
					})
				}
			})
		}
	}
}

// The complete original eight named/VEX2/VEX3/WIG source programs retain every
// X/Y/Z bank and K/FLAGS canary. Actual native MXCSR checks remain separate.
func TestX86VectorZeroOriginalWholeBankPortableExecution(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	source, _, prototypes, checks := x86VectorZeroRuntimeFixture(t)
	var declarations strings.Builder
	for index := 0; index < 8; index++ {
		fmt.Fprintf(&declarations, "func vectorzero%d(out,in *byte,mask uint64)\n", index)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes + `
static int checkVectorZero(void (*program)(uint8_t*,const uint8_t*,uint64_t),
                           const char *name,int clearLow) {
    for (unsigned round=0; round<16; round++) {
        uint8_t input[2050], original[2050], output[3596];
        for (unsigned i=0; i<sizeof(input); i++) input[i]=(uint8_t)(i*73+round*19+1);
        memcpy(original,input,sizeof(input));
        memset(output,0xc3,sizeof(output));
        uint64_t mask=UINT64_C(0x8123456789abcdef)^round;
        program(output+1,input+1,mask);
        uint64_t gotMask;
        memcpy(&gotMask,output+3587,8);
        if (output[0]!=0xc3 || output[3595]!=0xc3 || output[3585]!=1 ||
            output[3586]!=0 || gotMask!=mask || memcmp(input,original,sizeof(input))) {
            fprintf(stderr,"%s round=%u FLAGS/K/input/canary failure\n",name,round);
            return 1;
        }
        const unsigned widths[]={16,32,64}, offsets[]={0,16,48};
        for (unsigned reg=0; reg<32; reg++) {
            for (unsigned view=0; view<3; view++) {
                for (unsigned byte=0; byte<widths[view]; byte++) {
                    uint8_t want=reg<16 && (clearLow || byte>=16) ? 0 : input[1+reg*64+byte];
                    uint8_t got=output[1+reg*112+offsets[view]+byte];
                    if (got!=want) {
                        fprintf(stderr,"%s round=%u reg=%u view=%u byte=%u\n",
                                name,round,reg,view,byte);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
int main(void) {
` + checks + "return 0;\n}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("complete original vector-zero source lost its native-read continuation", err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("vector-zero-%s-ir%d-%s", api, index, level[1:]), triple, text, main, nil)
				}
			}
		})
	}
}
