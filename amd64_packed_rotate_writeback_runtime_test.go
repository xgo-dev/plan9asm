package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// These original EVEX functions execute portable LLVM on the actual host.
// This checks the complete physical byte bank, not native AVX512 hardware.
func TestX86PackedRotatePortableValuesAndUpperWriteback(t *testing.T) {
	x86PackedRotateWritebackRuntime(t, false, false)
}

func TestX86PackedRotatePortableMemoryValuesAndUpperWriteback(t *testing.T) {
	x86PackedRotateWritebackRuntime(t, false, true)
}

// Isolate the emitter's upper-byte semantics from source-effect registration.
// All inputs are explicitly initialized, but this is not public API evidence.
func TestX86PackedRotateEmitterPortableUpperWriteback(t *testing.T) {
	x86PackedRotateWritebackRuntime(t, true, false)
}

var x86PackedRotateTestFamilies = []struct {
	op       string
	bits     int
	left     bool
	variable bool
}{
	{"VPROLD", 32, true, false}, {"VPROLQ", 64, true, false},
	{"VPRORD", 32, false, false}, {"VPRORQ", 64, false, false},
	{"VPROLVD", 32, true, true}, {"VPROLVQ", 64, true, true},
	{"VPRORVD", 32, false, true}, {"VPRORVQ", 64, false, true},
}

func x86PackedRotateWritebackRuntime(t *testing.T, emitter, memory bool) {
	t.Helper()
	execution := x86ScalarCountHostExecution(t)
	widths, apis := []int{16, 32, 64}, []string{"text", "module", "Go"}
	if emitter {
		widths, apis = []int{16}, []string{"emitter"}
	}
	for _, width := range widths {
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
		t.Run(bank, func(t *testing.T) {
			var source, declarations, prototypes, rows strings.Builder
			count := 0
			for _, family := range x86PackedRotateTestFamilies {
				for mode := 0; mode < 3; mode++ {
					for destination := 0; destination < 3; destination++ {
						name := fmt.Sprint("Rotate", count)
						count++
						immediate := []int{0, 7, 255}[destination]
						instruction := family.op
						broadcast := memory && destination == 0
						if broadcast {
							immediate = 7
							instruction += ".BCST"
						}
						if mode == 2 {
							instruction += ".Z"
						}
						if family.variable {
							first := bank + "0"
							if memory {
								first = "(CX)"
							}
							instruction += " " + first + "," + bank + "1,"
						} else {
							data := bank + "1"
							if memory {
								data = "(BX)"
							}
							instruction += fmt.Sprintf(" $%d,%s,", immediate, data)
						}
						if mode != 0 {
							instruction += "K1,"
						}
						instruction += fmt.Sprint(bank, destination)
						fmt.Fprintf(&declarations, "func %s(out *[260]byte,data,counts,old *[64]byte,mask uint64)\n", name)
						fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DI\nMOVQ data+8(FP),BX\nMOVQ counts+16(FP),CX\nMOVQ old+24(FP),SI\n", name)
						source.WriteString("VMOVUPS (CX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (SI),Z2\nVMOVUPS (SI),Z3\nKMOVQ mask+32(FP),K1\nMOVL $5,R8\nCMPL R8,$3\n")
						fmt.Fprintf(&source, "%s\nVMOVUPS Z0,0(DI)\nVMOVUPS Z1,64(DI)\nVMOVUPS Z2,128(DI)\nVMOVUPS Z3,192(DI)\nSETCS 256(DI)\nSETOS 257(DI)\nRET\n", instruction)
						fmt.Fprintf(&rows, "{%s,%q,%d,%d,%t,%t,%t,%d,%d,%d},\n", name, instruction,
							width, family.bits, family.left, family.variable, broadcast, mode, destination, immediate)
					}
				}
			}
			if count != 72 {
				t.Fatal("complete rotate family/mask/alias inventory changed", count)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			driver := strings.NewReplacer("PROTOTYPES", prototypes.String(), "ROWS", rows.String()).Replace(x86PackedRotateWritebackDriver)
			for _, api := range apis {
				t.Run(api, func(t *testing.T) {
					var ir string
					var err error
					if emitter {
						file, parseErr := Parse(ArchAMD64, source.String())
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						pkg := mustGoPackage(t, "rotate", "package rotate\n"+declarations.String())
						resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
						sigs, sigErr := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
						if sigErr != nil {
							t.Fatal(sigErr)
						}
						ir = x86ScalarFormatObjectUnit(t, file, sigs, "amd64", execution.triple, 0)
						driver = strings.ReplaceAll(driver, "Rotate", "InstructionFormat")
					} else {
						ir, err = x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
					}
					if err != nil || ir == "" {
						t.Fatal("initialized rotate source rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							input := ir
							if level == "-O2" {
								input = x86MulDivRoundOptimize(t, ir)
							}
							execution.compileAndRunLLVM(t, "packed-rotate-writeback", input, driver, level)
						})
					}
				})
			}
		})
	}
}

const x86PackedRotateWritebackDriver = `
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
struct row {
    void (*run)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
    const char *name;
    unsigned width,bits;
    bool left,variable,broadcast;
    unsigned mode,destination,immediate;
};
static const struct row rows[] = { ROWS };

static uint64_t rotate(uint64_t value, unsigned count, unsigned bits, bool left) {
    const uint64_t mask = bits == 64 ? UINT64_MAX : UINT32_MAX;
    value &= mask;
    count %= bits;
    if (!count) return value;
    return (left ? (value << count) | (value >> (bits-count)) :
                   (value >> count) | (value << (bits-count))) & mask;
}

int main(void) {
    const uint64_t masks[] = {0,1,0x55,0xaa,UINT64_MAX,UINT64_C(1)<<63};
    for (unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);++r) {
        const struct row *row=&rows[r];
        const unsigned lane_bytes=row->bits/8;
        for (unsigned sample=0;sample<8;++sample) {
            uint8_t data[64],counts[64],old[64],data_before[64],counts_before[64],old_before[64];
            for (unsigned byte=0;byte<64;++byte) {
                data[byte]=(uint8_t)(byte*37+sample*53+1);
                old[byte]=(uint8_t)(byte*11+sample*67+129);
            }
            for (unsigned lane=0;lane<64/lane_bytes;++lane) {
                uint64_t value=UINT64_C(0xfedcba9876543200)+sample*row->bits+lane*5+sample;
                memcpy(counts+lane*lane_bytes,&value,lane_bytes);
            }
            memcpy(data_before,data,64);
            memcpy(counts_before,counts,64);
            memcpy(old_before,old,64);
            for (unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);++m) {
                uint8_t output[262],expected[262];
                memset(output,0xa7,sizeof(output));
                memset(expected,0xa7,sizeof(expected));
                memcpy(expected+1,counts,64);
                memcpy(expected+65,data,64);
                memcpy(expected+129,old,64);
                memcpy(expected+193,old,64);
                uint8_t *destination=expected+1+row->destination*64;
                for (unsigned lane=0;lane<row->width/lane_bytes;++lane) {
                    if (row->mode && !(masks[m]>>lane&1)) {
                        if (row->mode==2) memset(destination+lane*lane_bytes,0,lane_bytes);
                        continue;
                    }
                    uint64_t value=0,count=row->immediate;
                    unsigned source_lane=row->broadcast?0:lane;
                    memcpy(&value,data+(row->variable?lane:source_lane)*lane_bytes,lane_bytes);
                    if (row->variable) {
                        count=0;
                        memcpy(&count,counts+source_lane*lane_bytes,lane_bytes);
                    }
                    value=rotate(value,(unsigned)(count&(row->bits-1)),row->bits,row->left);
                    memcpy(destination+lane*lane_bytes,&value,lane_bytes);
                }
                memset(destination+row->width,0,64-row->width);
                expected[257]=expected[258]=0;
                row->run(output+1,data,counts,old,masks[m]);
                if (memcmp(output,expected,sizeof(output)) || memcmp(data,data_before,64) ||
                    memcmp(counts,counts_before,64) || memcmp(old,old_before,64)) {
                    for (unsigned byte=0;byte<sizeof(output);++byte) {
                        if (output[byte]!=expected[byte]) {
                            fprintf(stderr,"%s sample=%u mask=%llx byte=%u got=%x want=%x\n",
                                    row->name,sample,(unsigned long long)masks[m],byte,output[byte],expected[byte]);
                            break;
                        }
                    }
                    return 1;
                }
            }
        }
    }
    return 0;
}
`
