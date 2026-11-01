package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Read every original encoding row and its opcode-specific attributes. Sharing
// _yvpshufd does not give the word shuffles dword broadcast permissions.
func x86OfficialImmediateShuffleRows(t *testing.T) []string {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	counts := map[string]int{}
	for _, rule := range rules {
		pp := map[string]string{"VPSHUFD": "66", "VPSHUFHW": "F3", "VPSHUFLW": "F2"}[rule.Opcode]
		if pp == "" {
			continue
		}
		index := rule.RowIndex
		classes := [][]string{
			{"Yu8", "Yxm", "Yxr"}, {"Yi8", "Yxm", "Yxr"},
			{"Yu8", "Yym", "Yyr"}, {"Yi8", "Yym", "Yyr"},
			{"Yu8", "YxmEvex", "YxrEvex"}, {"Yu8", "YxmEvex", "Yknot0", "YxrEvex"},
			{"Yu8", "YymEvex", "YyrEvex"}, {"Yu8", "YymEvex", "Yknot0", "YyrEvex"},
			{"Yu8", "Yzm", "Yzr"}, {"Yu8", "Yzm", "Yknot0", "Yzr"},
		}
		zcase := "Zvex_i_rm_r"
		if index >= 4 {
			zcase = "Zevex_i_rm_r"
			if index%2 == 1 {
				zcase = "Zevex_i_rm_k_r"
			}
		}
		offsets := []int{0, 0, 2, 2, 4, 4, 7, 7, 10, 10}
		advances := []int{0, 2, 0, 2, 0, 3, 0, 3, 0, 3}
		if index < 0 || index >= len(classes) || rule.Ytab != "_yvpshufd" || rule.Prefix != "Pavx" ||
			!reflect.DeepEqual(rule.Classes, classes[index]) || rule.ZCase != zcase ||
			rule.EncodingOffset != offsets[index] || rule.ZOffset != advances[index] || len(rule.OpBytes) != 13 {
			t.Fatalf("unmodeled original shuffle row: %+v", rule)
		}
		generation, bits := "vex", "128"
		if index == 2 || index == 3 || index == 6 || index == 7 {
			bits = "256"
		} else if index >= 8 {
			bits = "512"
		}
		if index >= 4 {
			generation = "evex"
		}
		terms := []string{"avxEscape", generation + bits, generation + pp, generation + "0F", generation + "W0"}
		if !reflect.DeepEqual(strings.Split(rule.OpBytes[rule.EncodingOffset], " | "), terms) {
			t.Fatalf("unmodeled original shuffle prefix: %+v", rule)
		}
		opcodeOffset := rule.EncodingOffset + 1
		if generation == "evex" {
			attributes := "evexN" + map[string]string{"128": "16", "256": "32", "512": "64"}[bits]
			if rule.Opcode == "VPSHUFD" {
				attributes += " | evexBcstN4"
			}
			attributes += " | evexZeroingEnabled"
			if rule.OpBytes[opcodeOffset] != attributes {
				t.Fatalf("unmodeled original shuffle attributes: %+v", rule)
			}
			opcodeOffset++
		}
		if rule.OpBytes[opcodeOffset] != "0x70" {
			t.Fatalf("unmodeled original shuffle opcode: %+v", rule)
		}
		bank := map[string]string{"128": "X", "256": "Y", "512": "Z"}[bits]
		immediate := "255"
		if rule.Classes[0] == "Yi8" {
			immediate = "-128"
		}
		args := "$" + immediate + "," + bank + "0,"
		if len(rule.Classes) == 4 {
			args += "K1,"
		}
		// High banks force the unmasked X/Y EVEX row instead of VEX selection.
		destination := "1"
		if generation == "evex" && bits != "512" {
			destination = "17"
		}
		rows = append(rows, rule.Opcode+" "+args+bank+destination)
		counts[rule.Opcode]++
	}
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		if counts[op] != 10 {
			t.Fatalf("%s complete original-row denominator changed: %d", op, counts[op])
		}
	}
	if len(rows) != 30 {
		t.Fatalf("complete original shuffle denominator changed: %d", len(rows))
	}
	return rows
}

func TestX86ImmediateShuffleOfficialCallerRegistration(t *testing.T) {
	rows := x86OfficialImmediateShuffleRows(t)
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		rows = append(rows, op+" $255,X0,X1")
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !x86CallerVectorMoveKnown(file.Funcs[0].Instrs[1]) {
				t.Fatal("Go-accepted original shuffle row has no caller effect")
			}
		})
	}
}

func TestX86ImmediateShuffleMemoryShapeIsPhysicalTuple(t *testing.T) {
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for bank, width := range map[string]int{"X": 16, "Y": 32, "Z": 64} {
			for _, suffix := range []string{"", ".Z"} {
				row := fmt.Sprintf("%s%s $0,(AX),K1,%s1", op, suffix, bank)
				t.Run(row, func(t *testing.T) {
					goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					bytes, write, valid := x86InstructionMemoryShape(file.Funcs[0].Instrs[1], 1, "amd64")
					if !valid || write || bytes != int64(width) {
						t.Fatalf("physical tuple read got %d/%v/%v, want %d/false/true", bytes, write, valid, width)
					}
				})
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86ImmediateShuffleCompleteBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		widths := []int{16}
		if strings.HasPrefix(op, "V") {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			for _, mode := range []int{0, 1, 2} {
				if !strings.HasPrefix(op, "V") && mode != 0 {
					continue
				}
				broadcasts := []bool{false}
				if op == "VPSHUFD" {
					broadcasts = append(broadcasts, true)
				}
				for _, broadcast := range broadcasts {
					name := fmt.Sprintf("immshuffle%d", count)
					count++
					bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
					row := op
					if broadcast {
						row += ".BCST"
					}
					if mode == 2 {
						row += ".Z"
					}
					input := bank + "0"
					if broadcast {
						input = "(BX)"
					}
					row += " $27," + input + ","
					if mode != 0 {
						row += "K1,"
					}
					row += bank + "1"
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ mask+16(FP),DX\n", name)
					fmt.Fprintf(&source, "VMOVUPS (BX),Z0\nVMOVUPS (AX),Z1\nKMOVQ DX,K1\nCMPQ AX,AX\nSTC\n%s\nVMOVUPS Z1,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", row)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: I64, Index: 2, Field: -1},
					}}}
					kind := 0
					if strings.Contains(op, "HW") {
						kind = 2
					} else if strings.Contains(op, "LW") {
						kind = 1
					}
					fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,uint64_t);\n", name)
					fmt.Fprintf(&checks, "if(check(%s,\"%s\",%d,%d,%d,%d,%d)) return 1;\n", name, name, width, kind, mode,
						x86FloatAddSubBoolInt(strings.HasPrefix(op, "V")), x86FloatAddSubBoolInt(broadcast))
				}
			}
		}
	}
	if count != 40 {
		t.Fatalf("independent complete runtime denominator changed: %d", count)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations.String() + `
static int check(void (*program)(uint8_t*,const uint8_t*,uint64_t),const char *name,
                 unsigned width,int kind,int mode,int vector,int broadcast) {
    const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x55aa55aa55aa55aa)};
    for(unsigned m=0;m<4;m++) {
        uint8_t input[66],original[66],output[68],before[68];
        for(unsigned i=0;i<66;i++) input[i]=(uint8_t)(i*29+197);
        for(unsigned i=0;i<68;i++) output[i]=(uint8_t)(i*13+71);
        memcpy(original,input,sizeof(input)); memcpy(before,output,sizeof(output));
        program(output+1,input+1,masks[m]);
        if(output[0]!=before[0] || output[67]!=before[67] ||
           output[65]!=1 || output[66]!=0 || memcmp(input,original,sizeof(input))) return 1;
        unsigned lane=kind ? 2 : 4;
        for(unsigned i=0;i<64;i++) {
            uint8_t want=before[1+i];
            if(i>=width) { if(vector) want=0; }
            else if(mode && !(masks[m]>>(i/lane)&1)) { if(mode==2) want=0; }
            else {
                unsigned at=i;
                if(broadcast) at=i%4;
                else if(kind==0) at=(i/16)*16+((27>>(2*((i%16)/4)))&3)*4+i%4;
                else {
                    unsigned word=(i%16)/2;
                    if((kind==1 && word<4) || (kind==2 && word>=4))
                        at=(i/16)*16+(kind==2 ? 8 : 0)+((27>>(2*(word%4)))&3)*2+i%2;
                }
                want=input[1+at];
            }
            if(output[1+i]!=want) {
                fprintf(stderr,"%s mask=%llx byte=%u got=%x want=%x\n",name,(unsigned long long)masks[m],i,output[1+i],want);
                return 1;
            }
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "immediate-shuffle-complete-bytes", triple, text, oracle, prefix)
		})
	}
}
