package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestX86HighLowMoveGrammarAndPrivateSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86HighLowMoveOracle {
			text := row.op + " X0,X1"
			if row.vector {
				text += ",X2"
			}
			for _, change := range []string{"memory", "Y-bank", "arity", "Z", "unsealed-raw", "mode32-high"} {
				if change == "mode32-high" && (arch != "386" || !row.vector) {
					continue
				}
				t.Run(arch+"/"+row.op+"/"+change, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, text)
					switch change {
					case "memory":
						ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
					case "Y-bank":
						ins.Args[0].Reg = "Y0"
					case "arity":
						ins.Args = ins.Args[:len(ins.Args)-1]
					case "Z":
						ins.Op += ".Z"
					case "unsealed-raw":
						ins.x86Encoded = true
					case "mode32-high":
						ins.Args[0].Reg = "X16"
					}
					if change != "unsealed-raw" {
						_, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
						if !known || err == nil {
							t.Fatal("invalid class/suffix/mode lost its typed boundary", known, err)
						}
						if change == "mode32-high" && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("physical high bank was conflated with ordinary grammar refusal", err)
						}
					}
					state := x86ResultState{flags: x86ByteFlagsAll}
					for index := 0; index < 3; index++ {
						state.writeVector(index, 64, ^uint64(0), false)
					}
					before := state.clone()
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("invalid or unsealed source acquired NUM or changed state", change)
					}
				})
			}
		}
	}
}

func TestX86HighLowMoveMode32InitializedRawThreeAPIObjects(t *testing.T) {
	var source, declarations strings.Builder
	var names []string
	for _, row := range []struct {
		opcode byte
		op     string
	}{{0x12, "VMOVHLPS"}, {0x16, "VMOVLHPS"}} {
		name := "RawMode32" + row.op
		names = append(names, name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVL out+0(FP),DX\nMOVL input+4(FP),AX\n", name)
		for index := 1; index <= 6; index++ {
			fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", index)
		}
		for _, encoding := range []struct {
			kind                string
			first, second, dest int
			wig                 bool
		}{{"VEX2", 1, 2, 3, false}, {"VEX3", 4, 5, 6, true}, {"EVEX", 1, 2, 3, false}} {
			source.WriteString(x86RawDisplacementDirectives(encodeX86RawVectorHighLowMove(row.opcode, encoding.kind, encoding.first, encoding.second, encoding.dest, encoding.wig)))
		}
		source.WriteString("VMOVUPS Z3,(DX)\nVMOVUPS Z6,64(DX)\nRET\n")
		fmt.Fprintf(&declarations, "func %s(out *[128]byte,input *[64]byte)\n", name)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "386", triple, api)
					if err != nil {
						t.Fatal("initialized low-bank whole raw source rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				})
			}
		})
	}
}

var x86HighLowMoveOracle = []struct {
	op           string
	high, vector bool
}{
	{"MOVHLPS", false, false}, {"MOVLHPS", true, false},
	{"VMOVHLPS", false, true}, {"VMOVLHPS", true, true},
}

func TestX86HighLowMoveRawIdentityAndInputsRemainBound(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86HighLowMoveOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
				if arch == "386" {
					word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
				}
				instruction, destination := row.op+" X0,X1", "Z1"
				if row.vector {
					instruction, destination = row.op+" X0,X1,X2", "Z2"
				}
				prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s a+0(FP),AX\n%s b+%d(FP),BX\n%s out+%d(FP),DX\n", 3*word, move, move, word, move, 2*word)
				source := prefix + "VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (BX),Z2\n" + x86RawNumericalInstruction(t, arch, instruction) + "VMOVUPS " + destination + ",(DX)\nRET\n"
				declaration := "func Value(a,b,out *[64]byte)"
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil {
							t.Fatal("initialized actual-Go raw half source rejected", err)
						}
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(a,b,out uintptr)", arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("integer declaration borrowed pointer/source authority", err)
						}
						for _, seed := range []string{"VMOVUPS (AX),Z0\n", "VMOVUPS (BX),Z1\n", move + " out+" + fmt.Sprint(2*word) + "(FP),DX\n"} {
							changed := strings.Replace(source, seed, "", 1)
							if changed == source {
								t.Fatal("negative source was not changed", seed)
							}
							if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("raw bytes supplied missing numerical/pointer input", seed, err)
							}
						}
					})
				}
				parsed, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				file, err := normalizeX86RawFile(parsed, arch)
				if err != nil {
					t.Fatal(err)
				}
				function := file.Funcs[0]
				if function.x86RawReplay == nil || function.x86RawReplay.validate(function, arch) != nil {
					t.Fatal("original whole source lost its sealed replay")
				}
				changedProducer := function
				changedProducer.Instrs = cloneX86ReplayInstrs(function.Instrs)
				changedProducer.Instrs[1].Raw += " edited producer"
				if function.x86RawReplay.validate(changedProducer, arch) == nil {
					t.Fatal("edited producer borrowed original raw whole-source identity")
				}
				var raw Instr
				for _, ins := range file.Funcs[0].Instrs {
					if ins.Op == Op(row.op) {
						raw = ins
					}
				}
				if !x86RawMoveHalfSource(raw, arch) {
					t.Fatal("original raw instruction lost exact source identity", raw)
				}
				for _, mutation := range []string{"args", "source", "width", "address", "segment", "memory"} {
					t.Run(mutation, func(t *testing.T) {
						changed := raw
						changed.Args = append([]Operand(nil), raw.Args...)
						switch mutation {
						case "args":
							changed.Args[0].Reg = "X3"
						case "source":
							changed.x86SourceRaw = nil
							changed.x86Encoded = true
						case "width":
							changed.x86VectorBytes++
						case "address":
							changed.x86AddressBits = 32
						case "segment":
							changed.x86SegmentPrefix = 0x64
						case "memory":
							changed.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
						}
						state := x86ResultState{flags: x86ByteFlagsAll}
						for i := 0; i < 4; i++ {
							state.writeVector(i, 64, ^uint64(0), false)
						}
						before := state.clone()
						accepted, _ := x86ResultMoveHalfStep(changed, &state, nil, 0, arch, true)
						if x86RawMoveHalfSource(changed, arch) || accepted || !reflect.DeepEqual(state, before) {
							t.Fatal("changed raw identity acquired source/memory permission", mutation)
						}
					})
				}
			})
		}
	}
}

func TestX86HighLowMoveCompleteTypedByteEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86HighLowMoveOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				text := row.op + " X0,X1"
				destination := 1
				if row.vector {
					text += ",X2"
					destination = 2
				}
				ins := x86ScalarLaneInstruction(t, text)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.dynamicMemory || len(effect.operands) != len(ins.Args) {
					t.Fatal("complete register-half byte effect missing", effect, known, err)
				}
				sourceMask, baseMask := uint64(0xff00), uint64(0xff00)
				if row.high {
					sourceMask, baseMask = 0xff, 0xff
				}
				for index, operand := range effect.operands {
					required := uint64(0)
					if index == 0 {
						required = sourceMask
					} else if index == 1 {
						required = baseMask
					}
					if operand.index != index || !reflect.DeepEqual(operand.operand, ins.Args[index]) || operand.width != 16 || operand.read != (index < 2) || operand.write != (index == destination) || operand.requiredBytes != required {
						t.Fatal("selected halves/base/write were conflated", index, operand)
					}
				}
				upper := x86TypedVectorUpperPreserve
				if row.vector {
					upper = x86TypedVectorUpperZero
				}
				if effect.vector.upperWrite != upper || effect.vector.memoryAlignment != 0 {
					t.Fatal("register move acquired memory alignment or wrong upper rule", effect.vector)
				}
			})
		}
	}
}

func TestX86HighLowMoveSelectedNUMAndUpperAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86HighLowMoveOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				text := row.op + " X0,X1"
				destination := 1
				if row.vector {
					text += ",X2"
					destination = 2
				}
				ins := x86ScalarLaneInstruction(t, text)
				for missing := -1; missing < 32; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.writeVector(0, 64, ^uint64(0), false)
					state.writeVector(1, 64, ^uint64(0), false)
					state.vectorUpper[destination] = 0x1a5a012345670000
					if missing >= 0 {
						state.xmm[missing/16] &^= 1 << uint(missing%16)
					}
					want := state.clone()
					first, base := state.vectorBytes(0), state.vectorBytes(1)
					defined := (first>>8)&0xff | base&0xff00
					if row.high {
						defined = (base & 0xff) | (first&0xff)<<8
					}
					want.xmm[destination] = uint16(defined)
					if row.vector {
						want.vectorUpper[destination] = ^uint64(0xffff)
					}
					if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
						t.Fatal("half selector invented NUM, changed FLAGS/DF or lost upper aliases", missing, state, want)
					}
				}
			})
		}
	}
}

func TestX86HighLowMoveInitializedPortableBytesAndAliases(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch, move, word, original := "amd64", "MOVQ", 8, "x86_64-unknown-linux-gnu"
	if strconv.IntSize == 32 {
		arch, move, word, original = "386", "MOVL", 4, "i386-unknown-linux-gnu"
	}
	var source, declarations, prototypes, checks strings.Builder
	var names []string
	for _, row := range x86HighLowMoveOracle {
		for _, alias := range []bool{false, true} {
			name := fmt.Sprint("HighLow", len(names))
			names = append(names, name)
			destination := "X1"
			if row.vector {
				destination = "X2"
			}
			if alias {
				destination = "X0"
			}
			instruction := row.op + " X0," + destination
			if row.vector {
				instruction = row.op + " X0,X1," + destination
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s a+0(FP),AX\n%s b+%d(FP),BX\n%s out+%d(FP),DX\nVMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (BX),Z2\n%s\nVMOVUPS Z%s,(DX)\nRET\n", name, 3*word, move, move, word, move, 2*word, instruction, destination[1:])
			fmt.Fprintf(&declarations, "func %s(a,b,out *[64]byte)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,const uint8_t*,uint8_t*);\n", name)
			high, vector, overlap := 0, 0, 0
			if row.high {
				high = 1
			}
			if row.vector {
				vector = 1
			}
			if alias {
				overlap = 1
			}
			fmt.Fprintf(&checks, "failed|=check(%s,\"%s\",%d,%d,%d);\n", name, name, high, vector, overlap)
		}
	}
	if len(names) != 8 {
		t.Fatal("complete half/alias directory changed", len(names))
	}
	// Preserve the eight named programs, then derive their raw counterparts
	// from actual Go bytes. No handwritten opcode bytes or C mnemonic oracle.
	rawSource := strings.ReplaceAll(source.String(), "HighLow", "RawHighLow")
	operations := map[string]bool{}
	for _, line := range strings.Split(source.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for _, row := range x86HighLowMoveOracle {
			if fields[0] == row.op {
				operations[line] = true
			}
		}
	}
	if len(operations) != 8 {
		t.Fatal("original named instructions lost a distinct alias", len(operations))
	}
	for instruction := range operations {
		rawSource = strings.ReplaceAll(rawSource, instruction+"\n", x86RawNumericalInstruction(t, arch, instruction))
	}
	source.WriteString(rawSource)
	declarations.WriteString(strings.ReplaceAll(declarations.String(), "HighLow", "RawHighLow"))
	prototypes.WriteString(strings.ReplaceAll(prototypes.String(), "HighLow", "RawHighLow"))
	checks.WriteString(strings.ReplaceAll(checks.String(), "HighLow", "RawHighLow"))
	for _, name := range append([]string(nil), names...) {
		names = append(names, "Raw"+name)
	}
	if len(names) != 16 {
		t.Fatal("complete named/raw directory changed", len(names))
	}
	x86LEAActualTargetGoObject(t, arch, original, source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() + x86HighLowMoveValueC + "int main(void){int failed=0;\n" + checks.String() + "return failed;}\n"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			x86CompactExpandRequireAllDefinitions(t, ir, names)
			for _, pipeline := range []struct {
				name, level string
				optimize    bool
			}{{"default-O0", "-O0", false}, {"default-O2", "-O2", false}, {"opt-O2", "-O2", true}} {
				t.Run(pipeline.name, func(t *testing.T) {
					text := ir
					if pipeline.optimize {
						text = x86DwordProductIROptimize(t, text)
					}
					execution.compileAndRunLLVM(t, "high-low-pure-byte-values", text, driver, pipeline.level)
				})
			}
		})
	}
	t.Log("actual-host translated integer bytes/aliases/canaries; original Go object only, no native SIMD execution claim")
}

const x86HighLowMoveValueC = `
static int check(void (*run)(const uint8_t*,const uint8_t*,uint8_t*),const char *name,int high,int vector,int overlap) {
    for(unsigned round=0;round<3;round++) {
        uint8_t a[64],b[64],out[66],want[64];
        for(unsigned i=0;i<64;i++) {a[i]=(uint8_t)(i*13+round*29+3);b[i]=(uint8_t)(0xe9-i*7-round*11);}
        memset(out,0x69,sizeof(out));
        const uint8_t *base=overlap&&!vector ? a:b;
        for(unsigned i=0;i<64;i++) want[i]=i<16 || !vector ? base[i]:0;
        for(unsigned i=0;i<8;i++) want[(high?8:0)+i]=a[(high?0:8)+i];
        run(a,b,out+1);
        if(out[0]!=0x69 || out[65]!=0x69 || memcmp(out+1,want,64)) {
            fprintf(stderr,"%s round=%u high=%d vector=%d overlap=%d\n",name,round,high,vector,overlap);
            for(unsigned i=0;i<64;i++) if(out[1+i]!=want[i]) fprintf(stderr,"byte=%u got=%x want=%x\n",i,out[1+i],want[i]);
            return 1;
        }
    }
    return 0;
}
`
