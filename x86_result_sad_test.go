package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent Go inventory: legacy X, VPSADBW X/Y/Z, VMPSADBW X/Y,
// and VDBPSADBW X/Y/Z with optional merge/zero masks. Go's mode32
// frontend has no four/five-operand immediate vector spelling.
func x86SADValueRows(arch string) []struct{ op, bank, mode string } {
	var rows []struct{ op, bank, mode string }
	for _, op := range []string{"PSADBW", "MPSADBW", "VPSADBW", "VMPSADBW", "VDBPSADBW"} {
		if arch == "386" && (op == "VMPSADBW" || op == "VDBPSADBW") {
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			if !strings.HasPrefix(op, "V") && bank != "X" || op == "VMPSADBW" && bank == "Z" {
				continue
			}
			for _, mode := range []string{"plain", "merge", "zero"} {
				if mode != "plain" && op != "VDBPSADBW" {
					continue
				}
				rows = append(rows, struct{ op, bank, mode string }{op, bank, mode})
			}
		}
	}
	return rows
}

func x86SADValueInstruction(op, bank, mode, first string, control int) string {
	name, args := op, first+","+bank+"1"
	if strings.HasPrefix(op, "V") {
		if mode != "plain" {
			args += ",K1"
		}
		args += "," + bank + "2"
	}
	if mode == "zero" {
		name += ".Z"
	}
	if op != "PSADBW" && op != "VPSADBW" {
		args = fmt.Sprintf("$%d,", control) + args
	}
	return name + " " + args
}

func TestX86SADNumericalInputsAndAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86SADValueRows(arch) {
			t.Run(arch+"/"+row.op+"/"+row.bank+"/"+row.mode, func(t *testing.T) {
				width := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank]
				for control := 0; control < 256; control++ {
					ins := x86ScalarLaneInstruction(t, x86SADValueInstruction(row.op, row.bank, row.mode, row.bank+"0", control))
					// Derive dependencies by perturbing a separate numerical oracle,
					// never by reading the implementation's word-input masks.
					var required [2]uint64
					for input := 0; input < width; input++ {
						for source := range required {
							a, b := make([]byte, width), make([]byte, width)
							if source == 0 {
								a[input] = 1
							} else {
								b[input] = 1
							}
							for _, value := range x86SADReference(row.op, width, control, a, b) {
								if value != 0 {
									required[source] |= uint64(1) << uint(input)
								}
							}
						}
					}
					for missing := -1; missing < 2*width; missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[3], state.pointerGP[7], state.callerAddressGP[7] = 0x53, true, true
						state.masks[1] = true
						for index := 0; index < 3; index++ {
							state.xmm[index], state.vectorUpper[index] = 0xffff, ^uint64(0xffff)
						}
						want := true
						if missing >= 0 {
							index, bit := missing/width, uint(missing%width)
							bits := state.vectorBytes(index) &^ (uint64(1) << bit)
							state.xmm[index], state.vectorUpper[index] = uint16(bits), bits&^0xffff
							want = required[index]&(uint64(1)<<bit) == 0
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						if accepted != want {
							t.Fatalf("imm%d missing%d accepted=%t want=%t", control, missing, accepted, want)
						}
						if want {
							destination := 2
							if !strings.HasPrefix(row.op, "V") {
								destination = 1
							}
							before.writeVector(destination, width, x86CallerVectorByteMask(int64(width)), !strings.HasPrefix(row.op, "V"))
						}
						if !reflect.DeepEqual(state, before) {
							t.Fatal("SAD changed unrelated state or partially accepted missing inputs")
						}
					}
				}
			})
		}
	}
}

func TestX86SADUnknownVoidInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86SADValueRows(arch) {
			instruction := x86SADValueInstruction(row.op, row.bank, row.mode, row.bank+"0", 37)
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				original := "TEXT ·Value(SB),4,$0\n" + instruction + "\nRET\n"
				x86LEAActualTargetGoObject(t, arch, triple, original)
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, original, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead SAD output invented input data", declaration, api, err)
						}
					}
				}
			})
		}
	}
}

func TestX86SADSameSourceBlockConstants(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"PSADBW", "VPSADBW"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				if op == "PSADBW" && bank != "X" {
					continue
				}
				for source := 0; source < 8; source++ {
					for destination := 0; destination < 8; destination++ {
						if op == "PSADBW" && source != destination {
							continue
						}
						instruction := fmt.Sprintf("%s %s%d,%s%d", op, bank, source, bank, source)
						if op == "VPSADBW" {
							instruction += fmt.Sprintf(",%s%d", bank, destination)
						}
						state := x86ResultState{flags: x86ByteFlagAF}
						before := state.clone()
						width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
						before.writeVector(destination, width, x86CallerVectorByteMask(int64(width)), op == "PSADBW")
						if !x86ResultTransfer(x86ScalarLaneInstruction(t, instruction), &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
							t.Fatal("same-byte absolute differences require no incoming values", arch, instruction)
						}
						ins := x86ScalarLaneInstruction(t, instruction)
						form, _, err := x86PackedSADProperties(ins, arch)
						caller := &x86SourceStackState{vectors: map[Reg]uint64{}}
						if err != nil || !x86CallerSADStep(&ins, form, caller, nil) ||
							caller.vectors[Reg(fmt.Sprintf("Z%d", destination))] != before.vectorBytes(destination) {
							t.Fatal("caller and result disagree on the input-independent zero", arch, instruction, err)
						}
					}
				}
			}
		}
	}
	for _, instruction := range []string{"MPSADBW $0,X0,X0", "VMPSADBW $0,Y0,Y0,Y1", "VDBPSADBW $0,Z0,Z0,Z1"} {
		state := x86ResultState{}
		if x86ResultTransfer(x86ScalarLaneInstruction(t, instruction), &state, nil, 0, "amd64") {
			t.Fatal("sliding/shuffled SAD invented a same-source constant", instruction)
		}
	}
}

func TestX86SADInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := int(goWordSize(target.arch)), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			for _, instruction := range []string{"PSADBW X0,X0", "VPSADBW X0,X0,X0", "VPSADBW Y0,Y0,Y0", "VPSADBW Z0,Z0,Z0"} {
				name := "constant" + strings.NewReplacer(" ", "", ",", "").Replace(instruction)
				fmt.Fprintf(&declarations, "func %s() uint32\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n%s\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n", name, instruction)
			}
			for _, row := range x86SADValueRows(target.arch) {
				for _, memory := range []bool{false, true} {
					name := fmt.Sprintf("%s%s%s%t", row.op, row.bank, row.mode, memory)
					first := row.bank + "0"
					if memory {
						first = "3(AX)(DX*2)"
					}
					fmt.Fprintf(&declarations, "func %s(p *[128]byte,mask uintptr) uint32\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s mask+%d(FP),CX\nKMOVD CX,K1\n"+
						"MOVL $1,DX\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\n",
						name, 2*word+4, move, move, word, x86SADValueInstruction(row.op, row.bank, row.mode, first, 37))
					destination := "X2"
					if !strings.HasPrefix(row.op, "V") {
						destination = "X1"
					}
					fmt.Fprintf(&source, "PEXTRD $0,%s,AX\nMOVL AX,ret+%d(FP)\nRET\n", destination, 2*word)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete SAD input lost its numerical continuation", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86SADNativeInputsStayIndependent(t *testing.T) {
	for _, row := range x86SADValueRows("amd64") {
		instruction := x86SADValueInstruction(row.op, row.bank, row.mode, "3(AX)(DX*2)", 37)
		original := "TEXT ·Value(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ mask+8(FP),CX\nKMOVD CX,K1\n" +
			"MOVL $1,DX\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n" + instruction + "\nRET\n"
		declaration := "func Value(p *[128]byte,mask uintptr)"
		variants := []struct{ name, source string }{
			{"complete", original},
			{"unknown-pointer", strings.Replace(original, "p+0(FP),AX", "p+0(FP),DI", 1)},
			{"numeric-pointer", strings.Replace(original, "MOVQ p+0(FP),AX", "MOVQ $42,AX", 1)},
			{"unknown-index", strings.Replace(original, "MOVL $1,DX\n", "", 1)},
			{"unknown-second", strings.Replace(original, "VPXORD Z1,Z1,Z1\n", "", 1)},
		}
		if row.mode != "plain" {
			variants = append(variants, struct{ name, source string }{"unknown-mask", strings.Replace(original, "KMOVD CX,K1\n", "", 1)})
		}
		if row.mode == "merge" {
			variants = append(variants, struct{ name, source string }{"unknown-merge", strings.Replace(original, "VPXORD Z2,Z2,Z2\n", "", 1)})
		}
		for _, variant := range variants {
			t.Run(row.op+"/"+row.bank+"/"+row.mode+"/"+variant.name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, variant.source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if variant.name == "complete" {
						if err != nil || ir == "" {
							t.Fatal("complete native SAD inputs rejected", api, err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("SAD acquired unknown memory/vector/mask inputs", api, err)
					}
				}
			})
		}
	}
}
