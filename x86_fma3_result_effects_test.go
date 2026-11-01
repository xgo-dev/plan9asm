package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86FMA3ResultInputState() x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	state.gp[5], state.pointerGP[7], state.callerAddressGP[7], state.masks[1] = 0x53, true, true, true
	for register := 0; register < 3; register++ {
		state.writeVector(register, 64, ^uint64(0), false)
	}
	return state
}

// These expectations use the independent Go syntax inventory and architectural
// operand roles, never amd64FMA3Specs. All three arithmetic inputs are needed
// in every 132/213/231 order, including the old destination under zero masking.
func TestX86FMA3CompleteNamedResultEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86FMA3NamedFormats(arch)
		for _, opcode := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				for _, row := range rows {
					if strings.Split(strings.Fields(row)[0], ".")[0] != opcode || strings.Contains(row, "(AX)") {
						continue
					}
					ins := x86ScalarLaneInstruction(t, row)
					width := map[byte]int{'X': 16, 'Y': 32, 'Z': 64}[ins.Args[0].Reg[0]]
					active := width
					scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
					if scalar {
						active = 4
						if strings.HasSuffix(opcode, "SD") {
							active = 8
						}
					}
					masked := len(ins.Args) == 4
					mandatory := x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, arch)
					for missing := -2; missing < 193; missing++ {
						state := x86FMA3ResultInputState()
						want := true
						if missing == -2 && scalar {
							// The other arithmetic inputs cannot supply upper-X bytes.
							low := x86CallerVectorByteMask(int64(active))
							state.writeVector(0, 64, low, false)
							state.writeVector(1, 64, low, false)
							state.writeVector(2, 64, low|0xa500, false)
						} else if missing == 192 {
							state.masks[1], want = false, !masked
						} else if missing >= 0 {
							register, bit := missing/64, uint(missing%64)
							state.writeVector(register, 64, state.vectorBytes(register)&^(uint64(1)<<bit), false)
							want = int(bit) >= active
						}
						before := state.clone()
						accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
						if accepted != want || !mandatory {
							t.Fatalf("%s missing=%d: accepted=%t want=%t mandatory=%t", row, missing, accepted, want, mandatory)
						}
						if accepted {
							known := ^uint64(0)
							if scalar {
								low := x86CallerVectorByteMask(int64(active))
								known = low | before.vectorBytes(2)&(0xffff&^low)
							}
							before.writeVector(2, width, known, false)
						}
						if !reflect.DeepEqual(state, before) {
							t.Fatal("FMA changed FLAGS, addresses, masks, unknown passthrough or unrelated banks", row, missing)
						}
					}
				}
			})
		}
	}
}

func x86FMA3InitializedSource(arch, name, row string, dead bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	bank := "X"
	for _, candidate := range []string{"Y", "Z"} {
		if strings.Contains(row, candidate+"1") {
			bank = candidate
		}
	}
	load := "MOVUPS"
	if bank != "X" {
		load = "VMOVUPS"
	}
	var source strings.Builder
	frame, declaration := word+4, fmt.Sprintf("func %s(p *byte) uint32\n", name)
	if dead {
		frame, declaration = word, fmt.Sprintf("func %s(p *byte)\n", name)
	}
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n", name, frame, move)
	for register := 0; register < 3; register++ {
		fmt.Fprintf(&source, "%s (AX),%s%d\n", load, bank, register)
	}
	source.WriteString("MOVL $85,CX\nKMOVW CX,K1\n")
	source.WriteString(row + "\n")
	if !dead {
		fmt.Fprintf(&source, "MOVL X2,AX\nMOVL AX,ret+%d(FP)\n", word)
	}
	source.WriteString("RET\n")
	return source.String(), declaration
}

func TestX86FMA3InitializedRegisterMemoryAndDeadPrograms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var entries, declarations []string
		for index, opcode := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
			for _, memory := range []bool{false, true} {
				for _, dead := range []bool{false, true} {
					first := "X0"
					if memory {
						first = "(AX)"
					}
					name := fmt.Sprintf("FMA%d_%t_%t", index, memory, dead)
					entry, declaration := x86FMA3InitializedSource(arch, name, opcode+" "+first+",X1,X2", dead)
					entries = append(entries, entry)
					declarations = append(declarations, declaration)
				}
			}
		}
		triple := x86AddressMemoryTargets(arch)[0]
		if len(entries) != 240 {
			t.Fatal("incomplete independent FMA3 register/memory/live/dead source inventory", len(entries))
		}
		for start := 0; start < len(entries); start += 40 {
			end := start + 40
			// Independent Go objects precede each bounded public capture.
			// This is source validity, not LLVM/native execution certification.
			source := strings.Join(entries[start:end], "")
			declaration := strings.Join(declarations[start:end], "")
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/batch%d/%s", arch, start/40, api), func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("genuinely initialized complete FMA3 source has no result/effect continuation", err)
					}
					for _, opcode := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
						want := strings.Count(source, "\n"+opcode+" ")
						if found := strings.Count(ir, "asm sideeffect \""+strings.ToLower(opcode)+" "); found != want {
							t.Fatal("public FMA3 lost original live or dead native instructions", opcode, found, want)
						}
					}
				})
			}
		}
	}
}

func TestX86FMA3DoesNotInventInputsOrPhysicalAuthority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				triple := x86AddressMemoryTargets(arch)[0]
				for _, opcode := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
					bare := "TEXT ·Value(SB),4,$0-0\n" + opcode + " X0,X1,X2\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, bare, "func Value()", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("dead FMA borrowed implementation-zero arithmetic inputs", opcode, err)
					}
				}
				for _, row := range []string{
					"VFMADD132PS X0,X1,X2", "VFNMADD213SD (AX),X1,X2",
					"VFNMSUB231SS.RZ_SAE.Z X0,X1,K1,X2",
				} {
					if arch == "386" && strings.Contains(row, "K1") {
						continue // Go's named four-operand mode32 boundary stays closed.
					}
					original, declaration := x86FMA3InitializedSource(arch, "Value", row, true)
					for _, missing := range []string{"first", "second", "old destination", "mask", "address", "FLAGS"} {
						changed := original
						load := "MOVUPS (AX),X"
						switch missing {
						case "first":
							if strings.Contains(row, "(AX)") {
								continue
							}
							changed = strings.Replace(changed, load+"0\n", "", 1)
						case "second":
							changed = strings.Replace(changed, load+"1\n", "", 1)
						case "old destination":
							changed = strings.Replace(changed, load+"2\n", "", 1)
						case "mask":
							if !strings.Contains(row, "K1") {
								continue
							}
							changed = strings.Replace(changed, "KMOVW CX,K1\n", "", 1)
						case "address":
							if !strings.Contains(row, "(AX)") {
								continue
							}
							changed = strings.Replace(changed, row, strings.Replace(row, "(AX)", "(BX)", 1), 1)
						case "FLAGS":
							changed = strings.Replace(changed, "RET\n", "SETCS DL\nRET\n", 1)
						}
						if changed == original {
							t.Fatal("independent missing-input control did not change source", missing, row)
						}
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("FMA acquired an absent numerical, address, mask or FLAGS fact", row, missing, err)
						}
					}
				}
			})
		}
		for _, row := range []string{
			"VFMADD132PH X0,X1,X2", "VFMADD213SH X0,X1,X2",
			"VFMADD231PS X0,X1,K0,X2", "VFMADD231SS.BCST (AX),X1,X2",
		} {
			ins := x86ScalarLaneInstruction(t, row)
			state := x86FMA3ResultInputState()
			before := state.clone()
			if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
				t.Fatal("named FMA borrowed raw FP16 or an illegal mask/broadcast role", arch, row)
			}
		}
		code := encodeX86VEXFMA3(0xb9, true, false, 2, 1, 0)
		raw, length, known, err := decodedX86VEXFMA3Instruction(code, map[string]int{"386": 32, "amd64": 64}[arch])
		if !known || err != nil || length != len(code) {
			t.Fatal("independent physical FMA prior failed", arch, err)
		}
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t,
			"TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n"), arch)
		if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 {
			t.Fatal("independent physical FMA lost its normalized source identity", arch, err)
		}
		raw = file.Funcs[0].Instrs[1]
		if raw.x86SourceRaw == nil {
			t.Fatal("physical FMA fixture has no original byte identity", arch)
		}
		state := x86FMA3ResultInputState()
		before := state.clone()
		if x86ScalarFPResultTransfer(raw, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
			t.Fatal("standalone physical instruction borrowed a named FMA source contract", arch)
		}
	}
}
