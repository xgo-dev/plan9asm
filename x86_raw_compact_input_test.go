package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86RawCompactInputObjects(t *testing.T, bank string, expand bool) {
	t.Helper()
	members := []string{"VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ", "VCOMPRESSPS", "VCOMPRESSPD"}
	if expand {
		members = []string{"VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ", "VEXPANDPS", "VEXPANDPD"}
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, suffix := goWordSize(target.arch), "Q"
			if word == 4 {
				suffix = "L"
			}
			var source, declarations strings.Builder
			count := 0
			for _, member := range members {
				for _, memory := range []bool{false, true} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if memory && !expand && mode == "zero" {
							continue // Reserved EVEX.z memory stores have their own #UD oracle.
						}
						op, mask := member, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							op += ".Z"
						}
						first, last := bank+"2", bank+"3"
						if memory {
							if expand {
								first = "1(SI)"
							} else {
								last = "1(DI)"
							}
						}
						row := op + " " + first + "," + mask + last
						// The low-bank bytes have the same physical meaning in both
						// modes; Go's named frontend is not the raw decoder oracle.
						literal := x86RawNumericalInstruction(t, "amd64", row)
						name := fmt.Sprint("Compact", count)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n"+
							"MOV%s out+0(FP),DI\nMOV%s input+%d(FP),SI\nMOV%s old+%d(FP),BX\n"+
							"VMOVUPS (SI),Z2\nVMOVUPS (BX),Z3\nKXNORQ K1,K1,K1\n"+
							"%s\nVMOVUPS Z3,65(DI)\nRET\n", name, 3*word,
							suffix, suffix, word, suffix, 2*word, literal)
						fmt.Fprintf(&declarations, "func %s(out *[144]byte,input,old *[64]byte)\n", name)
						count++
					}
				}
			}
			want := 30
			if expand {
				want = 36
			}
			if count != want {
				t.Fatal("independent full raw compact/expand inventory changed", count, want)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func TestX86RawCompressCompleteXInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "X", false)
}

func TestX86RawCompressCompleteYInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "Y", false)
}

func TestX86RawCompressCompleteZInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "Z", false)
}

func TestX86RawExpandCompleteXInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "X", true)
}

func TestX86RawExpandCompleteYInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "Y", true)
}

func TestX86RawExpandCompleteZInputObjects(t *testing.T) {
	x86RawCompactInputObjects(t, "Z", true)
}

func TestX86RawCompactPhysicalMode32Masks(t *testing.T) {
	count := 0
	for _, member := range []string{
		"VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ", "VCOMPRESSPS", "VCOMPRESSPD",
		"VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ", "VEXPANDPS", "VEXPANDPD",
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for mask := 1; mask <= 7; mask++ {
				row := fmt.Sprintf("%s %s2,K%d,%s3", member, bank, mask, bank)
				literal := x86RawNumericalInstruction(t, "amd64", row)
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+literal+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, "386")
				if err != nil {
					t.Fatal("valid physical low-bank encoding inherited a named frontend limit", row, err)
				}
				ins := file.Funcs[0].Instrs[1]
				form, known, err := x86PackedCompactProperties(ins.Op, ins, "386")
				if !known || err != nil || form.mask != 1 || ins.Args[1].Reg != Reg(fmt.Sprint("K", mask)) {
					t.Fatal("raw mask/operand identity changed", row, form, err)
				}
				count++
			}
		}
	}
	if count != 252 {
		t.Fatal("complete physical compact mask inventory changed", count)
	}
}

func TestX86RawCompactDeadInputsCannotBorrowVoidOrBool(t *testing.T) {
	for _, member := range []string{
		"VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ", "VCOMPRESSPS", "VCOMPRESSPD",
		"VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ", "VEXPANDPS", "VEXPANDPD",
	} {
		for _, memory := range []bool{false, true} {
			first, last := "X2", "X3"
			if memory {
				if strings.Contains(member, "EXPAND") {
					first = "(SI)"
				} else {
					last = "(DI)"
				}
			}
			literal := x86RawNumericalInstruction(t, "amd64", member+" "+first+",K1,"+last)
			for _, target := range x86RawReturnTargets {
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						source := "TEXT ·Value(SB),4,$0\n" + literal + "RET\n"
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw compact inputs borrowed an implementation zero", target, member, memory, api, err)
						}
					}
				}
			}
		}
	}
}

func TestX86RawCompactOriginalIdentityAndEveryInputByte(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86CompactExpandResultMembers {
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				for _, mode := range []string{"merge", "zero"} {
					t.Run(arch+"/"+member+"/"+width.bank+"/"+mode, func(t *testing.T) {
						op := member
						if mode == "zero" {
							op += ".Z"
						}
						row := fmt.Sprintf("%s %s2,K1,%s3", op, width.bank, width.bank)
						literal := x86RawNumericalInstruction(t, "amd64", row)
						file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+literal+"RET\n")
						if err != nil {
							t.Fatal(err)
						}
						file, err = normalizeX86RawFile(file, arch)
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.masks[1] = true
						state.writeVector(2, 64, ^uint64(0), false)
						state.writeVector(4, 64, ^uint64(0), false)
						if mode == "merge" {
							state.writeVector(3, 64, ^uint64(0), false)
						}
						before := state.clone()
						if accepted, known := x86ResultCompactExpandMemoryStep(ins, &state, nil, 0, arch, true); !known || !accepted {
							t.Fatal("complete physical inputs lost their paired continuation", row)
						}
						expected := before.clone()
						expected.writeVector(3, width.bytes, x86CallerVectorByteMask(int64(width.bytes)), false)
						if !reflect.DeepEqual(state, expected) {
							t.Fatal("raw compact changed unrelated state or failed to clear wider aliases")
						}
						strict := before.clone()
						if accepted, known := x86ResultCompactExpandMemoryStep(ins, &strict, nil, 0, arch, false); !known || accepted || !reflect.DeepEqual(strict, before) {
							t.Fatal("standalone observer borrowed a lowering-only raw view")
						}
						for _, input := range []int{2, 3} {
							if input == 3 && mode == "zero" {
								continue // Zeroing does not consume old merge bytes.
							}
							for missing := 0; missing < width.bytes; missing++ {
								current := before.clone()
								current.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
								initial := current.clone()
								if accepted, known := x86ResultCompactExpandMemoryStep(ins, &current, nil, 0, arch, true); !known || accepted || !reflect.DeepEqual(current, initial) {
									t.Fatal("raw compact consumed a missing input byte", input, missing)
								}
							}
						}
						for _, mutation := range []string{"mask", "record", "opcode", "operand", "vector-width", "address-size", "override", "segment", "RIP"} {
							changed, current := ins, before.clone()
							changed.Args = append([]Operand(nil), ins.Args...)
							switch mutation {
							case "mask":
								current.masks[1] = false
							case "record":
								// Keep an encoded origin while removing its record.
								// Removing both denotes an ordinary valid named row.
								changed.x86Encoded = true
								changed.x86SourceRaw = nil
							case "opcode":
								changed.Op = Op(member + ".Z")
								if mode == "zero" {
									changed.Op = Op(member)
								}
							case "operand":
								changed.Args[0].Reg = Reg(width.bank + "4")
							case "vector-width":
								changed.x86VectorBytes ^= 16
							case "address-size":
								changed.x86AddressBits = 16
							case "override":
								changed.x86UnboundAddressOverride = true
							case "segment":
								changed.x86SegmentPrefix = 0x64
							case "RIP":
								changed.x86RIPLiteral = true
							}
							initial := current.clone()
							if accepted, known := x86ResultCompactExpandMemoryStep(changed, &current, nil, 0, arch, true); !known || accepted || !reflect.DeepEqual(current, initial) {
								t.Fatal("unbound raw origin or mask changed numerical state", mutation)
							}
						}
					})
				}
			}
		}
	}
}
