package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalScalarLaneCases() []string {
	var rows []string
	for _, prefix := range []string{"", "V"} {
		for _, suffix := range []string{"B", "W", "D", "Q"} {
			for _, selector := range []int{0, 255} {
				for _, transfer := range []string{"AX", "65(BP)", "1(SI)"} {
					insert := fmt.Sprintf("%sPINSR%s $%d,%s,X1", prefix, suffix, selector, transfer)
					if prefix != "" {
						insert += ",X2"
					}
					rows = append(rows, insert, fmt.Sprintf("%sPEXTR%s $%d,X1,%s", prefix, suffix, selector, transfer))
				}
				if prefix != "" {
					rows = append(rows, fmt.Sprintf("VPINSR%s $%d,AX,X1,X1", suffix, selector))
				} else if suffix != "W" {
					// These Go Ymm spellings encode GP registers, not MMX reads.
					rows = append(rows, fmt.Sprintf("PINSR%s $%d,M0,X1", suffix, selector),
						fmt.Sprintf("PEXTR%s $%d,X1,M0", suffix, selector))
				}
			}
			if prefix != "" {
				rows = append(rows, fmt.Sprintf("VPEXTR%s $-128,X1,AX", suffix), fmt.Sprintf("VPEXTR%s $-1,X1,65(BP)", suffix))
			}
			// Only the inserted lane is observed. Unrelated old X7 bytes
			// remain unknown through lowering as well as the direct proof.
			partial := fmt.Sprintf("%sPINSR%s $255,AX,X7", prefix, suffix)
			if prefix != "" {
				partial += ",X7"
			}
			rows = append(rows, partial+fmt.Sprintf("\n%sPEXTR%s $255,X7,AX\nMOVQ AX,128(BP)", prefix, suffix))
		}
	}
	return rows
}

func TestGoAMD64FixedLocalScalarLaneCompleteFamilies(t *testing.T) {
	rows := fixedLocalScalarLaneCases()
	if len(rows) != 132 {
		t.Fatal("scalar-lane source/selector/alias inventory changed", len(rows))
	}
	var original strings.Builder
	for index, row := range rows {
		original.WriteString(strings.Replace(fixedLocalVEXAssembly(row), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("original Go scalar-lane source lacks fixed-local support", err)
			}
			if !strings.Contains(row, "\n") && strings.Contains(row, "(BP)") {
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$256-0\n"+row+"\nRET\n")
				if err != nil || !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
					t.Fatal("isolated physical scalar-lane access did not request frame capture", err)
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalScalarLaneInsertDefinedBytes(t *testing.T) {
	for _, prefix := range []string{"", "V"} {
		for size, suffix := range []string{"B", "W", "D", "Q"} {
			width := 1 << uint(size)
			for _, destination := range []string{"X1", "X2"} {
				if prefix == "" && destination != "X1" {
					continue
				}
				t.Run(prefix+suffix+"/"+destination, func(t *testing.T) {
					for immediate := 0; immediate < 256; immediate++ {
						row := fmt.Sprintf("%sPINSR%s $%d,AX,X1", prefix, suffix, immediate)
						if prefix != "" {
							row += "," + destination
						}
						ins := x86ScalarLaneInstruction(t, row)
						root := x86CallerVectorRoot(Reg(destination))
						offset := (immediate % (16 / width)) * width
						selected := (uint64(1)<<uint(width) - 1) << uint(offset)
						for missing := -1; missing < 8; missing++ {
							state := x86FixedLocalState{
								known: map[Reg]uint8{AX: 255}, vectors: map[Reg]uint64{"Z1": 0x1000000000005555, "Z2": 0x200000000000aaaa},
								flags: x86ByteFlagsAll,
							}
							if missing >= 0 {
								state.known[AX] &^= 1 << uint(missing)
							}
							input := state.known[AX]
							old := state.vectors[root]
							err := fixedLocalStep(&ins, &state, FuncSig{}, nil, 0)
							if missing >= 0 && missing < width {
								if !errors.Is(err, ErrProbeNeedsContext) || state.vectors[root] != old {
									t.Fatal("undefined GP source acquired vector bytes", row, missing, err)
								}
								continue
							}
							want := uint64(0x5555)&^selected | selected
							if prefix == "" {
								want |= old &^ 0xffff
							} else {
								want |= ^uint64(0xffff)
							}
							if err != nil || state.vectors[root] != want || state.flags != x86ByteFlagsAll || state.known[AX] != input {
								t.Fatal("insert lost preserved unknown lanes, upper aliases or FLAGS", row, missing, err, state)
							}
							if destination == "X2" && state.vectors["Z1"] != 0x1000000000005555 {
								t.Fatal("insert changed its separate base register", row)
							}
						}
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalScalarLaneExtractSelectedBytes(t *testing.T) {
	for _, prefix := range []string{"", "V"} {
		for size, suffix := range []string{"B", "W", "D", "Q"} {
			width := 1 << uint(size)
			t.Run(prefix+suffix, func(t *testing.T) {
				for immediate := 0; immediate < 256; immediate++ {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%sPEXTR%s $%d,X1,AX", prefix, suffix, immediate))
					offset := (immediate % (16 / width)) * width
					selected := (uint64(1)<<uint(width) - 1) << uint(offset)
					for missing := -1; missing < 16; missing++ {
						state := x86FixedLocalState{
							known: map[Reg]uint8{}, booleans: map[Reg]uint8{AX: 255}, constants: map[Reg]int64{AX: 42},
							vectors: map[Reg]uint64{"Z1": selected | 1<<60}, flags: x86ByteFlagsAll,
						}
						if missing >= 0 {
							state.vectors["Z1"] &^= 1 << uint(missing)
						}
						before := state.vectors["Z1"]
						err := fixedLocalStep(&ins, &state, FuncSig{}, nil, 0)
						if missing >= offset && missing < offset+width {
							if !errors.Is(err, ErrProbeNeedsContext) || state.known[AX] != 0 {
								t.Fatal("undefined selected lane acquired GP result", ins, missing, err)
							}
							continue
						}
						_, constant := state.constants[AX]
						zeroBytes := uint8(0xf0)
						if width == 8 {
							zeroBytes = 0
						}
						if err != nil || state.known[AX] != 255 || constant || state.booleans[AX] != zeroBytes || state.vectors["Z1"] != before || state.flags != x86ByteFlagsAll {
							t.Fatal("extract read unselected bytes or changed unrelated state", ins, missing, err, state)
						}
					}
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalScalarLaneExactMemory(t *testing.T) {
	for _, prefix := range []string{"", "V"} {
		for size, suffix := range []string{"B", "W", "D", "Q"} {
			width := 1 << uint(size)
			for _, insert := range []bool{false, true} {
				row, memory := prefix+"PEXTR"+suffix+" $255,X1,(BP)", 2
				if insert {
					row, memory = prefix+"PINSR"+suffix+" $255,(BP),X1", 1
					if prefix != "" {
						row += ",X2"
					}
				}
				t.Run(row, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row)
					native := x86FixedLocalState{
						opaque: map[Reg]x86FixedLocalOrigins{BP: fixedLocalOrigin(x86FixedLocalOrigin{})}, vectors: map[Reg]uint64{"Z1": 0xffff},
						bytes: newFixedLocalByteSet(32), flags: x86ByteFlagsAll,
					}
					proof := &x86FixedLocalProof{frame: 32}
					if err := fixedLocalStep(&ins, &native, FuncSig{}, proof, 0); err != nil {
						t.Fatal("ordinary native scalar access was rejected", err)
					}
					access := ins.x86FixedLocalMemory[memory]
					if access.owner != proof || access.width != int64(width) || access.write == insert || !access.nativeInput || native.flags != x86ByteFlagsAll {
						t.Fatal("native scalar role became private extent or wrong width", access)
					}
					for index := int64(0); index < 32; index++ {
						if native.bytes.has(index) {
							t.Fatal("native access acquired private initialized bytes")
						}
					}
					for _, offset := range []int{1, 32 - width, 33 - width} {
						for missing := -1; missing < 32; missing++ {
							ins := x86ScalarLaneInstruction(t, row)
							state := x86FixedLocalState{
								pointers: map[Reg]int64{BP: int64(offset)}, vectors: map[Reg]uint64{"Z1": 0xffff},
								bytes: newFixedLocalByteSet(32), booleanBytes: newFixedLocalByteSet(32), flags: x86ByteFlagsAll,
							}
							for index := 0; index < 32; index++ {
								state.bytes.set(int64(index), index != missing)
							}
							proof := &x86FixedLocalProof{frame: 32}
							err := fixedLocalStep(&ins, &state, FuncSig{}, proof, 0)
							wantPass := offset+width <= 32 && (!insert || missing < offset || missing >= offset+width)
							if (err == nil) != wantPass || !wantPass && !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("exact native tuple/initialization mismatch", offset, missing, err)
							}
							if wantPass {
								access := ins.x86FixedLocalMemory[memory]
								if access.owner != proof || access.width != int64(width) || access.write == insert || access.nativeInput || state.flags != x86ByteFlagsAll {
									t.Fatal("scalar memory certificate widened or changed FLAGS", access)
								}
							}
							if missing >= 0 && state.bytes.has(int64(missing)) != (wantPass && !insert && missing >= offset && missing < offset+width) {
								t.Fatal("unrelated private byte initialized", offset, missing, err)
							}
						}
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalScalarLaneBoundaries(t *testing.T) {
	for _, row := range []string{
		"PINSRB $0,SI,X1", "PINSRQ $0,BP,X1", "PINSRB $0,R15,X1",
		"PINSRB $0,(AX),X1", "PINSRQ $0,256(BP),X1", "PEXTRQ $0,X1,256(BP)",
		"PINSRB $0,a+8(FP),X1", "PEXTRB $0,X1,a+8(FP)", "PEXTRB $0,X1,(AX)",
		"PEXTRB $0,X7,AX", "PINSRB $0,AX,X7\nPEXTRB $1,X7,AX",
		"PINSRB $0,AX,X7\nMOVOU X7,128(BP)", "PEXTRQ $0,X1,SP", "PEXTRD $0,X1,BP",
		"PINSRW $0,M0,X1", "PEXTRW $0,X1,M0", "VPINSRB $0,M0,X1,X2",
		"VPINSRB $0,AX,X1,X16", "VPEXTRB $0,X16,AX", "VPINSRD $0,AX,X1,K1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound scalar-lane form acquired frame permissions", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalScalarLaneObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := fixedLocalScalarLaneCases()
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(row), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64, a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
