package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86NarrowCallerRows(t *testing.T) []string {
	t.Helper()
	rows := x86OfficialPackedNarrowRows(t, "amd64")
	for _, name := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB"} {
		rows = append(rows, name+" X0,X1", name+" (DI),X1")
	}
	if len(rows) != 98 {
		t.Fatalf("independent current Go narrow denominator changed: %d", len(rows))
	}
	return rows
}

func TestX86GoCallerPackedNarrowRecognizesEveryOfficialVectorForm(t *testing.T) {
	for _, row := range x86NarrowCallerRows(t) {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !x86CallerVectorMoveKnown(file.Funcs[0].Instrs[1]) {
				t.Fatal("accepted complete narrow grammar has no caller consumer")
			}
		})
	}
}

func TestX86GoCallerPackedNarrowActualTypedCallerAndObjects(t *testing.T) {
	for index, original := range x86NarrowCallerRows(t) {
		t.Run(fmt.Sprintf("%d/%s", index, original), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+original+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			var args []string
			for position, arg := range ins.Args {
				if arg.Kind == OpReg && amd64VectorByteWidth(arg.Reg) != 0 {
					// Rebind only the physical index; bank, memory, mask and
					// opcode attributes remain the independent Go row shape.
					arg.Reg = Reg(fmt.Sprintf("%c%d", arg.Reg[0], position))
				}
				if arg.Kind == OpMem {
					arg.Mem.Base, arg.Mem.Index, arg.Mem.Sym = DI, "", ""
					arg.Mem.Off, arg.Mem.Scale = 0, 0
				}
				args = append(args, arg.String())
			}
			row := string(ins.Op) + " " + strings.Join(args, ",")
			result := "X" + fmt.Sprint(len(ins.Args)-1)
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nVMOVUPS (SI),Z3\n" +
				"MOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal("actual typed caller/LLVM object consumer failed", err)
				}
			}
		})
	}
}

func TestX86GoCallerPackedNarrowIndependentPerOutputByteDependencies(t *testing.T) {
	for _, name := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB",
		"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		legacy := !strings.HasPrefix(name, "V")
		banks := []string{"X", "Y", "Z"}
		if legacy {
			banks = banks[:1]
		}
		inputBytes := 2
		if strings.HasSuffix(name, "DW") || name == "PACKSSLW" {
			inputBytes = 4
		}
		for bankIndex, bank := range banks {
			for _, mask := range []string{"", "merge", "zero"} {
				if legacy && mask != "" {
					continue
				}
				opcode, args := name, bank+"0,"+bank+"1"
				if !legacy {
					if mask != "" {
						args += ",K1"
					}
					if mask == "zero" {
						opcode += ".Z"
					}
					args += "," + bank + "2"
				}
				row := opcode + " " + args
				t.Run(row, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					width := 16 << bankIndex
					widthMask := x86CallerVectorByteMask(int64(width))
					for _, first := range []uint64{0, 1, 3, 15, 0xffff, 0xff00ff00ff00ff00, ^uint64(0)} {
						for _, second := range []uint64{0, 7, 0xffff, 0x5555555555555555, ^uint64(0)} {
							old := uint64(0xaaaaaaaaaaaaaaaa)
							destination := Reg("Z2")
							if legacy {
								destination, old = "Z1", second
							}
							state := &x86SourceStackState{
								vectors: map[Reg]uint64{"Z0": first, "Z1": second, "Z2": old},
								masks:   map[Reg]bool{"K1": true},
							}
							// Each 128-bit chunk contains second's narrowed
							// low half, then first's narrowed high half. One
							// missing input byte revokes its whole output lane.
							var want uint64
							for output := 0; output < width; output += inputBytes / 2 {
								chunk, local := output/16*16, output%16
								input, source := chunk+(local%8)/(inputBytes/2)*inputBytes, second
								if local >= 8 {
									source = first
								}
								needed := uint64(1<<uint(inputBytes)-1) << uint(input)
								if source&needed == needed {
									want |= uint64(1<<uint(inputBytes/2)-1) << uint(output)
								}
							}
							if mask == "merge" {
								want &= old
							}
							if legacy {
								want |= old &^ widthMask
							} else {
								want |= ^widthMask
							}
							if !x86CallerVectorMoveStep(&ins, state, nil) {
								t.Fatal("pure narrow byte consumer is unregistered")
							}
							if got := state.vectors[destination]; got != want {
								t.Fatalf("dependency/alias grant %s first=%x second=%x got=%x want=%x", row, first, second, got, want)
							}
						}
					}
				})
			}
		}
	}
}
