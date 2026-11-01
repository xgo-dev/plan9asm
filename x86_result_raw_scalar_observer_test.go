package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawScalarObserverOriginsAndEveryInputByte(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var rows []string
		for _, stem := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			widths := []string{"W", "L"}
			if arch == "amd64" {
				widths = append(widths, "Q")
			}
			for _, width := range widths {
				rows = append(rows, stem+width+" AX,BX")
			}
		}
		for _, op := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
			rows = append(rows, op+" X1,BX")
			if strings.HasPrefix(op, "V") {
				rows = append(rows, op+" Y1,BX")
			}
		}
		for _, row := range rows {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawScalarObserverSource(ins, arch) {
				t.Fatal("complete original count/mask source not recognized", row)
			}
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.gp[0], state.gp[3] = 0xff, 0x80
			state.writeVector(1, 64, ^uint64(0), false)
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"opcode", func(ins *Instr) {
					if strings.Contains(row, "CNT") {
						ins.Op = "TZCNTL"
						if ins.x86SourceRaw.op == "TZCNTL" {
							ins.Op = "LZCNTL"
						}
					} else {
						ins.Op = "VMOVMSKPS"
						if ins.x86SourceRaw.op == "VMOVMSKPS" {
							ins.Op = "VMOVMSKPD"
						}
					}
				}},
				{"operand", func(ins *Instr) { ins.Args[1].Reg = DX }},
				{"source-operand", func(ins *Instr) { ins.x86SourceRaw.args[1].Reg = DX }},
				{"vector", func(ins *Instr) { ins.x86VectorBytes = 64 }},
				{"address", func(ins *Instr) { ins.x86AddressBits = 32 }},
				{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
				{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
			} {
				t.Run(arch+"/"+row+"/"+control.name, func(t *testing.T) {
					changed, next := ins, state.clone()
					changed.Args = append([]Operand(nil), ins.Args...)
					origin := *ins.x86SourceRaw
					origin.args = append([]Operand(nil), origin.args...)
					changed.x86SourceRaw = &origin
					control.change(&changed)
					accepted, known := x86LoweredRawScalarObserverStep(changed, &next, nil, 0, arch)
					if accepted || known != (control.name != "origin") || x86RawScalarObserverSource(changed, arch) || !reflect.DeepEqual(state, next) {
						t.Fatal("changed source acquired a numerical/native role", accepted, known)
					}
				})
			}
			width := 16
			mask := !strings.Contains(row, "CNT")
			if mask {
				if ins.Args[0].Reg == "Y1" {
					width = 32
				}
			} else {
				width = 4
				if strings.HasSuffix(string(ins.Op), "W") {
					width = 2
				} else if strings.HasSuffix(string(ins.Op), "Q") {
					width = 8
				}
			}
			for missing := -1; missing < width; missing++ {
				t.Run(fmt.Sprintf("%s/%s/missing=%d", arch, row, missing), func(t *testing.T) {
					next := state.clone()
					if missing >= 0 {
						if mask {
							next.writeVector(1, 64, ^uint64(0)&^(1<<uint(missing)), false)
						} else {
							next.gp[0] &^= 1 << uint(missing)
						}
					}
					before := next.clone()
					accepted, known := x86LoweredRawScalarObserverStep(ins, &next, nil, 0, arch)
					if !known || accepted != (missing < 0) || !accepted && !reflect.DeepEqual(before, next) {
						t.Fatal("raw projection invented an input byte or mutated failed state", accepted, known)
					}
					if accepted {
						want := uint8(0xff)
						if width == 2 {
							want = 0x83
						}
						if next.gp[3] != want {
							t.Fatal("wrong exact GP write/zero-extension", next.gp[3], want)
						}
						before.gp[3] = want
						if !mask && !strings.HasPrefix(row, "POPCNT") {
							before.flags = x86ByteFlagCF | x86ByteFlagZF
						}
						if !reflect.DeepEqual(before, next) {
							t.Fatal("count/mask changed unrelated state or retained undefined FLAGS")
						}
					}
				})
			}
		}
	}
}

func TestX86RawScalarObserverDoesNotGrantMemoryOrMMXRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{"POPCNTW (DI),BX", "LZCNTL (DI),BX", "TZCNTL (DI),BX", "PMOVMSKB M1,BX"} {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			t.Run(arch+"/"+row, func(t *testing.T) {
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.gp[7] = 0xff        // A numerical DI is not an incoming pointer.
				state.nativeMMX[1] = 0xff // Bytes alone are not an x87/MMX owner.
				before := state.clone()
				accepted, known := x86LoweredRawScalarObserverStep(ins, &state, nil, 0, arch)
				if accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("raw count/mask acquired missing native address or physical MMX authority", accepted, known)
				}
				if strings.HasPrefix(row, "PMOVMSKB") && x86RawScalarObserverSource(ins, arch) {
					t.Fatal("ordinary numerical source allowed physical MMX input")
				}
			})
		}
	}
}

func x86RawNumericalInstruction(t *testing.T, arch, instruction string) string {
	t.Helper()
	code := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
	if len(code) < 2 || code[len(code)-1] != 0xc3 {
		t.Fatal("original numerical instruction lost its exact terminal near RET", instruction)
	}
	return x86DwordProductDirectives(code[:len(code)-1])
}

func TestX86RawScalarCountCompleteFamilyNativeObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			widths := []string{"W", "L", "Q"}
			if target.arch == "386" {
				word, move = 4, "MOVL"
				widths = widths[:2] // Q has no Go mode32 encoder row.
			}
			var source, declarations strings.Builder
			count := 0
			for _, stem := range []string{"POPCNT", "LZCNT", "TZCNT"} {
				for _, width := range widths {
					for _, memory := range []bool{false, true} {
						for _, raw := range []bool{false, true} {
							name, input := fmt.Sprintf("Count%d", count), "AX"
							if memory {
								input = "(BX)"
							}
							line := stem + width + " " + input + ",CX"
							if raw {
								line = x86RawNumericalInstruction(t, target.arch, line)
							}
							fmt.Fprintf(&declarations, "func %s(value uintptr,input *[8]byte) uintptr\n", name)
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s value+0(FP),AX\n%s input+%d(FP),BX\n%s $-1,CX\n%s\n%s CX,ret+%d(FP)\nRET\n",
								name, 3*word, move, move, word, move, line, move, 2*word)
							count++
						}
					}
				}
			}
			if count != 12*len(widths) {
				t.Fatal("incomplete scalar count matrix", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func TestX86RawMoveMaskCompleteFamilyNativeObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, op := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
				banks := []string{"X"}
				if strings.HasPrefix(op, "V") {
					banks = append(banks, "Y")
				}
				for _, bank := range banks {
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("Mask%d", count)
						line := op + " " + bank + "1,AX"
						if raw {
							line = x86RawNumericalInstruction(t, target.arch, line)
						}
						fmt.Fprintf(&declarations, "func %s(input *[32]byte) uintptr\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),BX\nVMOVDQU (BX),Y1\n%s\n%s AX,ret+%d(FP)\nRET\n",
							name, 2*word, move, line, move, word)
						count++
					}
				}
			}
			if count != 18 {
				t.Fatal("incomplete legacy/VEX X/Y move-mask matrix", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func x86RawNumericalFamilyObjects(t *testing.T, source, declarations, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86LEAActualTargetGoObject(t, arch, triple, "#include \"textflag.h\"\n"+source)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
		if err != nil {
			t.Fatal("complete raw numerical family lost its paired native inputs", api, err)
		}
		for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, text, level)
			}
		}
	}
}
