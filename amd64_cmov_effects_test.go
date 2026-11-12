package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86CMOVFamilyIndependentCallerSourceEffect(t *testing.T) {
	for _, row := range []string{"CMOVWCC BX,AX", "CMOVLLE BX,AX", "CMOVQPS BX,AX", "CMOVLLE (DI),AX"} {
		t.Run(row, func(t *testing.T) {
			body := "MOVQ $9,BX\nCMPQ AX,BX\n" + row + "\nMOVL AX,(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal("actual-Go conditional move has no complete caller source effect", err)
			}
		})
	}
}

func TestX86CMOVFamilyCompleteCallerAndPotentialInputGuards(t *testing.T) {
	for _, name := range x86CMOVOracleNames("amd64") {
		for _, test := range []struct {
			label, body string
			valid       bool
		}{
			{"register", "MOVQ $9,BX\nCMPQ AX,BX\n" + name + " BX,AX", true},
			{"self", "CMPQ AX,AX\n" + name + " AX,AX", true},
			{"readonly-memory", "CMPQ AX,AX\n" + name + " (DI),AX", true},
			{"undefined-source", "CMPQ AX,AX\n" + name + " BX,AX", false},
			{"undefined-old-target", "CMPQ AX,AX\n" + name + " AX,BX", false},
			{"incoming-pointer-source", "CMPQ AX,AX\n" + name + " DI,AX", false},
			{"incoming-pointer-target", "CMPQ AX,AX\n" + name + " AX,DI", false},
			{"pointer-flags", "CMPQ DI,DI\n" + name + " AX,AX", false},
			{"unknown-flags", name + " AX,AX", false},
			{"unknown-memory-pointer", "CMPQ AX,AX\n" + name + " (R8),AX", false},
			{"stack-register-source", "CMPQ AX,AX\n" + name + " SP,AX", false},
			{"frame-register-target", "CMPQ AX,AX\n" + name + " AX,BP", false},
			{"incoming-g", "CMPQ AX,AX\n" + name + " R14,AX", false},
		} {
			t.Run(name+"/"+test.label, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", test.body+"\nMOVL AX,(DX)", 1)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
				if test.valid && err != nil || !test.valid && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("potential source/old-target/flags or permission boundary", err)
				}
			})
		}
	}
}

func TestX86CMOVFamilyCompleteResultPotentialBytes(t *testing.T) {
	for _, name := range x86CMOVOracleNames("amd64") {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[name[4]]
		for _, source := range []string{"AX", "x+0(FP)"} {
			body := "MOVQ x+0(FP),AX\nMOVQ $9,BX\nCMPQ AX,BX\n" + name + " " + source + ",BX\nMOVQ BX,ret0+8(FP)\nRET"
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint64", body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatal("complete result family", name, source, err)
			}
		}
		for _, input := range []Reg{AX, BX} {
			for missing := 0; missing < 8; missing++ {
				t.Run(fmt.Sprintf("%s/%s/missing%d", name, input, missing), func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+name+" AX,BX\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					effect, known, err := x86TypedInstructionByteEffect(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], "amd64")
					if !known || err != nil {
						t.Fatal(err)
					}
					state := x86SourceStackState{numericFlags: true, known: map[Reg]uint8{AX: 0xff, BX: 0xff}, callers: map[Reg]x86CallerPointerValue{}}
					state.known[input] &^= 1 << uint(missing)
					before := state.known[input]
					_, valid := x86CallerConditionalMoveStep(&file.Funcs[0].Instrs[1], &state, nil)
					if valid != (missing >= width) {
						t.Fatal("each potential byte must exist, regardless of predicate", valid, width, effect)
					}
					if !valid && state.known[input] != before {
						t.Fatal("failed proof washed unknown bytes")
					}
					result := x86ResultState{flags: x86ByteFlagsAll}
					result.gp[0], result.gp[3] = 0xff, 0xff
					index := 0
					if input == BX {
						index = 3
					}
					result.gp[index] &^= 1 << uint(missing)
					beforeResult := result
					validResult := x86ResultTransfer(file.Funcs[0].Instrs[1], &result, nil, 0, "amd64")
					if validResult != (missing >= width) || !validResult && !reflect.DeepEqual(result, beforeResult) {
						t.Fatal("result observer borrowed potential undefined bytes or mutated a failed proof", validResult)
					}
					if validResult && width == 4 && result.gp[3] != 0xff {
						t.Fatal("L false-or-true writes did not define upper zero bytes")
					}
				})
			}
		}
	}
}

func TestX86CMOVFamilyExactRequiredFlagsAndUnconditionalFrameBytes(t *testing.T) {
	for _, name := range x86CMOVOracleNames("amd64") {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[name[4]]
		for _, source := range []string{"AX", "x+0(FP)", "local-8(SP)"} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$8-8\n"+name+" "+source+",BX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			flags := uint8(0)
			for _, condition := range x86CMOVOracleConditions {
				if strings.HasSuffix(name, condition.name) {
					flags = condition.flags
				}
			}
			for bit := uint8(1); bit <= x86ByteFlagOF; bit <<= 1 {
				state := x86ResultState{flags: x86ByteFlagsAll &^ bit, fp: make([]bool, 8), auto: make([]bool, 8)}
				state.gp[0], state.gp[3] = 0xff, 0xff
				owned := make([]bool, 8)
				for index := 0; index < 8; index++ {
					state.fp[index], state.auto[index], owned[index] = true, true, true
				}
				valid := x86ResultTransfer(ins, &state, owned, 8, "amd64")
				if valid != (flags&bit == 0) || valid && state.flags != x86ByteFlagsAll&^bit {
					t.Fatal("CMOV exact flag dependency/preservation", name, source, bit, valid)
				}
			}
			if source == "AX" {
				continue
			}
			for missing := 0; missing < 8; missing++ {
				state := x86ResultState{flags: x86ByteFlagsAll, fp: make([]bool, 8), auto: make([]bool, 8)}
				state.gp[0], state.gp[3] = 0xff, 0xff
				owned := make([]bool, 8)
				for index := 0; index < 8; index++ {
					state.fp[index], state.auto[index], owned[index] = true, true, true
				}
				state.fp[missing], state.auto[missing] = false, false
				if valid := x86ResultTransfer(ins, &state, owned, 8, "amd64"); valid != (missing >= width) {
					t.Fatal("CMOV condition cannot suppress a missing FP/AUTO source byte", name, source, missing, valid)
				}
			}
		}
	}
}

func TestX86CMOVFamilyCountedComparisonVersionGuards(t *testing.T) {
	base := x86CallerCountedLoopScalarAssembly(false)
	for _, destination := range []string{"BX", "CX", "AX"} {
		t.Run(destination, func(t *testing.T) {
			assembly := strings.Replace(base, "CMPL CX,AX\nJNE again", "CMPL CX,AX\nCMOVLLE R11,"+destination+"\nJNE again", 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("CMOV relaxed the exact adjacent comparison/latch or retained a stale counter/bound version", destination, err)
			}
		})
	}
}

func TestX86CMOVFamilyCountedNumberObserver(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\nCMOVLLE BX,AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	flags := x86CallerCountedFlags{pc: 7, op: "CMPL", known: true, equal: true}
	facts := x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{
		AX: {version: 2, value: 17, known: true}, BX: {version: 3, value: 23, known: true},
	}, flags: flags, source: -1}
	facts.step(8, 0, file.Funcs[0].Instrs[1], x86SourceStackState{}, nil)
	if facts.flags != flags {
		t.Fatal("CMOV changed existing numerical flag facts", facts.flags)
	}
	if _, retained := facts.regs[AX]; retained {
		t.Fatal("CMOV invented an unconditional selected numerical value or retained a stale target version")
	}
	if !facts.regs[BX].known || facts.regs[BX].version != 3 {
		t.Fatal("CMOV erased its unchanged source version")
	}
}

func TestX86CMOVFamilyIndependentResultByteEffect(t *testing.T) {
	for _, row := range []string{"CMOVWCC AX,BX", "CMOVLLE AX,BX", "CMOVQPS AX,BX", "CMOVLLE AX,AX"} {
		t.Run(row, func(t *testing.T) {
			result := "BX"
			if row == "CMOVLLE AX,AX" {
				result = "AX"
			}
			body := "MOVQ x+0(FP),AX\nMOVQ $9,BX\nCMPQ AX,BX\n" + row + "\nMOVQ " + result + ",ret0+8(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint64", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatal("actual-Go conditional move has no complete result byte effect", err)
			}
		})
	}
}

func TestX86CMOVFamilyIndependentDeadNativeRead(t *testing.T) {
	for _, row := range []string{"CMOVWCC (DI),BX", "CMOVLLE (DI),BX", "CMOVQPS (DI),BX"} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT ·Dead(SB),4,$0-0\nMOVQ $7,AX\nMOVQ $9,BX\nCMPQ AX,BX\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Dead()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original uninitialized DI acquired native memory permission", api, err)
				}
			}
			initialized := strings.Replace(source, "$0-0\n", "$0-8\nMOVQ p+0(FP),DI\n", 1)
			goAssemblerOracleOutput(t, "amd64", initialized, "", true)
			ir := x86NarrowOracleIR(t, initialized, "package cmov\nfunc Dead(p *byte)\n", "x86_64-unknown-linux-gnu")
			optimized := x86DwordProductIROptimize(t, ir)
			t.Logf("original loads=%t; actual IR default<O2> retains any read=%t", strings.Contains(ir, " = load "), strings.Contains(optimized, " = load "))
			if !strings.Contains(ir, "load volatile") || !strings.Contains(optimized, "load volatile") {
				t.Fatal("unconditional source read can disappear with a dead CMOV result under real IR default<O2>")
			}
		})
	}
}

func TestX86CMOVFamilyExactSourceMemoryCertificates(t *testing.T) {
	for _, name := range x86CMOVOracleNames("amd64") {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "CMPQ AX,AX\n"+name+" (DI),AX\nMOVL AX,(DX)", 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ins := range normalized.Funcs[0].Instrs {
			if ins.Op != Op(name) {
				continue
			}
			found = true
			access, exists := ins.x86CallerMemory[0]
			width := map[byte]int64{'W': 2, 'L': 4, 'Q': 8}[name[4]]
			if !exists || access.width != width || access.write || !x86CallerMemoryCertified(ins, 0) {
				t.Fatal("false condition shrank or omitted native source read", name, access)
			}
			for _, mutation := range []string{"opcode", "width", "direction", "offset", "destination", "source", "address-size", "segment"} {
				changed, certificate := ins, access
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.x86CallerMemory = map[int]x86CallerMemoryAccess{0: access}
				switch mutation {
				case "opcode":
					changed.Op = "CMOV" + Op(string(name[4])) + "CS"
					if changed.Op == ins.Op {
						changed.Op = "CMOV" + Op(string(name[4])) + "CC"
					}
				case "width":
					certificate.width--
					changed.x86CallerMemory[0] = certificate
				case "direction":
					certificate.write = true
					changed.x86CallerMemory[0] = certificate
				case "offset":
					changed.Args[0].Mem.Off++
				case "destination":
					changed.Args[1].Reg = BX
				case "source":
					changed.Args[0].Mem.Base = SI
				case "address-size":
					changed.x86AddressBits = 32
				case "segment":
					changed.Args[0].Mem.Segment = FS
				}
				if x86CallerMemoryCertified(changed, 0) {
					t.Fatal("stale source or native extent survived", name, mutation)
				}
			}
		}
		if !found {
			t.Fatal("source normalization omitted family instruction", name)
		}
	}
}
