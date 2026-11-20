package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86MOVQSourceAliasesCountedNumericalOrigins(t *testing.T) {
	before := x86SourceStackState{callers: map[Reg]x86CallerPointerValue{
		CX: {argument: 0}, SI: {argument: 1},
	}}
	proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{
		{kind: x86CallerLocalLength, width: 8}, {kind: x86CallerSliceInput, width: 4},
	}}
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, row := range []string{"$0,AX", "$4294967296,AX", "$-1,AX", "R9,AX", "R9,R9", "R12,AX", "(CX),AX", "(SI),AX"} {
			t.Run(alias+"/"+row, func(t *testing.T) {
				instruction := x86PureGPUnknownInstruction(t, alias+" "+row)
				original := instruction
				goAssemblerOracleOutput(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction.Raw+"\nRET\n", "", true)
				canonical := instruction
				canonical.Op = "MOVQ"
				want := x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{
					"R9": {source: 7, mask: 3, value: 2, known: true, version: 4},
				}, source: 7, sequence: 8, flags: x86CallerCountedFlags{known: true, equal: true}}
				got := want.clone()
				want.step(9, 2, canonical, before, proof)
				got.step(9, 2, instruction, before, proof)
				if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(instruction, original) {
					t.Fatalf("source alias changed complete numeric origin/value/version/flags or original identity: got=%+v want=%+v", got, want)
				}
				if row == "$4294967296,AX" && (!got.regs[AX].known || got.regs[AX].value != 1<<32) {
					t.Fatal("qword alias truncated its high half")
				}
				if row == "R12,AX" || row == "(SI),AX" {
					if _, present := got.regs[AX]; present {
						t.Fatal("unknown/non-length source acquired a numerical origin")
					}
				}
				for _, raw := range []string{"encoded", "source raw"} {
					physical := instruction
					if raw == "encoded" {
						physical.x86Encoded = true
					} else {
						physical.x86SourceRaw = &x86SourceRawInstruction{op: instruction.Op, args: instruction.Args}
					}
					state := x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{}, source: -1}
					state.step(9, 2, physical, before, proof)
					if len(state.regs) != 0 || state.source != -1 {
						t.Fatal("raw origin borrowed named source alias semantics", raw, state)
					}
				}
			})
		}
	}
}

func x86SourceAliasCountedAssembly(original, alias string) string {
	// Exercise full-word bound copies and zero counter definitions as well as
	// source length/pointer imports. Actual raw guard/latch instructions stay raw.
	assembly := strings.NewReplacer("MOVL R9,AX", "MOVQ R9,AX", "MOVL R9,R13", "MOVQ R9,R13",
		"XORL CX,CX", "MOVQ $0,CX", "XORL R12,R12", "MOVQ $0,R12").Replace(original)
	return x86SourceMOVQSpelling(assembly, alias)
}

func x86SourceMOVQSpelling(assembly, alias string) string {
	lines := strings.Split(assembly, "\n")
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 0 && fields[0] == "MOVQ" {
			start := strings.Index(line, "MOVQ")
			lines[index] = line[:start] + alias + line[start+len("MOVQ"):]
		}
	}
	return strings.Join(lines, "\n")
}

func TestX86MOVQSourceAliasesCountedCompletePartitionsAndObjects(t *testing.T) {
	for _, alias := range append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...) {
		for _, raw := range []bool{false, true} {
			for _, shape := range []string{"single", "separate exit", "serial", "serial diamond"} {
				t.Run(fmt.Sprintf("%s/raw=%t/%s", alias, raw, shape), func(t *testing.T) {
					original := x86CallerCountedLoopScalarAssembly(raw)
					iterations := [4]int{0, 1, 2, 3}
					if shape == "separate exit" {
						original = x86CallerCountedLoopSeparateExitAssembly(raw)
					} else if strings.HasPrefix(shape, "serial") {
						original = x86CallerCountedSCCAssembly(raw, shape == "serial diamond")
						iterations = [4]int{0, 2, 4, 6}
						if shape == "serial diamond" {
							iterations = [4]int{0, 3, 6, 9} // Both feasible diamond paths replay the second SCC.
						}
					}
					assembly := x86SourceAliasCountedAssembly(original, alias)
					canonical := x86SourceAliasCountedAssembly(original, "MOVQ")
					if !bytes.Equal(x86OrderingHintGoBytes(t, "amd64", assembly), x86OrderingHintGoBytes(t, "amd64", canonical)) {
						t.Fatal("actual original Go source aliases differ from complete MOVQ body bytes")
					}
					pkg, file := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
					resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
					fingerprint, err := x86CallerSourceFingerprint(file.Funcs[0])
					if err != nil {
						t.Fatal(err)
					}
					normalized, err := normalizeX86RawFile(file, "amd64", options)
					if err != nil || normalized.Funcs[0].x86SourceStack == nil {
						t.Fatalf("complete alias counted provenance missing: %v", err)
					}
					proof := normalized.Funcs[0].x86SourceStack
					if proof.countedIterations != iterations || proof.caller.source != fingerprint {
						t.Fatal("complete partition inventory or original source identity changed", proof.countedIterations)
					}
					if actual, err := x86CallerSourceFingerprint(normalized.Funcs[0]); err != nil || actual != proof.normalized {
						t.Fatal("normalized source identity was not sealed")
					}
					for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
						x86CallerCountedSCCObjects(t, x86CallerCountedLoopScalarSource(), assembly, triple)
					}
					if after, err := x86CallerSourceFingerprint(file.Funcs[0]); err != nil || after != fingerprint {
						t.Fatal("alias replay rewrote original Instr.Op/Raw")
					}
					for _, change := range []string{"original", "normalized", "missing caller", "access width"} {
						t.Run(change, func(t *testing.T) {
							_, fresh := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
							copy, err := normalizeX86RawFile(fresh, "amd64", options)
							if err != nil || copy.Funcs[0].x86SourceStack == nil {
								t.Fatal("fresh proof missing", err)
							}
							if change == "original" {
								fresh.Funcs[0].Instrs[1].Raw += " "
								decoded, err := decodeX86RawDirectives(fresh.Funcs[0], "amd64")
								if err != nil {
									t.Fatal(err)
								}
								failed := normalizeX86RawReturnSourceStack(decoded, options, true, fresh.Funcs[0])
								if failed.x86SourceStack != nil {
									t.Fatal("changed original Raw borrowed its alias proof")
								}
								return
							}
							if change == "missing caller" {
								options.Sigs = map[string]FuncSig{}
								for name, sig := range sigs {
									sig.x86CallerRegions = nil
									options.Sigs[name] = sig
								}
								defer func() { options.Sigs = sigs }()
							} else {
								instruction := &copy.Funcs[0].Instrs[1]
								if change == "normalized" {
									instruction.Raw += " "
									if x86RawReturnMemoryBound(copy.Funcs[0], copy, options, true) {
										t.Fatal("changed normalized alias Raw retained its bound")
									}
								} else {
									access := instruction.x86CallerMemory[0]
									access.width++
									instruction.x86CallerMemory[0] = access
									if x86CallerMemoryCertified(*instruction, 0) || x86RawReturnMemoryBound(copy.Funcs[0], copy, options, true) {
										t.Fatal("changed alias access width retained authority")
									}
									return
								}
							}
							if _, err := Translate(copy, options); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("changed sealed alias/caller source translated", change, err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86MOVQSourceAliasesCountedAllExistingRejectedPaths(t *testing.T) {
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, serial := range []bool{false, true} {
			original, changes := x86CallerCountedLoopScalarAssembly(false), x86CallerCountedLoopRejectedChanges()
			if serial {
				original, changes = x86CallerCountedSCCAssembly(false, true), x86CallerCountedSCCRejectedChanges()
			}
			for name, change := range changes {
				t.Run(fmt.Sprintf("%s/serial=%t/%s", alias, serial, name), func(t *testing.T) {
					assembly := strings.Replace(original, change[0], change[1], 1)
					if assembly == original {
						t.Fatal("negative did not mutate the original complete source")
					}
					assembly = x86SourceMOVQSpelling(assembly, alias)
					goAssemblerOracleOutput(t, "amd64", assembly, "", true)
					pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
					if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("alias broadened a rejected loop/partition/mutation", err)
					}
					if serial {
						x86CallerCountedSCCRejectThreeAPIs(t, assembly)
					}
				})
			}
		}
	}
}

func TestX86MOVQSourceAliasesOtherScalarKnowledgeConsumers(t *testing.T) {
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, row := range []string{"$0,AX", "$4294967296,AX", "AX,BX", "AX,AX", "R12,AX"} {
			t.Run(alias+"/"+row, func(t *testing.T) {
				instruction := x86PureGPUnknownInstruction(t, alias+" "+row)
				original, canonical := instruction, instruction
				canonical.Op = "MOVQ"
				state := x86FixedLocalState{pointers: map[Reg]int64{}, opaque: map[Reg]x86FixedLocalOrigins{},
					booleans: map[Reg]uint8{AX: 0xaa}, constants: map[Reg]int64{AX: 1<<32 + 1}, known: map[Reg]uint8{AX: 0xff}}
				got, want := cloneFixedLocalState(state), cloneFixedLocalState(state)
				err := fixedLocalStep(&instruction, &got, FuncSig{}, nil, 0)
				wantErr := fixedLocalStep(&canonical, &want, FuncSig{}, nil, 0)
				if (err == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) ||
					fixedLocalInstructionShape(instruction) != fixedLocalInstructionShape(canonical) {
					t.Errorf("fixed-local scalar numeric/boolean knowledge differs: %v / %v", err, wantErr)
				}
				carry := x86LockCarryState{carry: true}
				carry.gp[0] = 0xff
				context := amd64Ctx{goarch: "amd64"}
				if got, want := context.lockCarryTransfer(instruction, carry.clone()), context.lockCarryTransfer(canonical, carry.clone()); !reflect.DeepEqual(got, want) {
					t.Errorf("carry initialization differs: %+v / %+v", got, want)
				}
				if !reflect.DeepEqual(instruction, original) {
					t.Fatal("scalar observer changed source identity")
				}
			})
		}
		for _, row := range []string{"(AX),BX", "BX,(AX)"} {
			ins := x86PureGPUnknownInstruction(t, alias+" "+row)
			canonical := ins
			canonical.Op = "MOVQ"
			for index := 0; index < 2; index++ {
				width, write, known := x86InstructionMemoryShape(ins, index, "amd64")
				wantWidth, wantWrite, wantKnown := x86InstructionMemoryShape(canonical, index, "amd64")
				if width != wantWidth || write != wantWrite || known != wantKnown {
					t.Errorf("alias native memory-width observation differs: %s index%d", row, index)
				}
			}
		}
	}
}

func TestX86MOVQSourceAliasesFixedLocalActualObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var assembly, declarations strings.Builder
	for index, alias := range append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...) {
		fmt.Fprintf(&declarations, "func Value%d(x uint64) uint64\n", index)
		fmt.Fprintf(&assembly, "TEXT ·Value%d(SB),4,$16-16\n%s x+0(FP),AX\n%s $4294967296,DX\n%s AX,0(SP)\n%s 0(SP),CX\n%s CX,ret+8(FP)\nRET\n",
			index, alias, alias, alias, alias, alias)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"}, {"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			observed := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			fingerprints := map[string][32]byte{}
			for _, function := range file.Funcs {
				fingerprint, err := x86CallerSourceFingerprint(function)
				if err != nil {
					t.Fatal(err)
				}
				fingerprints[function.Sym] = fingerprint
			}
			bound, err := observed.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("source-proved fixed-local MOVQ aliases lost scalar knowledge", err)
			}
			normalized, err := normalizeX86RawFile(file, "amd64", bound)
			if err != nil {
				t.Fatal(err)
			}
			for _, function := range normalized.Funcs {
				reads, writes := 0, 0
				for _, instruction := range function.Instrs {
					for index, access := range instruction.x86FixedLocalMemory {
						context := amd64Ctx{fixedLocal: access.owner}
						if access.width != 8 || !context.fixedLocalMemoryCertified(instruction, index) {
							t.Fatal("alias lost exact original eight-byte certificate", instruction.Raw)
						}
						if access.write {
							writes++
						} else {
							reads++
						}
					}
				}
				if reads != 1 || writes != 1 {
					t.Fatal("alias local memory inventory changed", function.Sym, reads, writes)
				}
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil || ir == "" {
					t.Fatal("bound original source alias failed public consumer", err)
				}
				compileLLVMToObject(t, llc, target.triple, "source-alias-local.ll", "source-alias-local.o", ir)
			})
			for _, function := range file.Funcs {
				if after, err := x86CallerSourceFingerprint(function); err != nil || after != fingerprints[function.Sym] {
					t.Fatal("fixed-local alias consumer rewrote sealed original source")
				}
			}
		})
	}
}
