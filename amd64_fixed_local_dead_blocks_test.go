package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These are source/CFG regressions, not execution witnesses for the dead MOVs.
func fixedLocalDeadBlockSource(operation, prefix, branch string) string {
	return "TEXT ·Value(SB),4,$24-16\nMOVQ a+0(FP),BX\n" +
		"MOVQ $7,AX\nMOVQ AX,0(SP)\n" + prefix + branch +
		"gap:\n" + operation + "\ndone:\n" +
		"MOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
}

func TestGoAMD64FixedLocalDeadMemoryBlocks(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, direction := range []string{"read", "write"} {
			t.Run(width+"/"+direction, func(t *testing.T) {
				operation := "MOV" + width + " (CX),AX"
				if direction == "write" {
					operation = "MOV" + width + " AX,(CX)"
				}
				assembly := fixedLocalDeadBlockSource(operation, "", "JMP done\n")
				pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
					"func Value(a uint64) uint64", "linux/amd64", "x86_64-unknown-linux-gnu")
				// Preserve the complete original instruction, including its
				// uninitialized address. Assembly acceptance grants no access.
				frameRelocationOriginal(t, pkg, request)
				fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
					func(t *testing.T, ir string, err error) {
						if err != nil {
							t.Fatal("unconditional source jump did not exclude its dead memory block", err)
						}
						compileLLVMToObject(t, llc, options.TargetTriple, "dead.ll", "dead.o", ir)
						compileLLVMToObject(t, llc, options.TargetTriple, "dead-o2.ll", "dead-o2.o", x86MulDivRoundOptimize(t, ir))
					})
			})
		}
	}
}

func TestGoAMD64FixedLocalLiveMemoryStillRequiresProof(t *testing.T) {
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, direction := range []string{"read", "write"} {
			for _, address := range []string{"unknown", "partial"} {
				t.Run(width+"/"+direction+"/"+address, func(t *testing.T) {
					operation := "MOV" + width + " (CX),AX"
					if direction == "write" {
						operation = "MOV" + width + " AX,(CX)"
					}
					prefix := ""
					if address == "partial" {
						prefix = "MOVB $1,CX\n"
					}
					// Both successors are possible for the declared input;
					// AX is known even in the write cases, isolating address duty.
					assembly := fixedLocalDeadBlockSource(operation, prefix, "CMPQ BX,$0\nJEQ gap\nJMP done\n")
					pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
						"func Value(a uint64) uint64", "linux/amd64", "x86_64-unknown-linux-gnu")
					frameRelocationOriginal(t, pkg, request)
					for _, api := range []string{"Translate", "Module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							ctx, cancel := runtimeOracleStageContext(t)
							defer cancel()
							source := requireGoAMD64FrameCapture(t, pkg, request)
							file, err := Parse(ArchAMD64, assembly)
							if err != nil {
								t.Fatal(err)
							}
							bound, err := source.BindFixedLocal(ctx, pkg, file, options)
							if err != nil {
								if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unknown/escaping address provenance") {
									t.Fatal("live address failed outside its expected binding obligation", err)
								}
								t.Log("live address rejected at Bind before codegen", err)
								return
							}
							fixedLocalAPI(t, pkg, file, bound, api, fixedLocalRequireContext, assembly)
						})
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalDeadBlocksKeepCompleteGrammar(t *testing.T) {
	const operation = "MOVQ (CX),AX"
	fn, sig := fixedLocalReplayFixture(t, "JMP done\n"+operation+"\ndone:")
	proven, err := proveX86FixedLocal(fn, sig)
	if err != nil {
		t.Fatal("legal complete dead source failed the independent proof baseline", err)
	}
	matched := 0
	for _, ins := range proven.Instrs {
		if len(ins.Args) == 2 && ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base == CX {
			matched++
			if len(ins.x86FixedLocalMemory) != 0 {
				t.Fatal("an unreachable unknown address acquired a memory certificate")
			}
		}
	}
	if matched != 1 {
		t.Fatal("independent dead-address control is missing or duplicated", matched)
	}
	for _, invalid := range []string{"MOVQ AX", "VADDPS X0,X1,AX", "MOVQ AX,(CX)\nSYSCALL"} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			assembly := strings.Replace(fixedLocalReplaySource("JMP done\n"+operation+"\ndone:"), operation, invalid, 1)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err == nil {
				t.Fatal("dead source bypassed complete typed-format validation", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalDeadBlockLabelAliases(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, label := range []string{"gap", "done"} {
		t.Run(label, func(t *testing.T) {
			assembly := fixedLocalDeadBlockSource("MOVQ (CX),AX", "", "JMP done\n")
			assembly = strings.Replace(assembly, label+":\n", label+":\n"+label+"_alias:\n", 1)
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
				"func Value(a uint64) uint64", "linux/amd64", "x86_64-unknown-linux-gnu")
			frameRelocationOriginal(t, pkg, request)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("adjacent labels lost their common successor", err)
					}
					if label == "done" {
						found := false
						for _, line := range strings.Split(ir, "\n") {
							if strings.HasPrefix(strings.TrimSpace(line), amd64LLVMBlockName("done")+":") {
								found = true
								continue
							}
							if found && strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), ";") {
								if !strings.HasPrefix(strings.TrimSpace(line), "br label %"+amd64LLVMBlockName("done_alias")) {
									t.Fatal("reachable empty label did not continue to its live successor", line)
								}
								break
							}
						}
						if !found {
							t.Fatal("reachable source label disappeared")
						}
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "aliases.ll", "aliases.o", ir)
				})
		})
	}
}

func TestGoAMD64FixedLocalDeadBlockProjectionGuards(t *testing.T) {
	assembly := fixedLocalDeadBlockSource("MOVQ (CX),AX", "", "JMP done\n")
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
		"func Value(a uint64) uint64", "linux/amd64", "x86_64-unknown-linux-gnu")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64", bound)
	if err != nil {
		t.Fatal(err)
	}
	fn := normalized.Funcs[0]
	makeConsumer := func() *amd64Ctx {
		return newX86Ctx(new(strings.Builder), fn, bound.Sigs[pkg.Path+".Value"], bound.ResolveSym,
			bound.Sigs, "amd64", options.TargetTriple, false)
	}
	baseline, err := makeConsumer().fixedLocalBlockReachability()
	if err != nil || len(baseline) == 0 {
		t.Fatal("actual source did not establish a valid emission projection", err)
	}
	for _, name := range []string{"owner", "source", "emitted instruction", "block mapping"} {
		t.Run(name, func(t *testing.T) {
			consumer := makeConsumer()
			switch name {
			case "owner":
				consumer.fixedLocal = &x86FixedLocalProof{}
			case "source":
				consumer.fpScalarSource.Instrs = append([]Instr(nil), fn.Instrs...)
				consumer.fpScalarSource.Instrs[0].Raw += " // changed source"
			case "emitted instruction":
				for index, live := range baseline {
					if !live && len(consumer.blocks[index].instrs) != 0 {
						consumer.blocks[index].instrs[0].Op = "SYSCALL"
						break
					}
				}
			case "block mapping":
				consumer.blockBase[1]++
			}
			if projection, err := consumer.fixedLocalBlockReachability(); !errors.Is(err, ErrProbeNeedsContext) || projection != nil {
				t.Fatal("changed emission acquired an unreachable-source exception", err)
			}
		})
	}
	for _, name := range []string{"private graph", "indirect", "address-taken"} {
		t.Run(name, func(t *testing.T) {
			consumer := makeConsumer()
			switch name {
			case "private graph":
				consumer.directTail = &x86DirectTailRoot{}
			case "indirect":
				consumer.indirectABI0 = &FuncSig{}
			case "address-taken":
				consumer.indirectLabels = []string{"gap"}
			}
			if projection, err := consumer.fixedLocalBlockReachability(); err != nil || projection != nil {
				t.Fatal("a separate entry graph was pruned", err)
			}
		})
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if projection, err := makeConsumer().fixedLocalBlockReachability(); !errors.Is(err, ErrProbeNeedsContext) || projection != nil {
		t.Fatal("closed actual source retained an emission exception", err)
	}
}
