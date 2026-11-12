package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerCountedLoopRejectedChanges() map[string][2]string {
	return map[string][2]string{
		"missing nonzero guard":    {"JE done\n", ""},
		"reversed guard":           {"JE done", "JNE done"},
		"stale guard flags":        {"JE done", "ADDL $1,R10\nJE done"},
		"different guard bits":     {"TESTB $3,R9", "TESTB $4,R9"},
		"byte flags truncate":      {"TESTB $3,R9\nJE done", "MOVL $256,R8\nTESTB R8,R8\nJNE done"},
		"unmapped length":          {"MOVQ (CX),R9", "MOVQ (SI),R9"},
		"unknown length":           {"MOVQ (CX),R9", "MOVQ R12,R9"},
		"bound four":               {"ANDL $3,AX", "ANDL $7,AX"},
		"unrelated bound":          {"MOVL R9,AX", "MOVL $2,AX"},
		"partial bound":            {"MOVL R9,AX", "MOVW R9,AX"},
		"bound overwritten":        {"MOVL (DI),BX", "ANDL $3,AX\nMOVL (DI),BX"},
		"bound alias":              {"ANDL $3,AX", "ANDL $3,CX"},
		"counter absent":           {"XORL CX,CX", ""},
		"counter nonzero":          {"XORL CX,CX", "MOVQ $1,CX"},
		"counter high bits":        {"XORL CX,CX", "MOVQ $0x100000000,CX"},
		"partial counter":          {"XORL CX,CX", "XORW CX,CX"},
		"zero stride":              {"ADDQ $1,CX", "ADDQ $0,CX"},
		"negative stride":          {"ADDQ $1,CX", "SUBQ $1,CX"},
		"two stride":               {"ADDQ $1,CX", "ADDQ $2,CX"},
		"double update":            {"ADDQ $1,CX", "ADDQ $1,CX\nADDQ $1,CX"},
		"update bypass":            {"ADDQ $1,CX", "TESTL BX,BX\nJE compare\nADDQ $1,CX\ncompare:"},
		"stale latch flags":        {"JNE again", "ADDL $1,R10\nJNE again"},
		"different latch operands": {"CMPL CX,AX", "CMPL BX,AX"},
		"side entry":               {"JE done", "JE again"},
		"nested loop":              {"MOVL (DI),BX", "inner:\nCMPQ R9,$0\nJNE inner\nMOVL (DI),BX"},
		"unknown indirect target":  {"JNE again", "JNE again\nJMP R12"},
		"unknown dead effect":      {"again:", "JMP again\nRDTSC\nagain:"},
		"different input origin":   {"ADDQ $4,DI", "MOVQ SI,DI"},
		"missing input origin":     {"ADDQ $4,DI", "MOVQ $0,DI"},
		"readonly write":           {"MOVL (DI),BX", "MOVL R10,(DI)\nMOVL (DI),BX"},
		"result displacement":      {"ADDQ $4,DI", "ADDQ $1,DX\nADDQ $4,DI"},
		"source stack escape":      {"ADDQ $4,DI", "MOVQ DI,SP\nADDQ $4,DI"},
		"input cap":                {"ADDQ $4,DI", "ADDQ $1048576,DI"},
		"pointer truncation":       {"ADDQ $4,DI", "LEAL 4(DI),DI"},
		"unknown first GP":         {"ADDL R11,BX", "ADDL R12,BX"},
		"late first GP":            {"MOVL (DI),BX", "ADDL BX,R10\nMOVL (DI),BX"},
		"unknown first vector":     {"MOVL (DI),BX", "VEXTRACTF128 $1,Y0,X1\nMOVL (DI),BX"},
		"unknown first mask":       {"MOVL (DI),BX", "VMOVUPS (DI),Z0\nVPADDD.Z Z0,Z0,K1,Z1\nMOVL (DI),BX"},
		"mask zero no rights":      {"MOVL (DI),BX", "VMOVUPS (DI),Z0\nMOVL $0,BX\nKMOVQ BX,K1\nVPADDD.Z (DX),Z0,K1,Z1\nMOVL (DI),BX"},
	}
}

func TestX86GoCallerCountedLoopRetainsUnprovedPaths(t *testing.T) {
	original := x86CallerCountedLoopScalarAssembly(false)
	for name, change := range x86CallerCountedLoopRejectedChanges() {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(original, change[0], change[1], 1)
			if assembly == original {
				t.Fatal("negative failed to change its original source")
			}
			pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved %s admitted: %v", name, err)
			}
		})
	}
}

func TestX86GoCallerCountedLoopSealsAllPartitionsAndSource(t *testing.T) {
	for _, change := range []string{"none", "original", "normalized", "missing caller", "certificate width"} {
		t.Run(change, func(t *testing.T) {
			assembly := x86CallerCountedLoopScalarAssembly(true)
			pkg, file := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
			normalized, err := normalizeX86RawFile(file, "amd64", options)
			if err != nil || normalized.Funcs[0].x86SourceStack == nil {
				t.Fatalf("complete finite source proof: %v", err)
			}
			proof := normalized.Funcs[0].x86SourceStack
			if proof.countedIterations != [4]int{0, 1, 2, 3} {
				t.Fatalf("missing or altered feasible residue visits: %v", proof.countedIterations)
			}
			actualHash, err := x86CallerSourceFingerprint(normalized.Funcs[0])
			if err != nil || actualHash != proof.normalized {
				t.Fatal("complete normalized identity was not sealed")
			}
			if change == "original" {
				file.Funcs[0].Instrs[1].Args[0].FPOffset++
				decoded, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
				if err != nil {
					t.Fatal(err)
				}
				failed := normalizeX86RawReturnSourceStack(decoded, options, true, file.Funcs[0])
				if failed.x86SourceStack != nil {
					t.Fatal("changed original source borrowed its old caller identity")
				}
				return
			}
			for index := range normalized.Funcs[0].Instrs {
				ins := &normalized.Funcs[0].Instrs[index]
				if ins.Op != "MOVL" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
					continue
				}
				if !x86CallerMemoryCertified(*ins, 0) {
					t.Fatal("original full-width read lacks a final replay certificate")
				}
				if change == "certificate width" {
					access := ins.x86CallerMemory[0]
					access.width++
					ins.x86CallerMemory[0] = access
					if x86CallerMemoryCertified(*ins, 0) || x86RawReturnMemoryBound(normalized.Funcs[0], normalized, options, true) {
						t.Fatal("mutated private width acquired admission")
					}
				} else if change == "normalized" {
					ins.Args[0].Mem.Base = DX
				}
			}
			if change == "missing caller" {
				sig := sigs["caller.kernel"]
				sig.x86CallerRegions = nil
				sigs[sig.Name] = sig
			}
			_, err = Translate(normalized, options)
			if change == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("edited %s retained final proof: %v", change, err)
			}
			if change == "certificate width" {
				fresh, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(fresh, options); err != nil {
					t.Fatalf("recapture from unchanged original source: %v", err)
				}
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				if err := x86CallerCoreTranslate(t, pkg, assembly, options.TargetTriple); err != nil {
					t.Fatalf("fresh actual caller source and LLVM object: %v", err)
				}
			}
		})
	}
}

func TestX86GoCallerCountedLoopFinitePathBudgetFailsClosed(t *testing.T) {
	var body strings.Builder
	for index := 0; index < 14; index++ {
		fmt.Fprintf(&body, "CMPL BX,$0\nJE branch%d\nMOVL $7,R11\nbranch%d:\n", index, index)
	}
	original := x86CallerCountedLoopScalarAssembly(false)
	assembly := strings.Replace(original, "MOVL (DI),BX", "MOVL (DI),BX\n"+body.String(), 1)
	pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
	err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("unproved/exhausted path set acquired a certificate: %v", err)
	}
}

func TestX86GoCallerCountedLoopStatusWidthsUseActualLowBits(t *testing.T) {
	for _, item := range []struct {
		op    Op
		value uint64
	}{
		{"TESTB", 1 << 8}, {"TESTW", 1 << 16}, {"TESTL", 1 << 32}, {"TESTQ", 0},
	} {
		t.Run(string(item.op), func(t *testing.T) {
			assembly := fmt.Sprintf("TEXT ·status(SB),4,$0-0\nMOVQ $%d,R8\n%s R8,R8\nRET\n", item.value, item.op)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			facts := x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{}, source: -1}
			for pc, ins := range file.Funcs[0].Instrs {
				facts.step(pc, 0, ins, x86SourceStackState{}, nil)
			}
			if !facts.flags.known || !facts.flags.equal {
				t.Fatalf("actual %s truncation to zero did not prove ZF: %+v", item.op, facts.flags)
			}
		})
	}
}

func TestX86GoCallerCountedLoopAbsentNumericalFactStaysUnknown(t *testing.T) {
	facts := x86CallerCountedNumbers{
		regs: map[Reg]x86CallerCountedNumber{}, source: 0,
	}
	facts.step(1, 0, Instr{Op: "TESTQ", Args: []Operand{
		{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("R8")},
	}}, x86SourceStackState{}, nil)
	if facts.flags.known {
		t.Fatal("an absent numerical fact borrowed the first partition source")
	}
}

func TestX86GoCallerCountedLoopAlternateRegistersAndWidths(t *testing.T) {
	for _, counterWidth := range []string{"L", "Q"} {
		for _, compareWidth := range []string{"L", "Q"} {
			t.Run(counterWidth+compareWidth, func(t *testing.T) {
				assembly := x86CallerCountedLoopScalarAssembly(false)
				assembly = strings.NewReplacer(
					"JE done", "JE empty_final", "done:", "empty_final:",
					"again:", "generic_body:", "JNE again", "JNE generic_body",
					"MOVL R9,AX", "MOVL R9,R13", "ANDL $3,AX", "ANDL $3,R13",
					"XORL CX,CX", "XORL R12,R12", "ADDQ $1,CX", "ADD"+counterWidth+" $1,R12",
					"CMPL CX,AX", "CMP"+compareWidth+" R12,R13",
				).Replace(assembly)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
				for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
					if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestX86GoCallerCountedLoopFiveTargetsKeepAMD64Authority(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			if target.arch == "amd64" {
				assembly := x86CallerCountedLoopScalarAssembly(false)
				pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, target.triple); err != nil {
					t.Fatal(err)
				}
				return
			}
			// These two objects are the existing ordinary 386 scalar contract.
			// They are not copied AMD64 input or finite-loop authority.
			pkg, selected, fn, sig := x86CallerFixture(t, x86CallerCountedLoopScalarSource())
			if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "386"); !errors.Is(err, ErrProbeNeedsContext) || proof != nil {
				t.Fatal("mode32 borrowed the AMD64 caller input contract")
			}
			source, scalarSig, _ := x86SourceStackNumericalFixture("386", "@MOV @WORD(SP),AX\nADDL $7,AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3")
			requireX86GoAssemblerResult(t, "386", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, x86SourceStackOptions("386", target.triple, scalarSig))
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "mode32-counted-boundary.ll", "mode32-counted-boundary.o", module.String())
		})
	}
}
