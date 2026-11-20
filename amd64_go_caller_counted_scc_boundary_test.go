package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerCountedSCCRejectThreeAPIs(t *testing.T, assembly string) {
	t.Helper()
	pkg, file := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
	before := fmt.Sprintf("%#v %#v", file, sigs)
	t.Run("Translate", func(t *testing.T) {
		if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved SCC source acquired text permission: %v", err)
		}
	})
	t.Run("Module", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved SCC source acquired module permission: %v", err)
		}
	})
	t.Run("GoModule", func(t *testing.T) {
		if err := x86CallerCoreTranslate(t, pkg, assembly, options.TargetTriple); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved SCC source acquired Go module permission: %v", err)
		}
	})
	if before != fmt.Sprintf("%#v %#v", file, sigs) {
		t.Fatal("failed SCC replay mutated caller/source inputs")
	}
}

func x86CallerCountedSCCRejectedChanges() map[string][2]string {
	return map[string][2]string{
		"second missing guard":       {"JE done\n", ""},
		"second reversed guard":      {"JE done", "JNE done"},
		"second unknown bound":       {"MOVL R9,R13", "MOVL BX,R13"},
		"second unrelated bound":     {"MOVL R9,R13", "MOVL $2,R13"},
		"second fresh length source": {"MOVL R9,R13", "MOVQ length+24(FP),R8\nMOVQ (R8),R9\nMOVL R9,R13"},
		"second wider partition":     {"ANDL $3,R13", "ANDL $7,R13"},
		"second partial bound":       {"MOVL R9,R13", "MOVW R9,R13"},
		"second missing counter":     {"XORL R12,R12", ""},
		"second nonzero counter":     {"XORL R12,R12", "MOVL $1,R12"},
		"second partial counter":     {"XORL R12,R12", "XORW R12,R12"},
		"second stride zero":         {"ADDQ $1,R12", "ADDQ $0,R12"},
		"second stride two":          {"ADDQ $1,R12", "ADDQ $2,R12"},
		"second decrement":           {"ADDQ $1,R12", "SUBQ $1,R12"},
		"second double update":       {"ADDQ $1,R12", "ADDQ $1,R12\nADDQ $1,R12"},
		"second update bypass":       {"ADDQ $1,R12", "TESTL BX,BX\nJE second_compare\nADDQ $1,R12\nsecond_compare:"},
		"second stale flags":         {"JNE second_body", "ADDL $1,R10\nJNE second_body"},
		"second side entry":          {"JE done", "JE second_body"},
		"second early exit":          {"second_body:", "second_body:\nTESTL BX,BX\nJE done"},
		"second nested cycle":        {"second_body:", "second_body:\ninner:\nTESTL BX,BX\nJNE inner"},
		"dead unknown effect":        {"second_body:", "JMP second_body\nRDTSC\nsecond_body:"},
		"first unknown GP":           {"ADDL R11,BX", "ADDL R8,BX"},
		"diamond missing GP":         {"MOVL $5,R11", "MOVL R8,R11"},
		"diamond missing vector":     {"MOVL $5,R11", "VEXTRACTF128 $1,Y0,X1\nMOVL $5,R11"},
		"diamond missing mask":       {"MOVL $5,R11", "VMOVUPS (DI),Z0\nVPADDD.Z Z0,Z0,K1,Z1\nMOVL $5,R11"},
		"diamond readonly write":     {"MOVL $5,R11", "MOVL $5,(DI)\nMOVL $5,R11"},
		"diamond unknown origin":     {"MOVL $5,R11", "MOVQ R8,DI\nMOVL $5,R11"},
		"diamond lost result":        {"MOVL $5,R11", "MOVQ DI,DX\nMOVL $5,R11"},
		"diamond displaced result":   {"MOVL $5,R11", "ADDQ $1,DX\nMOVL $5,R11"},
		"diamond SP escape":          {"MOVL $5,R11", "MOVQ DI,SP\nMOVL $5,R11"},
		"diamond BP escape":          {"MOVL $5,R11", "MOVQ DI,BP\nMOVL $5,R11"},
		"diamond g clobber":          {"MOVL $5,R11", "MOVQ $0,R14\nMOVL $5,R11"},
	}
}

func TestX86GoCallerCountedSCCRetainsEveryPathAndOrigin(t *testing.T) {
	original := x86CallerCountedSCCAssembly(false, true)
	for name, change := range x86CallerCountedSCCRejectedChanges() {
		t.Run(name, func(t *testing.T) {
			if strings.Count(original, change[0]) == 0 {
				t.Fatal("negative does not name original source")
			}
			assembly := strings.Replace(original, change[0], change[1], 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			x86CallerCountedSCCRejectThreeAPIs(t, assembly)
		})
	}
}

func TestX86GoCallerCountedSCCCannotCloseUnknownCallers(t *testing.T) {
	for name, change := range map[string][2]string{
		"indirect exit": {"done:", "done:\nJMP R8"},
		"unknown call":  {"first_done:", "first_done:\nCALL ·unregistered(SB)"},
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerCountedSCCAssembly(false, false), change[0], change[1], 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, file := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			if _, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed caller graph supplied a producer: %v", err)
			}
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed caller graph translated: %v", err)
			}
		})
	}
}

func TestX86GoCallerCountedSCCDoesNotMergeDifferentReadonlyPaths(t *testing.T) {
	// These paths are individually legal. Replay must keep their different
	// authenticated input origins rather than deriving a synthetic common one.
	assembly := strings.Replace(x86CallerCountedSCCAssembly(false, true), "MOVL $5,R11", "MOVQ SI,DI\nMOVL $5,R11", 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	x86CallerCountedSCCObjects(t, x86CallerCountedLoopScalarSource(), assembly, "x86_64-unknown-linux-gnu")
}

func TestX86GoCallerCountedSCCPreservesResidueAndSourceSeals(t *testing.T) {
	assembly := x86CallerCountedSCCAssembly(true, false)
	pkg, file := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
	normalized, err := normalizeX86RawFile(file, "amd64", options)
	if err != nil || normalized.Funcs[0].x86SourceStack == nil {
		t.Fatalf("complete SCC replay proof missing: %v", err)
	}
	proof := normalized.Funcs[0].x86SourceStack
	if proof.countedIterations != [4]int{0, 2, 4, 6} {
		t.Fatalf("multiple SCCs changed residue denominator: %v", proof.countedIterations)
	}
	if fingerprint, err := x86CallerSourceFingerprint(normalized.Funcs[0]); err != nil || fingerprint != proof.normalized {
		t.Fatal("normalized identity not sealed")
	}
	for _, name := range []string{"original source", "normalized source", "missing caller", "access width"} {
		t.Run(name, func(t *testing.T) {
			_, original := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			copy, err := normalizeX86RawFile(original, "amd64", options)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "original source":
				original.Funcs[0].Instrs[1].Args[0].FPOffset++
				decoded, err := decodeX86RawDirectives(original.Funcs[0], "amd64")
				if err != nil {
					t.Fatal(err)
				}
				failed := normalizeX86RawReturnSourceStack(decoded, options, true, original.Funcs[0])
				if failed.x86SourceStack != nil {
					t.Fatal("modified original acquired stale SCC permission")
				}
				return
			case "missing caller":
				privateOptions := options
				privateOptions.Sigs = map[string]FuncSig{}
				for symbol, sig := range sigs {
					sig.x86CallerRegions = nil
					privateOptions.Sigs[symbol] = sig
				}
				if _, err := Translate(copy, privateOptions); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("lost caller identity acquired SCC permission: %v", err)
				}
				return
			}
			for index := range copy.Funcs[0].Instrs {
				ins := &copy.Funcs[0].Instrs[index]
				if ins.Op != "MOVL" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.x86CallerMemory == nil {
					continue
				}
				if !x86CallerMemoryCertified(*ins, 0) {
					t.Fatal("complete read certificate missing")
				}
				if name == "access width" {
					access := ins.x86CallerMemory[0]
					access.width++
					ins.x86CallerMemory[0] = access
					if x86CallerMemoryCertified(*ins, 0) || x86RawReturnMemoryBound(copy.Funcs[0], copy, options, true) {
						t.Fatal("tampered read width borrowed SCC permission")
					}
					return
				}
				ins.Args[0].Mem.Base = DX
				if _, err := Translate(copy, options); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("modified normalized source retained SCC permission: %v", err)
				}
				return
			}
			t.Fatal("no source access selected for negative")
		})
	}
}

func TestX86GoCallerCountedSCCMasksAndWidths(t *testing.T) {
	for _, mask := range []int{1, 2, 3} {
		for _, width := range []string{"L", "Q"} {
			t.Run(fmt.Sprintf("mask%d/%s", mask, width), func(t *testing.T) {
				assembly := strings.ReplaceAll(x86CallerCountedSCCAssembly(false, false), "$3,", fmt.Sprintf("$%d,", mask))
				assembly = strings.NewReplacer("ADDQ $1,CX", "ADD"+width+" $1,CX",
					"ADDQ $1,R12", "ADD"+width+" $1,R12", "CMPL CX,AX", "CMP"+width+" CX,AX",
					"CMPL R12,R13", "CMP"+width+" R12,R13").Replace(assembly)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				x86CallerCountedSCCObjects(t, x86CallerCountedLoopScalarSource(), assembly, "x86_64-unknown-linux-gnu")
			})
		}
	}
}

func TestX86GoCallerCountedSCCIndependentMasksAndBodyDiamonds(t *testing.T) {
	for _, masks := range [][2]int{{1, 2}, {2, 3}, {3, 1}} {
		t.Run(fmt.Sprintf("%d/%d", masks[0], masks[1]), func(t *testing.T) {
			assembly := x86CallerCountedSCCAssembly(false, false)
			assembly = strings.NewReplacer("TESTB $3,R9\nJE first_done", fmt.Sprintf("TESTB $%d,R9\nJE first_done", masks[0]),
				"ANDL $3,AX", fmt.Sprintf("ANDL $%d,AX", masks[0]),
				"TESTB $3,R9\nJE done", fmt.Sprintf("TESTB $%d,R9\nJE done", masks[1]),
				"ANDL $3,R13", fmt.Sprintf("ANDL $%d,R13", masks[1])).Replace(assembly)
			// Both arms of this internal diamond are known numerical writes.
			// The +1 update still dominates every path to the exact latch.
			assembly = strings.Replace(assembly, "ADDQ $1,R12", `TESTL BX,BX
JE zero_value
MOVL $3,R11
JMP body_join
zero_value:
MOVL $5,R11
body_join:
ADDL R11,R10
ADDQ $1,R12`, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			x86CallerCountedSCCObjects(t, x86CallerCountedLoopScalarSource(), assembly, "x86_64-unknown-linux-gnu")
		})
	}
}

func TestX86GoCallerCountedSCCKeepsWholeReplayBudget(t *testing.T) {
	var diamond strings.Builder
	for index := 0; index < 14; index++ {
		fmt.Fprintf(&diamond, "TESTL BX,BX\nJE budget%d\nMOVL $7,R11\nbudget%d:\n", index, index)
	}
	assembly := strings.Replace(x86CallerCountedSCCAssembly(false, false), "ADDQ $1,R12", diamond.String()+"ADDQ $1,R12", 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "finite path budget exhausted") {
		t.Fatalf("SCC composition expanded or bypassed the finite replay budget: %v", err)
	}
}
