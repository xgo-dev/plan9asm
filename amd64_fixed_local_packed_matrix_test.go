package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalPackedCompleteProgram() (string, string, int) {
	return fixedLocalPackedCompleteProgramRange(0, 195)
}

func fixedLocalPackedCompleteProgramRange(start, end int) (string, string, int) {
	var assembly, declarations strings.Builder
	count := 0
	emit := func(operation string) {
		index := count
		count++
		if index < start || index >= end {
			return
		}
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalPackedAssembly(operation), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	for _, row := range fixedLocalPackedMoveOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank == "Z" && !row.evex {
				continue
			}
			for _, high := range []bool{false, true} {
				first, last := bank+"0", bank+"1"
				if high {
					first, last = bank+"15", bank+"14"
					if row.evex {
						first, last = bank+"31", bank+"30"
					}
				}
				for _, predicate := range []string{"none", "merge", "zero"} {
					if predicate != "none" && !row.evex {
						continue
					}
					operation := fmt.Sprintf("%s 64(BP),%s\n%s 128(BP),%s\n", row.name, first, row.name, last)
					mask, opcode := "", row.name
					if predicate != "none" {
						operation += "KMOVQ AX,K7\n"
						mask = "K7,"
					}
					if predicate == "zero" {
						opcode += ".Z"
					}
					operation += fmt.Sprintf("%s 64(BP),%s%s\n%s %s,%s%s\n%s %s,%s128(BP)",
						opcode, mask, first, opcode, first, mask, last, row.name, last, mask)
					emit(operation)
				}
			}
		}
	}
	// Legacy aliases retain upper bytes and share the exact same local envelope.
	for _, name := range []string{"MOVO", "MOVOA", "MOVOU", "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD"} {
		operation := fmt.Sprintf("%s 64(BP),X15\n%s X15,X0\n%s X0,128(BP)", name, name, name)
		emit(operation)
	}
	return assembly.String(), declarations.String(), count
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsLinuxBatch00(t *testing.T) {
	fixedLocalPackedActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 0)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsLinuxBatch01(t *testing.T) {
	fixedLocalPackedActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 1)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsLinuxBatch02(t *testing.T) {
	fixedLocalPackedActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 2)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsLinuxBatch03(t *testing.T) {
	fixedLocalPackedActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 3)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsDarwinBatch00(t *testing.T) {
	fixedLocalPackedActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 0)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsDarwinBatch01(t *testing.T) {
	fixedLocalPackedActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 1)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsDarwinBatch02(t *testing.T) {
	fixedLocalPackedActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 2)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsDarwinBatch03(t *testing.T) {
	fixedLocalPackedActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 3)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsWindowsBatch00(t *testing.T) {
	fixedLocalPackedActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 0)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsWindowsBatch01(t *testing.T) {
	fixedLocalPackedActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 1)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsWindowsBatch02(t *testing.T) {
	fixedLocalPackedActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 2)
}

func TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsWindowsBatch03(t *testing.T) {
	fixedLocalPackedActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 3)
}

func TestGoAMD64FixedLocalPackedObjectBatchPlan(t *testing.T) {
	completeAssembly, completeDeclarations, count := fixedLocalPackedCompleteProgram()
	if count != 195 {
		t.Fatal("complete independent packed format inventory changed", count)
	}
	var assembly, declarations strings.Builder
	for batch := 0; batch < 4; batch++ {
		start, end, ok := fixedLocalObjectBatchRange(count, batch)
		if !ok {
			t.Fatal("missing packed object batch", batch)
		}
		body, decls, total := fixedLocalPackedCompleteProgramRange(start, end)
		file, err := Parse(ArchAMD64, body)
		if err != nil || total != count || len(file.Funcs) != end-start {
			t.Fatal("packed object batch lost its exact function range", batch, err)
		}
		assembly.WriteString(body)
		declarations.WriteString(decls)
	}
	if assembly.String() != completeAssembly || declarations.String() != completeDeclarations {
		t.Fatal("packed object batches changed, omitted or duplicated original source bytes")
	}
}

func fixedLocalPackedActualObjects(t *testing.T, target, triple string, batch int) {
	t.Helper()
	// Keep lazy Go tools in this root's disposable cache, not a global cache
	// or a different source/object observation.
	t.Setenv("GOCACHE", t.TempDir())
	start, end, ok := fixedLocalObjectBatchRange(195, batch)
	if !ok {
		t.Fatal("invalid complete packed object batch", batch)
	}
	assembly, declarations, total := fixedLocalPackedCompleteProgramRange(start, end)
	if total != 195 {
		t.Fatalf("independent width/register/mask/legacy matrix changed: %d", total)
	}
	count := end - start
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
		pkg, request, _, options := x86CMOVFixedLocalFixture(t, assembly, declarations, target, triple)
		fixedLocalConversionPrepareToolCache(t, request)
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
			if err != nil || strings.Count(ir, "%fixed_local_native = alloca") != count {
				t.Fatalf("complete original frame inventory lost: %v", err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				var names []string
				for index := start; index < end; index++ {
					names = append(names, fmt.Sprintf("example.invalid/framefixture.Value%d", index))
				}
				x86CompactExpandRequireAllDefinitions(t, text, names)
				compileLLVMToObject(t, llc, triple, "complete-packed.ll", "complete-packed.o", text)
			}
		})
	})
}

func TestGoAMD64FixedLocalPackedEveryByteAndUnknownRole(t *testing.T) {
	for _, bank := range []struct {
		name  string
		width int
	}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
		operation := fmt.Sprintf("VMOVDQA64 64(BP),%s0\nVMOVDQA64 %s0,128(BP)", bank.name, bank.name)
		pkg, _, _, options := fixedLocalPackedFixture(t, operation)
		sig := options.Sigs[pkg.Path+".Value"]
		base := fixedLocalPackedAssembly(operation)
		for missing := 0; missing < bank.width; missing++ {
			t.Run(fmt.Sprintf("%s/byte%d", bank.name, missing), func(t *testing.T) {
				var stores strings.Builder
				for index := 0; index < 8; index++ {
					if index != missing%8 {
						fmt.Fprintf(&stores, "MOVB $1,%d(BP)\n", 64+missing/8*8+index)
					}
				}
				assembly := strings.Replace(base, fmt.Sprintf("MOVQ AX,%d(BP)\n", 64+missing/8*8), stores.String(), 1)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("missing private byte obtained native read authority", err)
				}
			})
		}
		for name, changed := range map[string]string{
			"past frame":           strings.Replace(base, operation, strings.Replace(operation, "64(BP)", "256(BP)", 1), 1),
			"misaligned":           strings.Replace(base, operation, strings.Replace(operation, "64(BP)", "65(BP)", 1), 1),
			"unknown base":         strings.Replace(base, operation, strings.Replace(operation, "64(BP)", "64(DX)", 1), 1),
			"external escape":      strings.Replace(base, operation, "MOVQ BP,(AX)\n"+operation, 1),
			"private mask":         strings.Replace(base, operation, "KMOVQ BP,K1\n"+operation, 1),
			"unaligned residue":    strings.Replace(base, "ANDQ $-64,BP", "ANDQ $-8,BP", 1),
			"unknown address size": strings.Replace(base, "ADDQ $64,BP", "ADDQ DX,BP", 1),
		} {
			t.Run(bank.name+"/"+name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("native frame boundary was weakened", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalPackedMod64IndependentAliasReplay(t *testing.T) {
	operation := "VMOVDQA64 64(BP),Z0\nVMOVDQA64 Z0,128(BP)"
	pkg, _, file, options := fixedLocalPackedFixture(t, operation)
	sig := options.Sigs[pkg.Path+".Value"]
	proved, err := proveX86FixedLocal(file.Funcs[0], sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, ins := range proved.Instrs {
		if ins.Op != "VMOVDQA64" {
			continue
		}
		for operand, access := range ins.x86FixedLocalMemory {
			for residue, offset := range access.offset {
				base := int64(((residue*8 + 64) & -64) - residue*8)
				if offset != base+ins.Args[operand].Mem.Off || (offset+int64(residue*8))%64 != 0 {
					t.Fatalf("mod64 residue %d: %+v", residue, access)
				}
			}
		}
	}
	// Only residues six and seven overlap this scalar store with source bytes.
	// Checking the old four residues would miss this real alias difference.
	changed := strings.Replace(fixedLocalPackedAssembly(operation), operation, "MOVQ $0,80(SP)\n"+operation, 1)
	requireX86GoAssemblerResult(t, "amd64", changed, true)
	file, err = Parse(ArchAMD64, changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "byte identity") {
		t.Fatal("residue-dependent byte aliases were relocated", err)
	}
}
