package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86OfficialMoveRemainderRows(t *testing.T) []goasmrules.X86PackedBinaryRow {
	t.Helper()
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86MoveRemainderRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Selection belongs to each register/memory alternative. In particular, a
// load-row register alternative cannot claim the earlier store-row's bytes.
func x86OfficialMoveRemainderShadowTarget(row goasmrules.X86PackedBinaryRow, w goasmrules.X86PackedBinaryWitness) string {
	parts := strings.Split(row.ID, "/")
	index, _ := strconv.Atoi(parts[4])
	target := -1
	switch parts[3] {
	case "_yvmovq":
		switch index {
		case 1, 5:
			if w.Destination == "(AX)" {
				target = index - 1
			}
		case 3, 7:
			target = index - 2
			if w.Memory {
				target++
			}
		}
	case "_yvmovsd":
		switch index {
		case 3:
			target = 0
		case 10, 11:
			target = index - 6
		}
	}
	if target < 0 {
		return ""
	}
	return fmt.Sprintf("/%s/%s/%d", row.Opcode, parts[3], target)
}

func x86OfficialMoveRemainderSelectedRows(rows []goasmrules.X86PackedBinaryRow, vexOnly bool) []goasmrules.X86PackedBinaryRow {
	var selected []goasmrules.X86PackedBinaryRow
	for _, row := range rows {
		copy := row
		copy.Witnesses = nil
		for _, w := range row.Witnesses {
			if x86OfficialMoveRemainderShadowTarget(row, w) == "" && (!vexOnly || w.Generation == "vex") {
				copy.Witnesses = append(copy.Witnesses, w)
			}
		}
		if len(copy.Witnesses) != 0 {
			selected = append(selected, copy)
		}
	}
	return selected
}

// Reuse existing bounded pointer and implicit-DI producers. Syntax fields do
// not decide semantic output: GP results, memory stores and implicit stores
// need their own observation. Full aliases also seed old scalar/merge bytes.
func x86OfficialMoveRemainderAssembly(t *testing.T, arch string, cases []x86OfficialPackedCase) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprint("MoveRemainder", index)
		w := fixture.witness
		parts := strings.Split(fixture.row, "/")
		table := parts[3]
		args := strings.Split(strings.Fields(w.Instruction)[1], ",")
		var body, declaration string
		if table == "_yvmaskmovdqu" {
			mask, err := strconv.Atoi(args[0][1:])
			if err != nil {
				t.Fatal(err)
			}
			data, err := strconv.Atoi(args[1][1:])
			if err != nil {
				t.Fatal(err)
			}
			body, declaration = x86ImplicitMaskMoveOracleRegisters(arch, "VMASKMOVDQU", fixture.symbol, mask, data)
		} else {
			var initialization strings.Builder
			seeded := map[string]bool{}
			for _, arg := range args {
				if len(arg) > 1 && strings.ContainsAny(arg[:1], "XYZ") && !seeded[arg[1:]] {
					fmt.Fprintf(&initialization, "VMOVUPS (AX),Z%s\n", arg[1:])
					seeded[arg[1:]] = true
				}
			}
			if w.First == "CX" {
				move := "MOVQ"
				if table == "_yvmovd" || arch == "386" {
					move = "MOVL"
				}
				fmt.Fprintf(&initialization, "%s (AX),CX\n", move)
			}
			result := w.Destination
			if result == "(AX)" {
				result = w.First
			}
			observation := "MOVL CX,CX"
			if result != "CX" {
				lane := 0
				if table == "_yvmovhpd" || table == "_yvmovhlps" {
					ins := x86ScalarLaneInstruction(t, w.Instruction)
					form, known, err := x86MoveHalfProperties(ins.Op, ins, "amd64")
					if !known || err != nil {
						t.Fatal("half observer lost typed lane roles", err)
					}
					lane = form.outputLane * 2
				}
				observation = fmt.Sprintf("VPEXTRD $%d,X%s,CX", lane, result[1:])
			}
			body, declaration = x86PackedMoveInitializedInstruction(fixture.symbol, arch, initialization.String(), w.Instruction, observation)
		}
		matches := 0
		for offset, instruction := range strings.Split(body, "\n") {
			if instruction == w.Instruction {
				fixture.line = line + offset
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("producer changed or duplicated the original instruction", fixture.row, w.Instruction)
		}
		source.WriteString(body)
		declarations.WriteString(declaration)
		line += strings.Count(body, "\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialMoveRemainderSelectedRowsThreeAPIObjects(t *testing.T) {
	selected := func(legacy goasmrules.X86LegacyCatalog, avx []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
		rows, err := goasmrules.X86MoveRemainderRows(legacy, avx)
		if err != nil {
			return nil, err
		}
		if len(rows) != 101 {
			return nil, fmt.Errorf("complete original move source rows changed: %d", len(rows))
		}
		return x86OfficialMoveRemainderSelectedRows(rows, false), nil
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86OfficialPackedRowsObjectsInspect(t, selected, 93, 105, 0,
		func(cases []x86OfficialPackedCase) (string, string) {
			return x86OfficialMoveRemainderAssembly(t, "amd64", cases)
		}, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86OfficialMoveRemainderNamedShadowsRetainOriginalBytes(t *testing.T) {
	rows := x86OfficialMoveRemainderRows(t)
	count, full, partial := 0, 0, 0
	for _, row := range rows {
		shadowed := 0
		for _, shadow := range row.Witnesses {
			target := x86OfficialMoveRemainderShadowTarget(row, shadow)
			if target == "" {
				continue
			}
			var earlier *goasmrules.X86PackedBinaryWitness
			for _, candidate := range rows {
				if strings.HasSuffix(candidate.ID, target) {
					for index := range candidate.Witnesses {
						if candidate.Witnesses[index].Instruction == shadow.Instruction {
							earlier = &candidate.Witnesses[index]
						}
					}
				}
			}
			if earlier == nil || bytes.Equal(earlier.Encoding, shadow.Encoding) {
				t.Fatal("shadow lost its distinct earlier original encoding", row.ID, shadow.Instruction)
			}
			fixtures := []x86OfficialPackedCase{{row: row.ID, witness: shadow}}
			source, _ := x86OfficialMoveRemainderAssembly(t, "amd64", fixtures)
			listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
			if err != nil {
				t.Fatal(err)
			}
			observed := fixtures[0]
			observed.witness = *earlier
			if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{observed}); err != nil {
				t.Fatal("actual Go changed original first-match selection", row.ID, target, err)
			}
			if err := x86OfficialPackedVerifyListing(listing, fixtures); err == nil {
				t.Fatal("earlier bytes falsely counted as the shadowed source row", row.ID)
			}
			count++
			shadowed++
		}
		if shadowed == len(row.Witnesses) {
			full++
		} else if shadowed != 0 {
			partial++
		}
	}
	if count != 14 || full != 8 || partial != 2 {
		t.Fatal("complete move first-match alternatives changed", count, full, partial)
	}
}

func TestX86OfficialMoveRemainderMode32LowBankObjectsAndHighBankContext(t *testing.T) {
	rows := x86OfficialMoveRemainderRows(t)
	low := func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
		return x86OfficialMoveRemainderSelectedRows(rows, true), nil
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86OfficialPackedRowsObjectsForTarget(t, "386", "i386-unknown-linux-gnu", low, 54, 58, 0,
		func(cases []x86OfficialPackedCase) (string, string) {
			return x86OfficialMoveRemainderAssembly(t, "386", cases)
		}, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "i386-unknown-linux-gnu", ir, "-O2")
		})
	// Go's oclass accepts X/Y16..31 as Evex in 386, but Z8..31 is Yxxx;
	// its parser also restricts four x86 operands to AMD64. Bind bare bytes or
	// concrete rejection independently of producer seeds. Neither outcome
	// supplies unavailable mode32 NUM aliases.
	count, accepted, rejected := 0, 0, 0
	boundaries := map[string]int{}
	for _, row := range x86OfficialMoveRemainderSelectedRows(rows, false) {
		for _, w := range row.Witnesses {
			if w.Generation != "evex" {
				continue
			}
			fixtures := []x86OfficialPackedCase{{row: row.ID, witness: w}}
			source, declaration := x86OfficialMoveRemainderAssembly(t, "386", fixtures)
			bare := "TEXT ·HighBank(SB),4,$0-0\n" + w.Instruction + "\nRET\n"
			if w.Width == 512 || len(strings.Split(strings.Fields(w.Instruction)[1], ",")) == 4 {
				goAssemblerOracleOutput(t, "386", bare, "", false)
				rejected++
			} else {
				listing, err := x86ScalarLiteralGoListing(t, "386", bare)
				if err != nil {
					t.Fatal(err)
				}
				original := x86OfficialPackedCase{row: row.ID, symbol: "HighBank", line: 2, witness: w}
				if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{original}); err != nil {
					t.Fatal("Go386 accepted high-bank spelling changed physical bytes", err)
				}
				accepted++
			}
			boundaries[x86OfficialMoveRemainderMode32InstructionBoundary(t, row.ID, w)]++
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", "i386-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("mode32 high-bank source borrowed physical encoding as NUM input", row.ID, api, err)
				}
			}
			count++
		}
	}
	if count != 47 {
		t.Fatal("complete late-EVEX mode32 source-context observations changed", count)
	}
	t.Logf("mode32 bare late-EVEX outcomes: %d actual byte identities, %d concrete Go Z-bank/arity rejections; direct mode guards=%d, grammar refusals=%d, paired low/high defined NUM controls=%d; initialized whole-source Context is separate",
		accepted, rejected, boundaries["mode"], boundaries["grammar"], boundaries["NUM"])
}
