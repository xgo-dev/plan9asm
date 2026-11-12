package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86OfficialInsertExtractBoundaryRows(t *testing.T) []goasmrules.X86PackedBinaryRow {
	t.Helper()
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86InsertExtractRows(legacy, avx)
	if err != nil || len(rows) != 82 {
		t.Fatal("complete source boundary directory changed", len(rows), err)
	}
	return rows
}

func x86OfficialInsertExtractTerminalSource(t *testing.T, result bool) (string, string, []x86OfficialPackedCase) {
	t.Helper()
	var source, declarations strings.Builder
	var cases []x86OfficialPackedCase
	frame, returns := 0, ""
	if result {
		frame, returns = 8, " uint64"
	}
	for _, row := range x86OfficialInsertExtractBoundaryRows(t) {
		for _, original := range row.Witnesses {
			if !original.Masked || original.Zeroing || original.Destination != "(AX)" {
				continue
			}
			witness := original
			op, operands, found := strings.Cut(witness.Instruction, " ")
			if !found || len(witness.Encoding) != 7 || witness.Encoding[0] != 0x62 || witness.Encoding[3]&0x80 != 0 {
				t.Fatal("original masked store is not the expected EVEX source row", row)
			}
			witness.Instruction, witness.Zeroing = op+".Z "+operands, true
			witness.Encoding = append([]byte(nil), original.Encoding...)
			witness.Encoding[3] |= 0x80
			name := fmt.Sprint("ExtractUndefined", len(cases))
			line := strings.Count(source.String(), "\n") + 2
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s\nRET\n", name, frame, witness.Instruction)
			fmt.Fprintf(&declarations, "func %s()%s\n", name, returns)
			cases = append(cases, x86OfficialPackedCase{row: row.ID + "/memory-Z", symbol: name, line: line, witness: witness})
		}
	}
	if len(cases) != 12 {
		t.Fatal("all eight block members and twelve width rows must retain memory-Z observations", len(cases))
	}
	return source.String(), declarations.String(), cases
}

func TestX86OfficialInsertExtractMemoryZeroingTerminalObjects(t *testing.T) {
	source, declarations, cases := x86OfficialInsertExtractTerminalSource(t, false)
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("stock Go did not emit the original reserved EVEX.z memory bytes", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			const triple = "x86_64-unknown-linux-gnu"
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("Go-encoded architectural #UD must terminate before reading K/vector/address inputs", api, err)
			}
			x86OfficialMoveInspectFaults(t, ir, cases)
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, ir, level)
			}
			for _, foreign := range []string{"aarch64-unknown-linux-gnu", "wasm32-wasi"} {
				translated, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", foreign, api)
				if err == nil || translated != "" {
					t.Fatal("x86 architectural UD2 acquired a foreign backend", foreign, api, err)
				}
			}
		})
	}
}

func TestX86OfficialInsertExtractMemoryZeroingTerminatesLogicalResults(t *testing.T) {
	source, declarations, cases := x86OfficialInsertExtractTerminalSource(t, true)
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("logical result signature changed the original terminal instruction bytes", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			const triple = "x86_64-unknown-linux-gnu"
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("terminal #UD cannot require a numerical value for an unreachable return", api, err)
			}
			x86OfficialMoveInspectFaults(t, ir, cases)
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, ir, level)
			}
		})
	}
}

func TestX86InsertExtractMemoryZeroingCannotAuthorizePrefixMemory(t *testing.T) {
	for _, result := range []bool{false, true} {
		source, declarations, _ := x86OfficialInsertExtractTerminalSource(t, result)
		frame := "$0-0\n"
		if result {
			frame = "$0-8\n"
		}
		for _, prefix := range []struct{ name, source string }{
			{"read", "MOVQ (AX),CX\n"},
			{"known-data-store", "MOVQ $1,CX\nMOVQ CX,(AX)\n"},
		} {
			candidate := strings.ReplaceAll(source, frame, frame+prefix.source)
			goAssemblerOracleOutput(t, "amd64", candidate, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("result=%t/%s/%s", result, prefix.name, api), func(t *testing.T) {
					text, err := x86ScalarFPBitViewAPI(t, candidate, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
					if err == nil || text != "" {
						t.Fatal("a later terminal instruction granted an earlier unproved memory address", api, err)
					}
				})
			}
		}
	}
}

func TestX86OfficialInsertExtractMode32SourceArityBoundary(t *testing.T) {
	low := strings.NewReplacer("X16", "X0", "Y16", "Y0", "Z16", "Z0", "X17", "X1", "Y17", "Y1", "Z17", "Z1", "X18", "X2", "Y18", "Y2", "Z18", "Z2")
	accepted, rejected := 0, 0
	for _, row := range x86OfficialInsertExtractBoundaryRows(t) {
		instruction := low.Replace(row.Witnesses[0].Instruction)
		_, operands, _ := strings.Cut(instruction, " ")
		want := len(strings.Split(operands, ",")) <= 3
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", "", want)
		if want {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted != 34 || rejected != 48 {
		t.Fatal("complete named386 source arity partition changed", accepted, rejected)
	}
	t.Log("82 original row projections: 34 low-bank syntax acceptances and 48 concrete frontend arity rejections; not 82 selected encodings or numerical passes")
}

func TestX86InsertExtractMemoryZeroingHasNoOrdinaryContinuation(t *testing.T) {
	count := 0
	for _, row := range x86OfficialInsertExtractBoundaryRows(t) {
		for _, witness := range row.Witnesses {
			if !witness.Masked || witness.Zeroing || witness.Destination != "(AX)" {
				continue
			}
			op, operands, _ := strings.Cut(witness.Instruction, " ")
			ins := x86ScalarLaneInstruction(t, op+".Z "+operands)
			form, known, err := x86InsertExtractProperties(ins, "amd64")
			if !known || err != nil || !form.undefinedOpcode() {
				t.Fatal("original memory-Z form lost its terminal classification", ins, err)
			}
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.pointerGP[0] = true
			for i := range state.masks {
				state.masks[i] = true
			}
			for i := 0; i < 32; i++ {
				state.writeVector(i, 64, ^uint64(0), false)
			}
			before := state.clone()
			if x86ResultBlockTransferWithNativeMemory(ins, form, &state, nil, 0, "amd64", true) ||
				!reflect.DeepEqual(state, before) {
				t.Fatal("terminal instruction acquired ordinary native-store or numerical effects", ins)
			}
			for _, identity := range []Op{ins.Op, "", "VINSERTF32X4.Z", "UNDEF"} {
				local := ins
				local.Op = identity
				_, trap, err := x86UndefinedTrapProperties(ins.Op, local, "amd64")
				if (trap && err == nil) != (identity == ins.Op || identity == "") {
					t.Fatal("terminal dispatch borrowed a different source opcode", ins.Op, identity, err)
				}
			}
			count++
		}
	}
	if count != 12 {
		t.Fatal("memory-Z continuation controls lost an original width row", count)
	}
}
