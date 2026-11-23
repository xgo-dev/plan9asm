package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestInitializedX86SegmentQueryProbes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for initialized selector-query probes")
	}
	type fixture struct {
		role, operands, argument string
		prepare                  func(string, Instr) ([]Instr, bool, error)
	}
	for _, target := range []struct {
		arch, triple, integer string
		word                  int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "uint64", 8},
		{"386", "i386-unknown-linux-gnu", "uint32", 4},
	} {
		t.Run(target.arch, func(t *testing.T) {
			var source, declarations strings.Builder
			var names, locations []string
			nativeReads := 0
			for _, row := range x86SegmentQueryOracle {
				if row.bytes > int64(target.word) {
					continue
				}
				rows := []fixture{
					{"Register", "AX", "", InitializedScalarRegisterProbeSequence},
					{"Pointer", "(BX)", "*uint16", InitializedScalarMemoryProbeSequence},
				}
				if row.bytes != 0 {
					rows[0].operands += ",AX"
					rows[1].operands += ",CX"
					rows = append(rows, fixture{"SharedBase", "(BX),BX", target.integer, InitializedScalarNumericMemoryProbeSequence})
				}
				for _, variant := range rows {
					ins := x86ScalarLaneInstruction(t, row.op+" "+variant.operands)
					sequence, ok, err := variant.prepare(target.arch, ins)
					if !ok || err != nil || len(sequence) < 2 {
						t.Errorf("%s: no initialized probe (%v, %v)", ins.Raw, ok, err)
						continue
					}
					if !reflect.DeepEqual(sequence[len(sequence)-1], ins) {
						t.Fatalf("changed original instruction %q", ins.Raw)
					}
					name := "Query" + row.op + variant.role
					arg, size := "", 0
					if variant.argument != "" {
						arg, size = "memory "+variant.argument, target.word
						nativeReads++
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", name, size)
					for _, step := range sequence {
						source.WriteString(step.Raw + "\n")
					}
					source.WriteString("RET\n")
					fmt.Fprintf(&declarations, "func %s(%s)\n", name, arg)
					names = append(names, name)
					locations = append(locations, ins.Raw)
				}
			}
			if t.Failed() {
				return
			}
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if got := strings.Count(ir, "load volatile i16, ptr"); got != nativeReads {
						t.Fatalf("got %d m16 reads, want %d", got, nativeReads)
					}
					path := x86PackedStringCompileObject(t, llc, target.triple, ir, "-O0")
					requireX86ELFTestFunctions(t, target.arch, path, names, locations)
				})
			}
		})
	}
}
