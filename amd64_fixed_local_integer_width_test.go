package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalIntegerWidthOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	operations := []string{
		"VPMOVSXBW (SP), K7, Z8",
		"VPMOVQB X11, K1, (SP)",
		"VPMOVUSQB Y30, K3, 17(SP)",
		"VPACKUSDW 17(SP)(BP*1), X25, K3, X0",
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalIntegerWidthOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations []string
	traps := make(map[int]bool)
	seen := make(map[string]bool)
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedWideningRows,
		goasmrules.X86SingleSourceNarrowingRows,
		goasmrules.X86PackedNarrowRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				if witness.Generation == "legacy" {
					continue
				}
				operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
				if seen[operation] {
					continue
				}
				index := len(operations)
				assembly.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", index), operation, "", ""))
				operations = append(operations, operation)
				if witness.Destination == "(AX)" && witness.Zeroing {
					traps[index] = true
				}
				seen[operation] = true
			}
		}
	}
	if len(operations) != 694 || len(traps) != 54 {
		t.Fatal("unexpected width-changing source or terminal inventory", len(operations), len(traps))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go width-changing boundaries", len(pcs))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, operation := range operations {
		bytes := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(bytes, 64)
		if err != nil || length != len(bytes) {
			t.Errorf("%s: original bytes %x failed to bind: %d, %v", operation, bytes, length, err)
		}
		_, err = proveX86FixedLocal(file.Funcs[index], sig)
		if traps[index] {
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s: terminal memory zeroing acquired a continuing frame effect: %v", operation, err)
			}
		} else if err != nil {
			t.Errorf("%s: initialized frame did not bind: %v", operation, err)
		}
	}
	t.Logf("checked %d original width-changing rows, including %d terminal forms", len(operations), len(traps))
}

func TestGoAMD64FixedLocalIntegerWidthRIPBoundaryOnly(t *testing.T) {
	var source strings.Builder
	rows := []struct {
		operation string
		decode    func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPMOVZXBQ table<>(SB),K1,X1", decodedX86PackedExtendInstruction},
		{"VPMOVQB X11,K1,table<>(SB)", decodedX86SingleSourceNarrowInstruction},
		{"VPACKUSDW table<>(SB),X25,K3,X0", decodedX86VectorPackedSaturatingNarrowInstruction},
	}
	for _, row := range rows {
		fmt.Fprintln(&source, row.operation)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("missing original RIP-relative width-changing boundaries", pcs)
	}
	for index, row := range rows {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || size != len(encoding) {
			t.Errorf("%s: original RIP bytes %x failed to bind: %d, %v", row.operation, encoding, size, err)
		}
		if _, _, known, err := row.decode(encoding, 64); !known || err == nil {
			t.Errorf("%s: original RIP bytes %x acquired a raw source address", row.operation, encoding)
		}
	}
}

func TestGoAMD64FixedLocalIntegerWidthProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation, tail string
		valid                 bool
	}{
		{"two-byte widening load fits", "VPMOVZXBQ 126(SP),X3", "", true},
		{"two-byte widening load crosses initialized storage", "VPMOVZXBQ 127(SP),X3", "", false},
		{"masked store retains initialized bytes", "VPMOVQB X11,K1,17(SP)", "", true},
		{"masked store alone is legal", "VPMOVQB X11,K1,128(SP)", "NOP", true},
		{"masked store does not initialize an unknown byte", "VPMOVQB X11,K1,128(SP)", "", false},
		{"unmasked store initializes its two bytes", "VPMOVQB X11,128(SP)", "MOVW 128(SP),AX", true},
		{"unmasked store stops at its tuple end", "VPMOVQB X11,128(SP)", "MOVB 130(SP),AL", false},
		{"masked store still requires a bounded tuple", "VPMOVQB X11,K1,255(SP)", "NOP", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalVectorStackAssembly(t, "Value", row.operation, "", "")
			if row.tail != "" {
				_, dest, _ := strings.Cut(row.operation, ",")
				dest = dest[strings.LastIndex(dest, ",")+1:]
				assembly = strings.Replace(assembly, "MOVB "+dest+",AL", row.tail, 1)
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}

	for _, row := range []struct {
		operation string
		source    uint64
		old       uint64
		valid     bool
	}{
		{"VPMOVZXBQ X0,X1", 3, 0, true},
		{"VPMOVZXBQ X0,X1", 1, 0, false},
		{"VPMOVQB X0,K1,X1", 0xffff, 3, true},
		{"VPMOVQB X0,K1,X1", 0xffff, 1, false},
	} {
		ins := x86ScalarLaneInstruction(t, row.operation)
		state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": row.source, "Z1": row.old}, masks: map[Reg]bool{"K1": true}}
		err := fixedLocalVectorStep(&ins, &state, nil, 0)
		if row.valid {
			if err != nil || state.vectors["Z1"] != ^uint64(0) {
				t.Errorf("%s: complete active lanes failed to define the cleared carrier: %v", row.operation, err)
			}
		} else if !errors.Is(err, ErrProbeNeedsContext) || state.vectors["Z1"] != row.old {
			t.Errorf("%s: missing active input acquired a new destination: %v", row.operation, err)
		}
	}
}
