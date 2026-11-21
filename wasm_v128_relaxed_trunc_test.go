package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var wasmV128RelaxedTruncMnemonics = map[string]string{
	"I32x4RelaxedTruncF32x4S": "i32x4.relaxed_trunc_f32x4_s",
	"I32x4RelaxedTruncF32x4U": "i32x4.relaxed_trunc_f32x4_u",
	"I32x4RelaxedTruncF64x2S": "i32x4.relaxed_trunc_f64x2_s_zero",
	"I32x4RelaxedTruncF64x2U": "i32x4.relaxed_trunc_f64x2_u_zero",
}

func TestWASMV128RelaxedTruncRuntime(t *testing.T) {
	var source, machine strings.Builder
	machine.WriteString(".text\n")
	sigs := make(map[string]FuncSig)
	var rows []wasmV128CoreObservation
	constant := func(v [2]uint64) string {
		return fmt.Sprintf("  v128.const %d, %d, %d, %d\n", int32(v[0]), int32(v[0]>>32), int32(v[1]), int32(v[1]>>32))
	}
	for _, form := range wasmV128ConversionTestForms {
		mnemonic, found := wasmV128RelaxedTruncMnemonics[form.name]
		if !found {
			continue
		}
		for _, input := range form.inputs() {
			name := fmt.Sprintf("relaxed%d", len(rows))
			sigs[name] = FuncSig{Name: name, Ret: I32}
			rows = append(rows, wasmV128CoreObservation{Name: name})
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", name, form.comparisonBody(input))

			expected, mask := form.reference(input, true)
			fmt.Fprintf(&machine, ".globl %s\n%s:\n  .functype %s () -> (i32)\n", name, name, name)
			machine.WriteString(constant(input))
			fmt.Fprintln(&machine, "  "+mnemonic)
			machine.WriteString(constant(mask) + "  v128.and\n")
			machine.WriteString(constant(expected) + "  v128.xor\n  v128.any_true\n  end_function\n")
		}
	}
	if len(rows) != 120 {
		t.Fatal("incomplete relaxed truncation runtime inventory", len(rows))
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	const pass = "V128 core PASS 120"
	t.Run("original-machine", func(t *testing.T) {
		dir := t.TempDir()
		asm := filepath.Join(dir, "original.s")
		obj := filepath.Join(dir, "original.o")
		binary := filepath.Join(dir, "original.wasm")
		inputs := filepath.Join(dir, "inputs.json")
		if err := os.WriteFile(asm, []byte(machine.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inputs, data, 0600); err != nil {
			t.Fatal(err)
		}
		wasmFloatBinaryCommand(t, wasmDataTool(t, "llvm-mc"), "-triple=wasm32", "-mattr=+simd128,+relaxed-simd", "-filetype=obj", asm, "-o", obj)
		wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", obj, "-o", binary)
		output := wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", wasmV128CoreNodeCheck, binary, inputs)
		if strings.TrimSpace(output) != pass {
			t.Fatal("incomplete native relaxed truncation execution", output)
		}
	})
	wasmV128CompareLLVMRuntime(t, source.String(), sigs, data, pass)
}
