package plan9asm

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestWASMFloatConstantOriginalGoAndLLVM(t *testing.T) {
	rows := []struct {
		literal string
		bits    int
		want    uint64
	}{
		{"0.0", 32, 0},
		{"-0.0", 32, 0x80000000},
		{"1.0", 32, 0x3f800000},
		{"1.000000059604644775390625", 32, 0x3f800000},
		{"1.000000059604645", 32, 0x3f800001},
		{"1.401298464324817e-45", 32, 1},
		{"1.1754942106924411e-38", 32, 0x007fffff},
		{"3.4028234663852886e38", 32, 0x7f7fffff},
		{"-0.0", 64, 0x8000000000000000},
		{"2.2250738585072014e-308", 64, 0x0010000000000000},
		{"5e-324", 64, 1},
		{"1.7976931348623157e308", 64, 0x7fefffffffffffff},
	}
	var source, original, wrappers, goSource strings.Builder
	goSource.WriteString("package main\nimport (\"encoding/json\";\"fmt\";\"strconv\")\n")
	sigs := make(map[string]FuncSig)
	var observations []wasmFloatBinaryRuntimeRow
	var functions []string
	for i, row := range rows {
		name := fmt.Sprintf("constant%d", i)
		body := fmt.Sprintf("F%dConst $%s\nI%dReinterpretF%d\n", row.bits, row.literal, row.bits, row.bits)
		if row.bits == 32 {
			body += "I64ExtendI32U\n"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", name, body)
		fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-24\nGet SP\n%sI64Store ret+16(FP)\nRET\n", name, body)
		fmt.Fprintf(&goSource, "func %s(a,b uint64) uint64\n", name)
		fmt.Fprintf(&wrappers, "define i64 @probe_%s(i64 %%a, i64 %%b) {\n", name)
		fmt.Fprintf(&wrappers, "  %%value = call i64 @%s()\n  ret i64 %%value\n}\n", name)
		sigs[name] = FuncSig{Name: name, Ret: I64}
		functions = append(functions, name)
		observations = append(observations, wasmFloatBinaryRuntimeRow{
			Name: name, Bits: row.bits, Cases: []wasmFloatBinaryReference{{A: "0", B: "0", Want: fmt.Sprint(row.want)}},
		})
	}
	data, err := json.Marshal(observations)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&goSource, "var inputs=%q\nvar functions=[]func(uint64,uint64)uint64{%s}\n", data, strings.Join(functions, ","))
	goSource.WriteString(wasmFloatBinaryGoCheck)
	t.Run("original-Go", func(t *testing.T) { wasmFloatRunOriginal(t, original.String(), goSource.String(), len(rows)) })
	t.Run("LLVM", func(t *testing.T) {
		wasmFloatRunLLVM(t, source.String(), sigs, wrappers.String(), data, len(rows))
	})
}

func TestWASMFloatConstantInference(t *testing.T) {
	for _, row := range []struct {
		opcode string
		typ    LLVMType
	}{
		{"F32Const", "float"},
		{"F64Const", "double"},
	} {
		sigSource := fmt.Sprintf("TEXT constant(SB),4,$0-0\n%s $1.25\nReturn\n", row.opcode)
		file, err := Parse(ArchWASM, sigSource)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := InferWASMAssemblyFuncSig(file.Funcs[0], "constant")
		if err != nil || sig.Ret != row.typ {
			t.Errorf("%s inference = %s / %v, want %s", row.opcode, sig.Ret, err, row.typ)
		}
		for _, operand := range []string{"", " R0", " $1.0,$2.0", " $symbol(SB)", ".invalid $1.0"} {
			bad, err := Parse(ArchWASM, "TEXT constant(SB),4,$0-0\nRET\n"+row.opcode+operand+"\n")
			if err != nil {
				continue
			}
			if _, err := InferWASMAssemblyFuncSig(bad.Funcs[0], "constant"); err == nil {
				t.Errorf("inference accepted malformed dead %s%s", row.opcode, operand)
			}
			sigs := map[string]FuncSig{"constant": {Name: "constant", Ret: Void}}
			if out, err := Translate(bad, wasmPackedOptions(sigs, WASMABIDirect)); err == nil || out != "" {
				t.Errorf("translation accepted malformed dead %s%s", row.opcode, operand)
			}
		}
	}
}
