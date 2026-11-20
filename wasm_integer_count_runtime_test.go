package plan9asm

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type wasmIntegerCountRow struct {
	Name  string
	Cases [][2]string
}

func wasmIntegerCountFixture(t *testing.T) (string, string, string, map[string]FuncSig, []byte, int) {
	t.Helper()
	var source, original, goSource strings.Builder
	goSource.WriteString("package main\n\nimport \"fmt\"\n\n")
	var rows []wasmIntegerCountRow
	sigs := make(map[string]FuncSig)
	count := 0
	for _, opcode := range wasmIntegerCountGoNames(t) {
		name := strings.ToLower(opcode)
		body := wasmIntegerCountBody(opcode, "R0")
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", name, body)
		fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-16\nMOVD a+0(FP),R0\nGet SP\n%sI64Store ret+8(FP)\nRET\n", name, body)
		fmt.Fprintf(&goSource, "func %s(a uint64) uint64\n", name)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: I64}
		row := wasmIntegerCountRow{Name: name}
		inputs := []uint64{0, ^uint64(0), 0x5555555555555555, 0xaaaaaaaaaaaaaaaa, 0xffffffff00000000}
		for bit := uint(0); bit < 64; bit++ {
			inputs = append(inputs, 1<<bit, ^(uint64(1) << bit))
		}
		for _, input := range inputs {
			leading, trailing, ones := bits.LeadingZeros64(input), bits.TrailingZeros64(input), bits.OnesCount64(input)
			if strings.HasPrefix(opcode, "I32") {
				leading, trailing, ones = bits.LeadingZeros32(uint32(input)), bits.TrailingZeros32(uint32(input)), bits.OnesCount32(uint32(input))
			}
			want := ones
			if strings.HasSuffix(opcode, "Clz") {
				want = leading
			} else if strings.HasSuffix(opcode, "Ctz") {
				want = trailing
			}
			row.Cases = append(row.Cases, [2]string{fmt.Sprint(input), fmt.Sprint(want)})
			count++
		}
		rows = append(rows, row)
	}
	goSource.WriteString("\nfunc main() {\n\tcount := 0\n")
	for _, row := range rows {
		for _, sample := range row.Cases {
			fmt.Fprintf(&goSource, "\tif got := %s(%s); got != %s {\n\t\tpanic(fmt.Sprintf(\"%s/%s: %%d\", got))\n\t}\n\tcount++\n",
				row.Name, sample[0], sample[1], row.Name, sample[0])
		}
	}
	goSource.WriteString("\tfmt.Printf(\"integer-count PASS %d\\n\", count)\n}\n")
	if len(rows) != 6 || count != 798 {
		t.Fatal("complete six-opcode, zero/boundary/every-bit runtime inventory changed", len(rows), count)
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return source.String(), original.String(), goSource.String(), sigs, data, count
}

func TestWASMIntegerCountOriginalGoRuntime(t *testing.T) {
	_, source, goSource, _, _, count := wasmIntegerCountFixture(t)
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module integer_count_oracle\ngo 1.20\n", "main.go": goSource, "oracle_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", "oracle.wasm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("original Go build: %v\n%s", err, output)
	}
	cmd, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), filepath.Join(dir, "oracle.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil || strings.TrimSpace(string(output)) != fmt.Sprintf("integer-count PASS %d", count) {
		t.Fatalf("original Go execution: %v\n%s", err, output)
	}
}

func TestWASMIntegerCountLLVMRuntime(t *testing.T) {
	source, _, _, sigs, inputs, count := wasmIntegerCountFixture(t)
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			options := wasmPackedOptions(sigs, WASMABIDirect)
			options.TargetTriple = triple
			ir, err := wasmPackedTranslate(t, file, options, route)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimize := range []bool{false, true} {
				for _, backend := range []string{"0", "2"} {
					t.Run(fmt.Sprintf("%s/%s/IR-O2=%t/llc-O%s", route, triple, optimize, backend), func(t *testing.T) {
						dir := t.TempDir()
						input, object, binary := filepath.Join(dir, "input.ll"), filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
						if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
							t.Fatal(err)
						}
						if optimize {
							optimized := filepath.Join(dir, "optimized.ll")
							wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
							input = optimized
						}
						wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-O"+backend, "-filetype=obj", input, "-o", object)
						wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", object, "-o", binary)
						inputJSON := filepath.Join(dir, "inputs.json")
						if err := os.WriteFile(inputJSON, inputs, 0600); err != nil {
							t.Fatal(err)
						}
						output := wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", wasmIntegerCountNodeCheck, binary, inputJSON)
						if strings.TrimSpace(output) != fmt.Sprintf("integer-count PASS %d", count) {
							t.Fatal("execution did not consume the complete input matrix", output)
						}
					})
				}
			}
		}
	}
}

const wasmIntegerCountNodeCheck = `
const fs = require('fs');
WebAssembly.instantiate(fs.readFileSync(process.argv[1]), {}).then(({instance:{exports:e}}) => {
  const rows = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  let count = 0;
  for (const row of rows) {
    for (const [input, want] of row.Cases) {
      const got = e[row.Name](BigInt(input));
      if (got !== BigInt(want)) throw Error(row.Name + '/' + input + ': ' + got + ' want ' + want);
      count++;
    }
  }
  console.log('integer-count PASS ' + count);
}).catch(error => { console.error(error); process.exit(1); });
`
