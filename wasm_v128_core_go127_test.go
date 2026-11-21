//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestWASMV128ArithmeticActualGoEncoding(t *testing.T) {
	rows := append(wasmV128RelaxedFloatCases(), wasmV128IntegerArithmeticCases()...)
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			object := wasmV128ActualGoBytes(t, wasmV128ArithmeticSource(rows), goos)
			for _, row := range rows {
				store := []byte{0xfd, 0x0b, 0, 0}
				encoding := binary.AppendUvarint([]byte{0xfd}, uint64(row.Code))
				if bytes.Contains(object, append(encoding, store...)) {
					continue
				}
				if row.Code >= 0x100 {
					legacy := []byte{0xfd, byte(row.Code&0x7f) | 0x80, 0x01, 0x02}
					if bytes.Contains(object, append(legacy, store...)) {
						t.Logf("%s has the known extra ULEB byte in Go's relaxed SIMD encoding", row.Opcode)
						continue
					}
				} else if row.Code >= 0x80 && bytes.Contains(object, append(append(encoding, 0x01), store...)) {
					t.Logf("%s has the known trailing nop byte in Go's SIMD encoding", row.Opcode)
					continue
				}
				t.Errorf("missing or unknown original Go object encoding of %s", row.Opcode)
			}
		})
	}
}

func TestWASMV128RoutingActualGoEncoding(t *testing.T) {
	rows := wasmV128RoutingCases()
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			object := wasmV128ActualGoBytes(t, wasmV128RoutingSource(rows), goos)
			for _, row := range rows {
				encoding := binary.AppendUvarint([]byte{0xfd}, uint64(row.Code))
				incomplete := []byte(nil)
				switch {
				case row.Mask != nil:
					incomplete = append([]byte(nil), encoding...)
					for _, index := range row.Mask {
						encoding = append(encoding, byte(index))
					}
				case row.Code >= 0x100:
					incomplete = []byte{0xfd, byte(row.Code&0x7f) | 0x80, 0x01, 0x02}
				}
				store := []byte{0xfd, 0x0b, 0, 0}
				if bytes.Contains(object, append(encoding, store...)) {
					continue
				}
				if len(incomplete) != 0 && bytes.Contains(object, append(incomplete, store...)) {
					t.Logf("%s has a known immediate or ULEB encoding discrepancy in original Go", row.Opcode)
					continue
				}
				t.Errorf("missing or unknown original Go object encoding of %s", row.Opcode)
			}
		})
	}
}

func TestWASMV128RelaxedTruncActualGoEncoding(t *testing.T) {
	var source strings.Builder
	mnemonics := []string{
		"I32x4RelaxedTruncF32x4S", "I32x4RelaxedTruncF32x4U",
		"I32x4RelaxedTruncF64x2S", "I32x4RelaxedTruncF64x2U",
	}
	for index, name := range mnemonics {
		fmt.Fprintf(&source, "TEXT relax%d(SB),4,$0-0\nGet V0\n%s\nReturn\n", index, name)
	}
	data := wasmV128ActualGoBytes(t, source.String(), "js")
	for index, name := range mnemonics {
		op := byte(0x81 + index)
		switch {
		case bytes.Contains(data, []byte{0xfd, op, 0x02, 0x0f}):
			t.Logf("%s has the standard encoding", name)
		case bytes.Contains(data, []byte{0xfd, op, 0x01, 0x02, 0x0f}):
			t.Logf("%s has the known extra ULEB byte in Go's relaxed SIMD encoding", name)
		default:
			t.Errorf("unrecognized original Go encoding for %s", name)
		}
	}
}

func TestWASMV128MemoryActualGoEncoding(t *testing.T) {
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			data := wasmV128ActualGoBytes(t, wasmV128MemorySource, goos)
			for _, encoding := range [][]byte{
				{0xfd, 0x00, 0, 3}, // v128.load at offset 3, alignment 1.
				{0xfd, 0x0b, 0, 0}, // implicit zero destination offset.
				{0xfd, 0x0b, 0, 3}, // offset on the explicit destination.
				{0xfd, 0x0b, 0, 5}, // register spelling supplies only the offset.
			} {
				if !bytes.Contains(data, encoding) {
					t.Errorf("original Go object omitted vector memory encoding % x", encoding)
				}
			}
		})
	}
}

func wasmV128ActualGoBytes(t *testing.T, source, goos string) []byte {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.s"), filepath.Join(dir, "source.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-o", output, input)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=wasm", "GOTOOLCHAIN=local")
	if log, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go %s/wasm assembly: %v\n%s", goos, err, log)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Go's assembler gained the SIMD namespace in Go 1.27. Its independent
// original-object/runtime checks must not hide minimum-Go LLVM coverage.
func TestWASMV128CoreActualGoNamespaceAndObjects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	pattern := `"(V128(?:Const|Not|And|Andnot|Or|Xor|Bitselect|AnyTrue)` +
		`|I(?:8x16|16x8|32x4|64x2)(?:Add(?:Sat[SU])?|Sub(?:Sat[SU])?|Mul|Eq|Ne|(?:Lt|Gt|Le|Ge|Min|Max)[SU]|Abs|Neg|AllTrue|Bitmask|Shl|ShrS|ShrU|Popcnt)` +
		`|I(?:16x8|32x4|64x2)(?:Extend(?:Low|High)|Extmul(?:Low|High)|ExtaddPairwise)I(?:8x16|16x8|32x4)[SU]` +
		`|I(?:8x16|16x8)NarrowI(?:16x8|32x4)[SU]` +
		`|I32x4(?:TruncSatF32x4[SU]|TruncSatF64x2[SU]Zero)` +
		`|I32x4RelaxedTrunc(?:F32x4|F64x2)[SU]` +
		`|F32x4(?:ConvertI32x4[SU]|DemoteF64x2Zero)|F64x2(?:ConvertLowI32x4[SU]|PromoteLowF32x4)` +
		`|F(?:32x4|64x2)(?:Abs|Neg|Sqrt|Ceil|Floor|Trunc|Nearest|Add|Sub|Mul|Div|Min|Max|Pmin|Pmax|Eq|Ne|Lt|Gt|Le|Ge))"`
	for _, match := range regexp.MustCompile(pattern).FindAllSubmatch(data, -1) {
		names = append(names, string(match[1]))
	}
	want := wasmV128CoreNames()
	sort.Strings(names)
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("complete official V128 core namespace changed: %v", names)
	}
	source, _ := wasmV128CoreObjectFixture()
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source, goos)
	}
}

func TestWASMV128CoreOriginalGoRuntime(t *testing.T) {
	_, source, program, _, _ := wasmV128CoreRuntimeFixture(t)
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module v128_core_oracle\ngo 1.20\n", "main.go": program, "oracle_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-o", "oracle.wasm", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOWORK=off", "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go V128 core build: %v\n%s", err, output)
	}
	command, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), filepath.Join(dir, "oracle.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || strings.TrimSpace(string(output)) != wasmV128CorePass {
		t.Fatalf("original Go V128 core execution: %v\n%s", err, output)
	}
}

func TestWASMV128LaneActualGoNamespaceAndObjects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"((?:I8x16|I16x8|I32x4|I64x2|F32x4|F64x2)(?:Splat|ExtractLane[SU]?|ReplaceLane))"`)
	names := make(map[string]bool)
	for _, match := range pattern.FindAllSubmatch(data, -1) {
		names[string(match[1])] = true
	}
	want := make(map[string]bool)
	for _, form := range wasmV128LaneTestForms() {
		want[form.name] = true
	}
	if len(names) != 20 || !reflect.DeepEqual(names, want) {
		t.Fatal("SIMD lane encoder namespace changed", names)
	}
	source, _ := wasmV128LaneObjectFixture(t)
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source, goos)
	}
}
