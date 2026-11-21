//go:build go1.27

package plan9asm

import (
	"bytes"
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

func TestWASMV128RelaxedTruncActualGoEncoding(t *testing.T) {
	var source strings.Builder
	mnemonics := []string{
		"I32x4RelaxedTruncF32x4S", "I32x4RelaxedTruncF32x4U",
		"I32x4RelaxedTruncF64x2S", "I32x4RelaxedTruncF64x2U",
	}
	for index, name := range mnemonics {
		fmt.Fprintf(&source, "TEXT relax%d(SB),4,$0-0\nGet V0\n%s\nReturn\n", index, name)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "relax.s"), filepath.Join(dir, "relax.o")
	if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-o", output, input)
	command.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if log, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go relaxed truncation assembly: %v\n%s", err, log)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
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
