package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// This table is an independent projection of all twelve original AVX rows,
// including their zcase/advances, W bits, transfer opcodes and memory tuples.
func x86OfficialGPSIMDTransferRows(t *testing.T) []string {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VMOVD" && rule.Opcode != "VMOVQ" {
			continue
		}
		classes := [][]string{{"Yxr", "Yml"}, {"Yml", "Yxr"}, {"YxrEvex", "Yml"}, {"Yml", "YxrEvex"}}
		zCases := []string{"Zvex_r_v_rm", "Zvex_rm_v_r", "Zevex_r_v_rm", "Zevex_rm_v_r"}
		offsets := []int{0, 2, 4, 7}
		advances := []int{2, 2, 3, 3}
		opcodes := []string{"0x7E", "0x6E", "0x7E", "0x6E"}
		ws := []string{"W0", "W0", "W0", "W0"}
		pps := []string{"66", "66", "66", "66"}
		sources, destinations := []string{"X0", "AX", "X17", "AX"}, []string{"AX", "X1", "AX", "X17"}
		table, count, tuple := "_yvmovd", 10, "evexN4"
		if rule.Opcode == "VMOVQ" {
			classes = [][]string{{"Yxr", "Yml"}, {"Yxr", "Yxm"}, {"Yml", "Yxr"}, {"Yxm", "Yxr"},
				{"YxrEvex", "Yml"}, {"YxrEvex", "YxmEvex"}, {"Yml", "YxrEvex"}, {"YxmEvex", "YxrEvex"}}
			zCases = []string{"Zvex_r_v_rm", "Zvex_r_v_rm", "Zvex_rm_v_r", "Zvex_rm_v_r", "Zevex_r_v_rm", "Zevex_r_v_rm", "Zevex_rm_v_r", "Zevex_rm_v_r"}
			offsets, advances = []int{0, 2, 4, 6, 8, 11, 14, 17}, []int{2, 2, 2, 2, 3, 3, 3, 3}
			opcodes = []string{"0x7E", "0xD6", "0x6E", "0x7E", "0x7E", "0xD6", "0x6E", "0x7E"}
			ws, pps = []string{"W1", "W0", "W1", "W0", "W1", "W1", "W1", "W1"}, []string{"66", "66", "66", "F3", "66", "66", "66", "F3"}
			sources, destinations = []string{"X0", "X0", "AX", "X0", "X17", "X17", "AX", "X0"}, []string{"AX", "X1", "X1", "X1", "AX", "X0", "X17", "X17"}
			table, count, tuple = "_yvmovq", 20, "evexN8"
		}
		index := rule.RowIndex
		if index < 0 || index >= len(classes) || rule.Ytab != table || rule.Prefix != "Pavx" ||
			!reflect.DeepEqual(rule.Classes, classes[index]) || rule.ZCase != zCases[index] ||
			rule.EncodingOffset != offsets[index] || rule.ZOffset != advances[index] || len(rule.OpBytes) != count {
			t.Fatalf("unmodeled complete GP/SIMD transfer row: %+v", rule)
		}
		generation := "vex"
		if strings.Contains(zCases[index], "evex") {
			generation = "evex"
		}
		terms := []string{"avxEscape", generation + "128", generation + pps[index], generation + "0F", generation + ws[index]}
		if !reflect.DeepEqual(strings.Split(rule.OpBytes[offsets[index]], " | "), terms) {
			t.Fatalf("unmodeled GP/SIMD encoding generation/W/prefix: %+v", rule)
		}
		opcodeIndex := offsets[index] + 1
		if generation == "evex" {
			if rule.OpBytes[opcodeIndex] != tuple {
				t.Fatalf("unmodeled transfer memory width/mask attributes: %+v", rule)
			}
			opcodeIndex++
		}
		if rule.OpBytes[opcodeIndex] != opcodes[index] {
			t.Fatalf("unmodeled complete transfer opcode: %+v", rule)
		}
		rows = append(rows, rule.Opcode+" "+sources[index]+","+destinations[index])
		counts[rule.Opcode]++
	}
	if counts["VMOVD"] != 4 || counts["VMOVQ"] != 8 || len(rows) != 12 {
		t.Fatalf("complete original transfer denominator changed: %v", counts)
	}
	return rows
}

func TestX86GPSIMDTransferCompleteCallerRegistration(t *testing.T) {
	rows := x86OfficialGPSIMDTransferRows(t)
	for _, op := range []string{"MOVL", "MOVQ", "MOVD"} {
		rows = append(rows, op+" AX,X0", op+" X0,AX", op+" (DI),X0", op+" X0,(DX)")
		if op != "MOVL" {
			rows = append(rows, op+" X0,X1")
		}
	}
	for _, op := range []string{"VMOVD", "VMOVQ"} {
		rows = append(rows, op+" (DI),X0", op+" X0,(DX)")
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			ins := x86YMMReadSource(t, row)
			if !x86CallerVectorMoveKnown(ins) {
				t.Fatal("Go-accepted whole-family transfer has no caller effect", row)
			}
		})
	}
}

func TestX86GPSIMDTransferActualSelectedCallerThreeAPIs(t *testing.T) {
	count := 0
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
		for _, direction := range []string{"gp-to-x", "x-to-gp", "memory-load", "memory-store", "x-to-x"} {
			if direction == "x-to-x" && (op == "MOVL" || op == "VMOVD") {
				continue
			}
			count++
			t.Run(op+"/"+direction, func(t *testing.T) {
				body := "MOVQ $7,AX\n" + op + " AX,X1\nVMOVSS X1,(DX)"
				switch direction {
				case "x-to-gp":
					body = "VMOVUPS (DI),X0\n" + op + " X0,AX\nMOVL AX,(DX)"
				case "memory-load":
					body = op + " (DI),X1\nVMOVSS X1,(DX)"
				case "memory-store":
					body = "VMOVUPS (DI),X0\n" + op + " X0,(DX)"
				case "x-to-x":
					body = "VMOVUPS (DI),X0\n" + op + " X0,X1\nVMOVSS X1,(DX)"
				}
				source := x86CallerFixtureSource
				if direction == "memory-store" && op != "MOVL" && op != "VMOVD" {
					source = strings.NewReplacer("var res float32", "var res uint64", ") float32 {", ") uint64 {").Replace(source)
				}
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				goAssemblerOracleOutput(t, "amd64", assembly, "", true)
				pkg, file := x86CallerCoreFixture(t, source, assembly)
				resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs, ResolveSym: resolve}
				ir, err := Translate(file, options)
				if err != nil {
					t.Error("text caller consumer", err)
				} else {
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM22 required")
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "transfer-text.ll", "transfer-text.o", ir)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Error("module caller consumer", err)
				} else {
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM22 required")
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "transfer-module.ll", "transfer-module.o", module.String())
				}
				if err := x86CallerCoreTranslate(t, pkg, assembly, options.TargetTriple); err != nil {
					t.Error("actual selected typed caller", err)
				}
			})
		}
	}
	// Scope denominator is independent of the typed implementation table.
	if count != 28 {
		t.Fatalf("caller direction denominator changed: %d", count)
	}
}
