package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

// This is a distinct complete-source counterpart, not a replacement of the
// original Windows runtime owner. Preserve all18 TEXTs, manual transport roles,
// the existing BX-only correction and the C driver. No GoModule ABI is invented
// for cas64's original SI/AX/DX/BX/CX register convention.
var runtime386BoundedScratchPatches = [][2]string{
	{"TEXT floorValue(SB),NOSPLIT,$0-16", "TEXT floorValue(SB),NOSPLIT,$4-16"},
	{"\tFSTCW -2(SP)\n", "\tFSTCW savedCW-2(SP)\n"},
	{"\tMOVW -2(SP), AX\n", "\tMOVW savedCW-2(SP), AX\n"},
	{"\tMOVW AX, -4(SP)\n", "\tMOVW AX, roundCW-4(SP)\n"},
	{"\tFLDCW -4(SP)\n", "\tFLDCW roundCW-4(SP)\n"},
	{"\tFLDCW -2(SP)\n", "\tFLDCW savedCW-2(SP)\n"},
	{"TEXT uint32ToFloat64(SB),NOSPLIT,$0-12", "TEXT uint32ToFloat64(SB),NOSPLIT,$8-12"},
	{"\tMOVL AX, 0(SP)\n", "\tMOVL AX, integer-8(SP)\n"},
	{"\tMOVL $0, 4(SP)\n", "\tMOVL $0, integer-4(SP)\n"},
	{"\tFMOVV 0(SP), F0\n", "\tFMOVV integer-8(SP), F0\n"},
}

func runtime386ScratchReplace(t *testing.T, source, before, after string) string {
	t.Helper()
	if before == after || strings.Count(source, before) != 1 {
		t.Fatalf("scratch producer is not unique: %q", before)
	}
	return strings.Replace(source, before, after, 1)
}

func runtime386BoundedScratchAssembly(t *testing.T) string {
	t.Helper()
	source := runtime386CoreCorrectedAssembly(t)
	for _, patch := range runtime386BoundedScratchPatches {
		source = runtime386ScratchReplace(t, source, patch[0], patch[1])
	}
	return source
}

func runtime386ScratchSourceBodies(t *testing.T, source string) []string {
	t.Helper()
	parts := strings.Split(source, "\nTEXT ")
	if len(parts) != 19 || parts[0] != "" {
		t.Fatal("complete original eighteen-TEXT source inventory changed")
	}
	for index := 1; index < len(parts); index++ {
		parts[index] = "TEXT " + parts[index]
	}
	return parts[1:]
}

func TestRuntimeExec386CoreBoundedScratchKeepsCompleteSource(t *testing.T) {
	for _, pin := range []struct{ name, source, digest string }{
		{"original18", runtime386CoreAssembly, "8cfb20eb17f5105cb92fc184bffa1333007c80fcfe19865795ed15b0c6d1fbb2"},
		{"BX-only18", runtime386CoreCorrectedAssembly(t), "27ba9d589e34fd6be7497b7ea180d498453f2fe9d7b6d1c2aa14ca4cafdeb331"},
		{"original-C-driver", runtime386CoreCSource, "50eb6e546b44eff9347c96721d22f49eb70e0be57b2be06b75c2324cae12916a"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(pin.source))); got != pin.digest {
			t.Fatal("original fixture bytes changed", pin.name, got)
		}
	}
	// Pin the actual manual-options producer, including its ordinary target,
	// modes, complete frame slots and custom-register signature. CRLF source
	// normalization changes no Go token or raw literal value.
	data, err := os.ReadFile("x86_runtime386_core_fixture_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	positions := token.NewFileSet()
	parsed, err := parser.ParseFile(positions, "original-fixture.go", text, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "runtime386CoreOptions" {
			continue
		}
		found++
		start, end := positions.Position(function.Pos()).Offset, positions.Position(function.End()).Offset
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(text[start:end]))); got != "26215a784fbdd37a0375d0c39535bf48a9f79946388671669e975072545d4957" {
			t.Fatal("original manual-options producer changed", got)
		}
	}
	if found != 1 {
		t.Fatal("original manual-options producer is not unique")
	}
	corrected, bounded := runtime386CoreCorrectedAssembly(t), runtime386BoundedScratchAssembly(t)
	restored := bounded
	for _, patch := range runtime386BoundedScratchPatches {
		restored = runtime386ScratchReplace(t, restored, patch[1], patch[0])
	}
	if restored != corrected || strings.Count(bounded, "\tMOVBLZX BX,BX\n") != 1 {
		t.Fatal("bounded counterpart changed more than the two scratch producers or lost the BX correction")
	}
	beforeBodies, afterBodies := runtime386ScratchSourceBodies(t, corrected), runtime386ScratchSourceBodies(t, bounded)
	file, err := Parse(ArchAMD64, bounded)
	if err != nil || len(file.Funcs) != 18 {
		t.Fatal("complete bounded source lost an original TEXT", err)
	}
	options := runtime386CoreOptions()
	if len(options.Sigs) != 18 || options.Goarch != "386" || options.TargetTriple != "i686-pc-windows-msvc" || options.X87Mode != X87Auto {
		t.Fatal("bounded counterpart changed the original target/mode/signature inventory")
	}
	if !reflect.DeepEqual(options.Sigs["cas64"].ArgRegs, []Reg{SI, AX, DX, BX, CX}) || options.Sigs["cas64"].Ret != I1 {
		t.Fatal("bounded scratch fabricated a Go ABI0 cas64 declaration")
	}
	for index, function := range file.Funcs {
		t.Run(function.Sym, func(t *testing.T) {
			if !strings.HasPrefix(afterBodies[index], "TEXT "+function.Sym+"(SB),") || options.Sigs[function.Sym].Name != function.Sym {
				t.Fatal("original ordered TEXT/signature identity changed")
			}
			switch function.Sym {
			case "floorValue":
				if function.FrameSize != 4 || function.ArgSize != 16 || strings.Count(afterBodies[index], "savedCW-2(SP)") != 3 || strings.Count(afterBodies[index], "roundCW-4(SP)") != 2 {
					t.Fatal("floor scratch does not have its exact two distinct bounded words")
				}
			case "uint32ToFloat64":
				if function.FrameSize != 8 || function.ArgSize != 12 || !strings.Contains(afterBodies[index], "MOVL AX, integer-8(SP)\n\tMOVL $0, integer-4(SP)\n\tFMOVV integer-8(SP), F0") {
					t.Fatal("unsigned conversion lost the complete eight-byte integer producer")
				}
			default:
				if beforeBodies[index] != afterBodies[index] {
					t.Fatal("another original TEXT changed", function.Sym)
				}
			}
		})
	}
}

func TestRuntimeExec386CoreBoundedScratchOriginalGoObjects(t *testing.T) {
	for _, row := range []struct{ name, source string }{
		{"original18", runtime386CoreAssembly},
		{"BX-only18", runtime386CoreCorrectedAssembly(t)},
		{"bounded-complete18", runtime386BoundedScratchAssembly(t)},
	} {
		t.Run(row.name, func(t *testing.T) { runtime386CoreGoObject(t, row.source) })
	}
	// These are complete actual Windows386 Go objects, not native execution,
	// memory permission, or original-Go ABI0 validation of the C transport.
}

func TestRuntimeExec386CoreBoundedScratchCompleteTextModuleObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete bounded Windows386 objects require LLVM22 llc")
	}
	source := runtime386BoundedScratchAssembly(t)
	functions, err := Parse(ArchAMD64, source)
	if err != nil || len(functions.Funcs) != 18 {
		t.Fatal("complete bounded source lost its full inventory", err)
	}
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := runtime386CoreTranslate(t, source, api)
			if err != nil || ir == "" {
				t.Fatal("complete bounded source has an independent unclosed contract; backend axes not attempted", err)
			}
			for _, function := range functions.Funcs {
				x86StringMemoryFunction(t, ir, function.Sym)
			}
			if !strings.Contains(ir, "target triple = \"i686-pc-windows-msvc\"") {
				t.Fatal("complete bounded observation changed the original target")
			}
			for _, level := range []string{"0", "2"} {
				input := ir
				if level == "2" {
					input = x86DwordProductIROptimize(t, input)
				}
				for _, backend := range []string{"0", "2"} {
					t.Run("IR"+level+"/backend"+backend, func(t *testing.T) {
						x86PackedStringCompileObject(t, llc, "i686-pc-windows-msvc", input, "-O"+backend)
					})
				}
			}
		})
	}
}

func TestRuntimeExec386CoreBoundedScratchSingleMutationBoundaries(t *testing.T) {
	source := runtime386BoundedScratchAssembly(t)
	mutations := []struct{ name, before, after string }{
		{"floor-zero-frame", "TEXT floorValue(SB),NOSPLIT,$4-16", "TEXT floorValue(SB),NOSPLIT,$0-16"},
		{"floor-physical-SP", "savedCW-2(SP)", "-2(SP)"},
		{"floor-outside-frame", "roundCW-4(SP)", "roundCW-6(SP)"},
		{"floor-missing-CW-write", "\tFSTCW savedCW-2(SP)\n", ""},
		{"floor-partial-CW-write", "\tFSTCW savedCW-2(SP)\n", "\tMOVB $127,savedCW-2(SP)\n"},
		{"floor-missing-round-CW-byte", "\tMOVW AX, roundCW-4(SP)\n", "\tMOVB AX, roundCW-4(SP)\n"},
		{"floor-one-path-no-CW-write", "\tFSTCW savedCW-2(SP)\n", "\tMOVL value+0(FP),AX\n\tTESTL AX,AX\n\tJE noFloorCW\n\tFSTCW savedCW-2(SP)\nnoFloorCW:\n"},
		{"integer-zero-frame", "TEXT uint32ToFloat64(SB),NOSPLIT,$8-12", "TEXT uint32ToFloat64(SB),NOSPLIT,$0-12"},
		{"integer-physical-SP", "integer-8(SP)", "0(SP)"},
		{"integer-outside-frame", "integer-8(SP)", "integer-12(SP)"},
		{"integer-missing-low-write", "\tMOVL AX, integer-8(SP)\n", ""},
		{"integer-missing-high-write", "\tMOVL $0, integer-4(SP)\n", ""},
		{"integer-partial-high-write", "\tMOVL $0, integer-4(SP)\n", "\tMOVW $0, integer-4(SP)\n"},
		{"integer-one-path-no-high-write", "\tMOVL $0, integer-4(SP)\n", "\tTESTL AX,AX\n\tJE noIntegerHigh\n\tMOVL $0, integer-4(SP)\nnoIntegerHigh:\n"},
	}
	for _, mutation := range mutations {
		// Address-role mutations intentionally change every use of exactly one
		// scratch cell; other mutations change one actual source instruction.
		if !strings.Contains(source, mutation.before) {
			t.Fatal("single-axis mutation no longer identifies its source", mutation.name)
		}
		changed := strings.ReplaceAll(source, mutation.before, mutation.after)
		if mutation.name == "integer-physical-SP" {
			changed = strings.ReplaceAll(changed, "integer-4(SP)", "4(SP)")
		} else if mutation.name == "integer-outside-frame" {
			changed = strings.ReplaceAll(changed, "integer-4(SP)", "integer-8(SP)")
		}
		if changed == source || len(runtime386ScratchSourceBodies(t, changed)) != 18 {
			t.Fatal("single-axis mutation lost complete original source", mutation.name)
		}
		for _, api := range []string{"text", "module"} {
			t.Run(mutation.name+"/"+api, func(t *testing.T) {
				ir, err := runtime386CoreTranslate(t, changed, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("changed complete source bypassed scratch/input obligation: output=%t error=%v", ir != "", err)
				}
				t.Logf("actual first Context for %s (not a certificate for a later boundary): %v", mutation.name, err)
			})
		}
	}
	// This951 checkpoint has no new word/integer proof. Retain any real false
	// pass or independent earlier Context; do not weaken these expectations or
	// call an unrelated first rejection proof of a particular scratch boundary.
}
