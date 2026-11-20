package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The independent Go directory includes all twelve yxmov opcodes and MOVOA's
// frontend alias. Sharing yxmov does not share lane, source or memory effects.
var x86CallerLegacyMoveDirectory = []struct {
	name, prefix, bytes string
	width               int64
	half, aligned       bool
}{
	{"MOVAPD", "Pe", "0x28, 0x29", 16, false, true},
	{"MOVAPS", "Pm", "0x28, 0x29", 16, false, true},
	{"MOVO", "Pe", "0x6f, 0x7f", 16, false, true},
	{"MOVOU", "Pf3", "0x6f, 0x7f", 16, false, false},
	{"MOVHPD", "Pe", "0x16, 0x17", 8, true, false},
	{"MOVHPS", "Pm", "0x16, 0x17", 8, true, false},
	{"MOVLPD", "Pe", "0x12, 0x13", 8, true, false},
	{"MOVLPS", "Pm", "0x12, 0x13", 8, true, false},
	{"MOVSD", "Pf2", "0x10, 0x11", 8, false, false},
	{"MOVSS", "Pf3", "0x10, 0x11", 4, false, false},
	{"MOVUPD", "Pe", "0x10, 0x11", 16, false, false},
	{"MOVUPS", "Pm", "0x10, 0x11", 16, false, false},
	{"MOVOA", "Pe", "0x6f, 0x7f", 16, false, true},
}

func TestX86GoCallerLegacyMoveCompleteGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A(MOV\w+), yxmov, (\w+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 12 {
		t.Fatalf("actual Go yxmov opcode/attribute inventory changed: %d", len(rows))
	}
	for index, row := range rows {
		want := x86CallerLegacyMoveDirectory[index]
		if row[1] != want.name || row[2] != want.prefix || row[3] != want.bytes {
			t.Fatalf("actual Go opcode attributes differ: %v want %+v", row, want)
		}
	}
	table := regexp.MustCompile(`(?s)var yxmov = \[\]ytab\{\n(.*?)\n\}`).FindSubmatch(data)
	if len(table) != 2 || strings.Join(strings.Fields(string(table[1])), " ") !=
		"{Zm_r_xm, 1, argList{Yxm, Yxr}}, {Zr_m_xm, 1, argList{Yxr, Yxm}}," {
		t.Fatal("actual Go operand classes, zcases or row-byte advances changed")
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil || !strings.Contains(string(aliases), `instructions["MOVOA"] = x86.AMOVO`) {
		t.Fatal("actual Go MOVOA frontend identity changed", err)
	}
}

func x86CallerLegacyMoveInstruction(t *testing.T, text string) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+text+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86GoCallerLegacyMoveRegisteredEffects(t *testing.T) {
	// A transfer-domain model, not a package/caller authority producer. Complete
	// actual source/signature binding is tested separately below. Input slices
	// retain the existing numerical-origin/nonalias contract, not allocation bounds.
	proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{
		{kind: x86CallerSliceInput, width: 4},
		{kind: x86CallerFreshResult, width: 8},
	}}
	for _, row := range x86CallerLegacyMoveDirectory {
		for _, operands := range []string{"X0,X1", "(DI),X1", "X0,(DX)"} {
			t.Run(row.name+"/"+operands, func(t *testing.T) {
				ins := x86CallerLegacyMoveInstruction(t, row.name+" "+operands)
				original := fmt.Sprintf("%#v", ins)
				if known := x86CallerVectorMoveKnown(ins); known == row.half {
					t.Errorf("caller known axis: got %t, half-unregistered=%t", known, row.half)
				}
				if x86SourceStackInstructionKnown(ins, "MOVQ", "Q", "amd64") {
					t.Error("a move shape alone acquired non-caller source-stack admission")
				}
				if original != fmt.Sprintf("%#v", ins) {
					t.Fatal("known/grammar observation changed original instruction")
				}
				state := x86SourceStackState{
					callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}, DX: {argument: 1}},
					vectors: map[Reg]uint64{"Z0": 0xffff, "Z1": 1 << 40},
					known:   map[Reg]uint8{}, masks: map[Reg]bool{}, partialNumericFlags: x86ByteFlagCF | x86ByteFlagOF,
				}
				wantValid := !row.half && (!row.aligned || operands == "X0,X1") &&
					(operands != "X0,(DX)" || row.width <= 8)
				if valid := x86CallerVectorMoveStep(&ins, &state, proof); valid != wantValid {
					t.Errorf("caller step axis: got %t want %t", valid, wantValid)
				}
				if !x86SourceStackFlagsStep(ins, &state) || x86SourceStackNumericFlagMask(&state) != x86ByteFlagCF|x86ByteFlagOF {
					t.Error("legacy move changed or fabricated numerical flags")
				}
				memory := -1
				if operands == "(DI),X1" {
					memory = 0
				} else if operands == "X0,(DX)" {
					memory = 1
				}
				if memory >= 0 {
					width, write, known := x86InstructionMemoryShape(ins, memory, "amd64")
					if known == row.half || known && (width != row.width || write != (memory == 1)) {
						t.Errorf("memory-shape axis differs: %d/%t/%t", width, write, known)
					}
					if wantValid && (!x86CallerMemoryCertified(ins, memory) || ins.x86CallerMemory[memory].width != row.width) {
						t.Error("accepted read/write lacks its exact instruction-local native width")
					}
				} else if !row.half {
					want := uint64(1)<<40 | 0xffff
					if row.width < 16 {
						want = uint64(1)<<40 | x86CallerVectorByteMask(row.width)
					}
					if state.vectors["Z1"] != want {
						t.Errorf("register transfer fabricated/cleared old X/Y/Z bytes: %x want %x", state.vectors["Z1"], want)
					}
				}
			})
		}
	}
}

func TestX86GoCallerLegacyMoveActualSourceProducer(t *testing.T) {
	for _, row := range x86CallerLegacyMoveDirectory {
		t.Run(row.name, func(t *testing.T) {
			body := row.name + " (DI),X1"
			if row.aligned {
				// The current caller contract has no native alignment witness.
				// Register recognition must not authorize aligned memory.
				body = "VMOVUPS (DI),X1\n" + row.name + " X1,X2"
			}
			assembly := "TEXT ·kernel(SB),4,$0-32\nMOVQ a+0(FP),DI\n" + body + "\nBYTE $0xc3\n"
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			sig := sigs["caller.kernel"]
			if sig.Ret != Void || len(sig.Frame.Results) != 0 || sig.x86CallerRegions == nil ||
				!x86CallerRegionSourceMatches(sig, file.Funcs[0], "amd64") {
				t.Fatal("actual original source and pointer-only Void signature prerequisite missing")
			}
			decoded, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", ResolveSym: resolve, Sigs: sigs}
			proved := normalizeX86RawReturnSourceStack(decoded, options, true, file.Funcs[0])
			if row.half {
				if proved.x86SourceStack != nil {
					t.Fatal("half-vector move inherited an unproved caller byte effect")
				}
				return
			}
			if proved.x86SourceStack == nil || !x86CallerNormalizedSourceMatches(proved, sig) {
				t.Fatalf("existing typed move lacks whole-source caller producer hook: %s", proved.x86SourceStackFailure)
			}
			for _, ins := range proved.Instrs {
				if !row.aligned && ins.Op == Op(row.name) && (!x86CallerMemoryCertified(ins, 0) || ins.x86CallerMemory[0].width != row.width) {
					t.Fatal("actual instruction did not retain exact numerical-source read width")
				}
			}
		})
	}
}

func TestX86GoCallerLegacyMoveDoesNotBorrowUnknownBytesOrRegions(t *testing.T) {
	for _, row := range x86CallerLegacyMoveDirectory {
		if row.half {
			continue
		}
		for _, text := range []string{row.name + " X0,X1", row.name + " (BX),X1", row.name + " X0,(DI)", row.name + " X0,1(DX)"} {
			t.Run(text, func(t *testing.T) {
				ins := x86CallerLegacyMoveInstruction(t, text)
				proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{
					{kind: x86CallerSliceInput, width: 4}, {kind: x86CallerFreshResult, width: row.width},
				}}
				state := x86SourceStackState{
					callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}, DX: {argument: 1}},
					vectors: map[Reg]uint64{"Z0": x86CallerVectorByteMask(row.width) &^ 1},
					known:   map[Reg]uint8{}, masks: map[Reg]bool{},
				}
				valid := x86CallerVectorMoveStep(&ins, &state, proof)
				if text == row.name+" X0,X1" {
					// A register copy may propagate unknown bytes. It may never
					// turn those bytes into a numerically initialized output.
					if valid && state.vectors["Z1"]&x86CallerVectorByteMask(row.width) == x86CallerVectorByteMask(row.width) {
						t.Fatal("register transfer fabricated a missing source byte")
					}
					ins = x86CallerLegacyMoveInstruction(t, row.name+" X1,(DX)")
					valid = x86CallerVectorMoveStep(&ins, &state, proof)
				}
				if valid {
					t.Fatal("move acquired unknown numerical byte/address or exceeded the fresh result envelope")
				}
				if !reflect.DeepEqual(state.callers, map[Reg]x86CallerPointerValue{DI: {argument: 0}, DX: {argument: 1}}) {
					t.Fatal("failed numerical transfer changed pointer provenance")
				}
			})
		}
	}
}
