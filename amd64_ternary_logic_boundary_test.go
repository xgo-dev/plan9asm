package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryPhysicalDecoderKeepsReservedAndModeBoundaries(t *testing.T) {
	for _, row := range x86TernaryCompleteOracleRows() {
		if row.memory || row.mask >= 0 {
			continue
		}
		code := x86TernaryIndependentFixtureBytes(row)
		for name, mutate := range map[string]func([]byte) []byte{
			"missing immediate": func(code []byte) []byte { return code[:len(code)-1] },
			"reserved LL":       func(code []byte) []byte { code[3] |= 0x60; return code },
			"zero without mask": func(code []byte) []byte { code[3] |= 0x80; return code },
			"register BCST":     func(code []byte) []byte { code[3] |= 0x10; return code },
			"address override":  func(code []byte) []byte { return append([]byte{0x67}, code...) },
		} {
			for _, mode := range []int{32, 64} {
				changed := mutate(append([]byte(nil), code...))
				if _, _, known, err := decodedX86TernaryLogicInstruction(changed, mode); known && err == nil {
					t.Fatal("invalid physical ternary encoding accepted", row.row, name, mode)
				}
			}
		}
		for _, field := range []struct {
			index int
			clear byte
		}{{1, 0x80}, {1, 0x10}, {1, 0x20}, {1, 0x40}, {2, 0x40}, {3, 0x08}} {
			changed := append([]byte(nil), code...)
			changed[field.index] &^= field.clear
			if _, _, known, err := decodedX86TernaryLogicInstruction(changed, 64); !known || err != nil {
				t.Fatal("valid AMD64 high bank was lost", row.row, field, err)
			}
			if _, _, known, err := decodedX86TernaryLogicInstruction(changed, 32); !known || err == nil {
				t.Fatal("physical386 borrowed an AMD64 high vector bank", row.row, field, err)
			}
		}
		align := append([]byte(nil), code...)
		align[4] = 0x03
		if _, _, known, err := decodedX86VectorAlignInstruction(align, 32); !known || err == nil {
			t.Fatal("ternary-only physical386 repair changed the separate VALIGN boundary")
		}
	}
}

func TestX86TernaryRawContinuationRequiresWholeReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86TernaryCompleteOracleRows() {
			code := x86TernaryIndependentFixtureBytes(row)
			source, _ := x86TernaryInitializedFixture("Value", arch, x86RawDisplacementDirectives(code))
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
			if err != nil {
				t.Fatal(err)
			}
			function := file.Funcs[0]
			sig := FuncSig{Name: "Value", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
			for _, mutation := range []string{"none", "missing replay", "changed spelling", "changed origin", "raw entry"} {
				candidate := function
				candidate.Instrs = cloneX86ReplayInstrs(function.Instrs)
				switch mutation {
				case "missing replay":
					candidate.x86RawReplay = nil
				case "changed spelling":
					candidate.Instrs[1].Raw += " changed"
				case "changed origin":
					for index := range candidate.Instrs {
						if origin := candidate.Instrs[index].x86SourceRaw; origin != nil {
							origin.ternaryLogic.encoded = false
						}
					}
				case "raw entry":
					candidate.X86RawText = []byte{0x90}
				}
				consumer := amd64Ctx{fpScalarSource: candidate, sig: sig, fpSourceSig: sig, goarch: arch}
				err := consumer.checkLoweredScalarFPResultInitialization()
				if mutation == "none" && err != nil || mutation != "none" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("paired ternary numerical role lost complete source or gained raw entry", arch, row.row, mutation, err)
				}
			}
		}
	}
}

func x86TernaryInitializedLiteralSource(index int, row x86TernaryOracleRow) string {
	code := x86TernaryIndependentFixtureBytes(row)
	// Replace the ordinary address with RIP+disp32 to a complete literal
	// after the original raw RET. Immediate remains part of the instruction.
	code = append(append(append([]byte(nil), code[:5]...), 0x15, 1, 0, 0, 0), 150, 0xc3)
	for at := 0; at < row.sourceWidth; at++ {
		code = append(code, byte(at*29+11))
	}
	return fmt.Sprintf("TEXT ·Literal%d(SB),4,$0-0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nMOVL $85,CX\nKMOVD CX,K7\n%s",
		index, x86RawDisplacementDirectives(code))
}

func TestX86TernaryIndependentLiteralOwnerKeepsCompleteInputs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("ternary original literal objects require LLVM22")
	}
	var source, declarations strings.Builder
	count := 0
	for _, row := range x86TernaryCompleteOracleRows() {
		if !row.memory {
			continue
		}
		program := x86TernaryInitializedLiteralSource(count, row)
		source.WriteString(program)
		fmt.Fprintf(&declarations, "func Literal%d()\n", count)
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, program), "amd64")
		if err != nil || len(file.Data) != 1 || len(file.Data[0].Payload) != row.sourceWidth {
			t.Fatal("literal lost its complete original DATA tuple", row.row, err)
		}
		ins := file.Funcs[0].Instrs[5]
		address, valid := x86StaticSBReadAddress(ins.Args[1], "amd64")
		if !valid || !x86RawTernaryLogicLiteralForm(ins, "amd64") {
			t.Fatal("literal lost its separately bound source identity")
		}
		for _, mutation := range []string{"none", "short DATA", "missing mask", "changed tuple", "removed origin"} {
			if mutation == "missing mask" && row.mask < 0 {
				continue
			}
			state := x86TernaryNativeOracleState("amd64", row.width)
			state.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(row.sourceWidth)}
			changed := cloneX86ReplayInstrs([]Instr{ins})[0]
			switch mutation {
			case "short DATA":
				state.loweredStaticReads[address]--
			case "missing mask":
				state.masks[7] = false
			case "changed tuple":
				changed.x86RIPMemoryRead.width--
			case "removed origin":
				changed.x86SourceRaw = nil
			}
			if accepted, known := x86ResultTernaryLogicStep(changed, &state, nil, "amd64"); !known || accepted != (mutation == "none") {
				t.Fatal("literal borrowed missing DATA, mask or identity", row.row, mutation, accepted, known)
			}
		}
		count++
	}
	if count != 36 {
		t.Fatal("incomplete full/broadcast/mask literal directory", count)
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // RIP+disp32 is a physical64 DATA role, not mode32 absolute addressing.
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized original raw literal/RET failed its independent DATA owner", err)
				}
				for _, pipeline := range []struct{ ir, level string }{
					{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
				} {
					x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
				}
			})
		}
	}
}
