package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

// The original format probes declare a frame but never initialize vector or
// address inputs. Keep all three public Context checks and original emitter
// objects; the separate initialized matrices below own public object success.
func x86DwordProductOriginalFormatObject(t *testing.T, source, declarations, arch, triple string, frame int64) string {
	t.Helper()
	_, declarations, found := strings.Cut(declarations, "\n")
	if !found {
		t.Fatal("original format declarations lost their package header")
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("original formats invented vector, mask or native address inputs", api, err)
		}
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "formatprobe", "package formatprobe\n"+declarations)
	signatures := make(map[string]FuncSig)
	for _, function := range file.Funcs {
		name := strings.TrimPrefix(function.Sym, "·")
		sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		signatures[name] = sig
	}
	file, err = normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal(err)
	}
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, frame,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			return c.lowerDwordToQwordMultiply(ins.Op, ins)
		})
}

// These four names and the complete encoder rows are independently checked in
// TestX86DwordProductCompleteIndependentEncoderRows. Reuse the common native
// input matrix, not the implementation's registry.
func x86DwordProductResultRows(arch string) []struct{ op, bank, mode string } {
	return x86FixedBinaryValueRows(arch, []string{"PMULDQ", "PMULULQ", "VPMULDQ", "VPMULUDQ"})
}

func TestX86DwordProductPairedNativeReadCompleteFamily(t *testing.T) {
	x86FixedBinaryCompleteFamilyObjects(t, x86DwordProductResultRows, 20, 8)
}

func TestX86DwordProductPairedNativeReadCannotBorrowInputs(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, x86DwordProductResultRows)
}

func TestX86DwordProductVoidCannotInventRegisterInputs(t *testing.T) {
	x86FixedBinaryVoidInputBoundaries(t, x86DwordProductResultRows)
}

func TestX86DwordProductRawPairedNativeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86FixedBinaryValueRows("amd64", []string{
				"VPMULDQ", "VPMULUDQ", "VPMULDQ.BCST", "VPMULUDQ.BCST",
			}) {
				body, declaration := x86FixedBinaryValueFixture(target.arch, row.op, row.bank, row.mode, false)
				file, err := Parse(ArchAMD64, body)
				if err != nil {
					t.Fatal(err)
				}
				var instruction string
				for _, ins := range file.Funcs[0].Instrs {
					if strings.HasPrefix(string(ins.Op), "VPMULDQ") || strings.HasPrefix(string(ins.Op), "VPMULUDQ") {
						instruction = ins.Raw
					}
				}
				if instruction == "" {
					t.Fatal("independent source lost its arithmetic instruction")
				}
				code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
				body = strings.Replace(body, instruction, x86DwordProductDirectives(code[:len(code)-1]), 1)
				name := fmt.Sprintf("ProductRaw%d", count)
				source.WriteString(strings.ReplaceAll(body, "Value", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
				count++
			}
			if count != 36 {
				t.Fatal("complete raw full/broadcast/mask denominator changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("exact raw input source lost its paired native continuation", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86DwordProductRawVoidCannotInventInputs(t *testing.T) {
	for _, row := range x86FixedBinaryValueRows("386", []string{"VPMULDQ", "VPMULUDQ"}) {
		instruction := fmt.Sprintf("%s %s0,%s1,%s2", row.op, row.bank, row.bank, row.bank)
		code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
		source := "TEXT ·Value(SB),4,$0-0\n" + x86DwordProductDirectives(code[:len(code)-1]) + "RET\n"
		for _, target := range x86RawReturnTargets {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("raw Void opcode borrowed zeroed implementation registers", instruction, target.triple, api, err)
				}
			}
		}
	}
}

func TestX86DwordProductRawSourceCannotBeRebound(t *testing.T) {
	for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
		for _, instruction := range []string{
			name + " X0,X1,X2", name + " Y0,Y1,Y2", name + " Z0,Z1,K1,Z2",
			name + ".BCST.Z 8(AX),Y1,K1,Y2",
		} {
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86DwordProductDirectives(code[:len(code)-1])+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, arch := range []string{"386", "amd64"} {
				normalized, err := normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := normalized.Funcs[0].Instrs[1]
				if !x86RawDwordProductResultSource(ins, arch) {
					t.Fatal("fresh original physical source was not bound", instruction, arch)
				}
				if !x86ResultPreservesPrivateStorage(ins, arch) || x86PreservesNumericalSourceState(ins) {
					t.Fatal("product private-control preservation was confused with inert numerical state")
				}
				for _, direction := range []x86ResultDirection{x86ResultDirectionUnknown,
					x86ResultDirectionForward, x86ResultDirectionBackward, x86ResultDirectionEither} {
					if x86ResultDirectionAfterSource(ins, direction, arch) != direction ||
						x86ResultDirectionAfter(ins, direction) != x86ResultDirectionUnknown {
						t.Fatal("paired product invented DF or granted a standalone raw-source fact")
					}
				}
				state := x86ResultState{valueStack: &x86ResultValueStack{bytes: []uint8{255, 255}, id: true}}
				if !x86ResultValueStackContinuation(ins, &state, arch) {
					t.Fatal("exact product revoked independent live private storage")
				}
				for label, change := range map[string]func(*Instr){
					"absent-origin": func(ins *Instr) { ins.x86SourceRaw = nil },
					"opcode": func(ins *Instr) {
						ins.Op = Op(strings.Replace(string(ins.Op), name, map[string]string{"VPMULDQ": "VPMULUDQ", "VPMULUDQ": "VPMULDQ"}[name], 1))
					},
					"destination": func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = "X3" },
					"address":     func(ins *Instr) { ins.x86AddressBits = 32 },
					"segment":     func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
					"literal":     func(ins *Instr) { ins.x86RIPLiteral = true },
				} {
					t.Run(arch+"/"+instruction+"/"+label, func(t *testing.T) {
						changed := ins
						changed.Args = append([]Operand(nil), ins.Args...)
						change(&changed)
						state := x86ResultState{flags: x86ByteFlagsAll}
						before := state.clone()
						accepted, known := x86LoweredDwordProductResultStep(changed, &state, nil, arch)
						if accepted || !known || x86RawDwordProductResultSource(changed, arch) || !reflect.DeepEqual(before, state) {
							t.Fatal("changed raw source borrowed a paired numerical continuation", accepted, known)
						}
						if x86ResultPreservesPrivateStorage(changed, arch) ||
							x86ResultDirectionAfterSource(changed, x86ResultDirectionEither, arch) != x86ResultDirectionUnknown {
							t.Fatal("changed raw source borrowed private storage or DF preservation")
						}
					})
				}
			}
		}
	}
}
