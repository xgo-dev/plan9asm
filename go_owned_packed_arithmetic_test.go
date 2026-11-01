package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func ownedPackedArithmeticNames() []string {
	// The independent complete Go add/subtract inventory includes PADDD's
	// PADDL alias. The existing word and low-product tables own PMULLW/D.
	return append(append([]string(nil), x86LegacyIntegerArithmeticTestNames...), "PMULLW", "PMULLD")
}

func ownedPackedArithmeticTable() string {
	return strings.Replace(ownedIndexedVectorTable(), "8,$256", "8,$512", 1)
}

func ownedPackedArithmeticFunction(name, opcode, arch, address string, loop bool) (string, string) {
	move, lea, subtract, word := "MOVQ", "LEAQ", "SUBQ", 8
	if arch == "386" {
		move, lea, subtract, word = "MOVL", "LEAL", "SUBL", 4
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s n+0(FP),CX\nPXOR X0,X0\n", name, word*2, move)
	base := "AX"
	switch address {
	case "lea":
		fmt.Fprintf(&source, "%s numericBytes<>(SB),AX\n", lea)
	case "move", "copy":
		fmt.Fprintf(&source, "%s $numericBytes<>(SB),AX\n", move)
		if address == "copy" {
			fmt.Fprintf(&source, "%s AX,BX\n", move)
			base = "BX"
		}
	}
	if loop {
		fmt.Fprintf(&source, "again%s:\n", name)
	}
	for _, offset := range []int{0, 16, 480} {
		memory := fmt.Sprintf("%d(%s)", offset, base)
		if address == "direct" {
			memory = fmt.Sprintf("numericBytes<>+%d(SB)", offset)
		}
		fmt.Fprintf(&source, "%s %s,X0\n", opcode, memory)
	}
	if loop {
		// The count is not a literal index. The literal-only abstract state
		// retains an unknown word before/after SUB; the result CFG owns NUM.
		fmt.Fprintf(&source, "%s $1,CX\nJNE again%s\n", subtract, name)
	}
	fmt.Fprintf(&source, "%s X0,AX\n%s AX,ret+%d(FP)\nRET\n", move, move, word)
	return source.String(), fmt.Sprintf("func %s(n uintptr) uintptr\n", name)
}

func TestX86OwnedPackedArithmeticSourceFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, address := range []string{"lea", "move", "copy"} {
			for _, loop := range []bool{false, true} {
				var assembly strings.Builder
				assembly.WriteString(ownedPackedArithmeticTable())
				for index, op := range ownedPackedArithmeticNames() {
					source, _ := ownedPackedArithmeticFunction(fmt.Sprintf("Value%d", index), op, arch, address, loop)
					assembly.WriteString(source)
				}
				goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
				file, err := Parse(ArchAMD64, assembly.String())
				if err != nil {
					t.Fatal(err)
				}
				resolve := testResolveSym(ordinaryGlobalReadPackage)
				values := x86LoweredStaticAddressValues(file, resolve, nil, arch)
				if len(file.Funcs) != 19 || values == nil || values.numericLiterals["numericBytes<>"] != 512 {
					t.Fatal("complete arithmetic family or readonly numerical object changed", values)
				}
				for index, fn := range file.Funcs {
					t.Run(fmt.Sprintf("%s/%s/loop%t/%s", arch, address, loop, ownedPackedArithmeticNames()[index]), func(t *testing.T) {
						typ, word := I64, int64(8)
						if arch == "386" {
							typ, word = I32, 4
						}
						sig := FuncSig{Name: resolve(fn.Sym), Args: []LLVMType{typ}, Ret: typ, Frame: FrameLayout{
							Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
							Results: []FrameSlot{{Offset: word, Type: typ, Index: 0, Field: -1}},
						}}
						facts, err := proveX86SDKLiteralAccesses(fn, sig, arch, values.numericLiterals)
						if err != nil || len(facts) != 4 {
							t.Fatal("literal base or invariant loop lost its independent complete-source proof", facts, err)
						}
						c := &amd64Ctx{fpStaticAddressValues: values}
						reads := c.ownedIndexedVectorReads(fn, sig, arch)
						if len(reads) != 3 {
							t.Fatal("complete owned DATA arithmetic reads were not handed off", len(reads))
						}
						for ordinal, fact := range reads {
							operand, width, valid := x86OwnedIndexedVectorReadAt(reads, ordinal, fn.Instrs[ordinal])
							if !valid || width != 16 || fact.Symbol != "numericBytes<>" || fact.Minimum != fact.Maximum ||
								!reflect.DeepEqual(operand, fn.Instrs[ordinal].Args[0]) {
								t.Fatal("exact instruction/operand/extent identity changed", fact)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86OwnedPackedArithmeticFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			source.WriteString(ownedPackedArithmeticTable())
			count := 0
			for _, address := range []string{"direct", "lea", "move", "copy"} {
				for _, loop := range []bool{false, true} {
					for _, opcode := range ownedPackedArithmeticNames() {
						assembly, declaration := ownedPackedArithmeticFunction(fmt.Sprintf("Value%d", count), opcode, target.arch, address, loop)
						source.WriteString(assembly)
						declarations.WriteString(declaration)
						count++
					}
				}
			}
			if count != 152 {
				t.Fatal("complete family/address/loop inventory changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete owned readonly arithmetic failed public translation", err)
					}
					if strings.Count(ir, "asm sideeffect ") != count*3 {
						t.Fatal("legacy full-m128 opcode/fault inventory changed")
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}

func TestX86OwnedPackedArithmeticRetainsAuthorityBoundaries(t *testing.T) {
	function, declaration := ownedPackedArithmeticFunction("Value", "PADDD", "amd64", "lea", true)
	base := ownedPackedArithmeticTable() + function
	for _, change := range []struct{ name, before, after string }{
		{"extent", "8,$512", "8,$495"},
		{"mutable", "8,$512", "0,$512"},
		{"relocation", "$0x719283a4b5c6d7e8", "$external(SB)"},
		{"unknown vector", "PXOR X0,X0\n", ""},
		{"numerical base", "LEAQ numericBytes<>(SB),AX", "MOVQ $512,AX"},
		{"pointer as index", "PADDD 0(AX),X0", "PADDD 0(AX)(AX*1),X0"},
		{"partial pointer", "againValue:\n", "againValue:\nMOVB $0,AL\n"},
		{"changed origin", "SUBQ $1,CX", "LEAQ other<>(SB),AX\nSUBQ $1,CX"},
		{"cleared origin", "SUBQ $1,CX", "MOVQ $0,AX\nSUBQ $1,CX"},
		{"vector clobber", "SUBQ $1,CX", "MOVQ X0,AX\nSUBQ $1,CX"},
		{"pointer write", "PADDD 0(AX),X0", "MOVOU X0,0(AX)\nPADDD 0(AX),X0"},
		{"pointer escape", "PADDD 0(AX),X0", "MOVQ AX,ret+8(FP)\nPADDD 0(AX),X0"},
		{"raw", "SUBQ $1,CX", "BYTE $0x90\nSUBQ $1,CX"},
	} {
		t.Run(change.name, func(t *testing.T) {
			if strings.Count(base, change.before) != 1 {
				t.Fatal("negative control lost its exact source location", change.name)
			}
			source := strings.Replace(base, change.before, change.after, 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err == nil || ir != "" {
					t.Fatal("owned DATA arithmetic borrowed a different input/extent/origin contract", api, err)
				}
			}
		})
	}
}

func TestX86OwnedPackedArithmeticFactsCannotMove(t *testing.T) {
	ins := x86PureGPUnknownInstruction(t, "PADDD 16(AX),X0")
	reads := map[int]x86SDKLiteralAccess{3: {Operand: 0, Width: 16, Original: ins}}
	if operand, width, valid := x86OwnedIndexedVectorReadAt(reads, 3, ins); !valid || width != 16 || !reflect.DeepEqual(operand, ins.Args[0]) {
		t.Fatal("positive exact instruction-local fact was not consumed")
	}
	for _, change := range []struct {
		name    string
		ordinal int
		ins     Instr
	}{
		{"ordinal", 4, ins},
		{"opcode", 3, x86PureGPUnknownInstruction(t, "PSUBL 16(AX),X0")},
		{"offset", 3, x86PureGPUnknownInstruction(t, "PADDD 17(AX),X0")},
		{"base", 3, x86PureGPUnknownInstruction(t, "PADDD 16(BX),X0")},
		{"destination", 3, x86PureGPUnknownInstruction(t, "PADDD 16(AX),X1")},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, _, valid := x86OwnedIndexedVectorReadAt(reads, change.ordinal, change.ins); valid {
				t.Fatal("owned read was reused after instruction/ordinal mutation")
			}
		})
	}
}

func TestGoX86SDKLiteralCompleteStoreAndPackedMoveEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var original strings.Builder
		original.WriteString("TEXT ·effects(SB),4,$0-16\n")
		for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
			if arch == "386" && op == "MOVQ" {
				continue
			}
			for _, destination := range []string{"ret+0(FP)", "0(CX)"} {
				for _, source := range []string{"AX", "$1"} {
					text := op + " " + source + "," + destination
					original.WriteString(text + "\n")
					t.Run(arch+"/"+text, func(t *testing.T) {
						state := x86SDKLiteralState{}
						state.gp[3] = x86SDKLiteralValue{symbol: "numericBytes<>"}
						before := state
						if err := x86SDKLiteralTransfer(x86PureGPUnknownInstruction(t, text), &state, FuncSig{}, arch, nil); err != nil || state != before {
							t.Fatal("ordinary typed store changed an unrelated literal origin", err)
						}
						if source == "AX" {
							state.gp[0] = state.gp[3]
							if err := x86SDKLiteralTransfer(x86PureGPUnknownInstruction(t, text), &state, FuncSig{}, arch, nil); err == nil {
								t.Fatal("literal source escaped through a numerical scalar store")
							}
						}
					})
				}
			}
		}
		original.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
	}
	var original strings.Builder
	original.WriteString("TEXT ·moves(SB),4,$0-0\n")
	for _, row := range fixedLocalPackedMoveOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank == "Z" && !row.evex {
				continue
			}
			for _, operands := range []string{"0(CX)," + bank + "0", bank + "0," + bank + "1", bank + "0,0(CX)"} {
				text := row.name + " " + operands
				original.WriteString(text + "\n")
				t.Run(text, func(t *testing.T) {
					state := x86SDKLiteralState{}
					state.gp[3] = x86SDKLiteralValue{symbol: "numericBytes<>"}
					before := state
					if err := x86SDKLiteralTransfer(x86PureGPUnknownInstruction(t, text), &state, FuncSig{}, "amd64", nil); err != nil || state != before {
						t.Fatal("complete packed move changed an unrelated literal origin", err)
					}
				})
			}
		}
	}
	original.WriteString("RET\n")
	goAssemblerOracleOutput(t, "amd64", original.String(), "", true)
}

func TestGoX86SDKLiteralLoopEntryCannotBorrowAnotherPath(t *testing.T) {
	source := `TEXT ·entry<ABIInternal>(SB),4,$0-16
CMPQ AX,$0
JE incoming
MOVQ $numericBytes<>(SB),BX
JMP selected
incoming:
MOVQ DI,BX
selected:
TESTQ CX,CX
join:
MOVOU 0(BX),X0
SUBQ $1,CX
JNE join
MOVQ X0,AX
RET
`
	sig := FuncSig{Name: "example.invalid/owner.entry", Args: []LLVMType{I64, I64, I64, Ptr}, Ret: I64}
	for _, sameOwner := range []bool{true, false} {
		t.Run(fmt.Sprintf("same-owner=%t", sameOwner), func(t *testing.T) {
			text := source
			if sameOwner {
				text = strings.Replace(text, "MOVQ DI,BX", "MOVQ $numericBytes<>(SB),BX", 1)
			}
			file, err := Parse(ArchAMD64, text)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericBytes<>": 512})
			if sameOwner {
				if err != nil || len(facts) != 3 {
					t.Fatal("both independent stable literal loop entries must succeed", facts, err)
				}
			} else if err == nil || facts != nil || !strings.Contains(err.Error(), "mixed origin") {
				t.Fatal("a prior branch's stable label state authorized an unrelated incoming origin", facts, err)
			}
		})
	}
}
