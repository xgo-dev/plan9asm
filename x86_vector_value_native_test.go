package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent current-Go opcode/attribute inventories are shared with the
// existing exhaustive register and same-file DATA oracles, not production maps.
func x86NativeVectorValueMembers() []x86FixedLaneValueOracle {
	var members []x86FixedLaneValueOracle
	for _, name := range x86IndexedPermuteResultNames {
		members = append(members, x86FixedLaneValueOracle{name: name,
			broadcast: !strings.HasSuffix(name, "B") && !strings.HasSuffix(name, "W")})
	}
	members = append(members, x86GFNIResultOracle...)
	return append(members, x86BitCountResultOracle...)
}

func x86NativeVectorValueFixture(member x86FixedLaneValueOracle, arch, bank, mode string, broadcast, dead bool) (string, string) {
	word, move, maskMove := 8, "MOVQ", "KMOVQ"
	if arch == "386" {
		word, move, maskMove = 4, "MOVL", "KMOVD"
	}
	op, immediate, mask := member.name, "", ""
	if broadcast {
		op += ".BCST"
	}
	if member.immediate {
		immediate = "$99,"
	}
	if mode != "plain" {
		mask = "K1,"
	}
	if mode == "zero" {
		op += ".Z"
	}
	second := bank + "1,"
	if member.unary {
		second = ""
	}
	result := "PEXTRD $0,X2,AX\n"
	if dead {
		result = "MOVL $7,AX\n"
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n%s mask+%d(FP),CX\n"+
		"%s CX,K1\nMOVL $1,DX\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"+
		"%s %s3(AX)(DX*2),%s%s%s2\n%sMOVL AX,ret+%d(FP)\nRET\n",
		2*word+4, move, move, word, maskMove, op, immediate, second, mask, bank, result, 2*word)
	return source, "func Value(p *[128]byte,mask uintptr) uint32"
}

func TestX86VectorValueNativeCompleteFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	members := x86NativeVectorValueMembers()
	if len(members) != 23 {
		t.Fatal("complete native value-family denominator changed", len(members))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for _, member := range members {
				if target.arch == "386" && member.immediate {
					continue // Original cmd/asm named four-operand boundary stays separate.
				}
				for _, mode := range []string{"plain", "merge", "zero"} {
					if target.arch == "386" && !member.unary && mode != "plain" {
						continue // No physical mode32 arity is invented by a numerical proof.
					}
					for _, broadcast := range []bool{false, true} {
						if broadcast && !member.broadcast {
							continue
						}
						body, declaration := x86NativeVectorValueFixture(member, target.arch, "Z", mode, broadcast, false)
						name := fmt.Sprintf("NativeValue%d", len(names))
						names = append(names, name)
						source.WriteString(strings.ReplaceAll(body, "Value", name))
						declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
					}
				}
			}
			want := 111
			if target.arch == "386" {
				want = 53
			}
			if len(names) != want {
				t.Fatal("complete native mode/broadcast denominator changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete initialized native value source rejected", api, err)
				}
				x86CompactExpandRequireAllDefinitions(t, ir, names)
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86VectorValueNativeMissingInputsStayContext(t *testing.T) {
	for _, member := range x86NativeVectorValueMembers() {
		t.Run(member.name, func(t *testing.T) {
			source, declaration := x86NativeVectorValueFixture(member, "amd64", "Z", "merge", false, false)
			body := strings.SplitN(source, "\n", 2)[1]
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", declaration, body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone query borrowed native continued execution", err)
				}
			}
			variants := map[string]string{
				"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
				"numeric-pointer": strings.Replace(source, "MOVL $1,DX", "MOVL $42,AX\nMOVL $1,DX", 1),
				"unknown-index":   strings.Replace(source, "MOVL $1,DX\n", "", 1),
				"unknown-mask":    strings.Replace(source, "KMOVQ CX,K1\n", "", 1),
				"unknown-merge":   strings.Replace(source, "VPXORD Z2,Z2,Z2\n", "", 1),
			}
			if !member.unary {
				variants["unknown-vector"] = strings.Replace(source, "VPXORD Z1,Z1,Z1\n", "", 1)
			}
			for name, changed := range variants {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native result invented a pointer, index, mask, merge or vector", name, api, err)
					}
				}
			}
		})
	}
}

func TestX86VectorValueNativeDeadEmitterKeepsInputRead(t *testing.T) {
	for _, member := range x86NativeVectorValueMembers() {
		for axis, bank := range []string{"X", "Y", "Z"} {
			width := 16 << axis
			for _, broadcast := range []bool{false, true} {
				if broadcast && !member.broadcast {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/broadcast%t", member.name, bank, broadcast), func(t *testing.T) {
					source, _ := x86NativeVectorValueFixture(member, "amd64", bank, "plain", broadcast, true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					var ins Instr
					matches := 0
					for _, instruction := range file.Funcs[0].Instrs {
						base, _, _ := strings.Cut(string(instruction.Op), ".")
						if base == member.name {
							ins = instruction
							matches++
						}
					}
					if matches != 1 {
						t.Fatal("emitter fixture must retain its exact original value opcode", matches)
					}
					consumer, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					var known bool
					if _, _, known, _ = x86IndexedPermuteProperties(ins.Op, ins, "amd64"); known {
						_, _, err = consumer.lowerIndexedPermute(ins.Op, ins)
					} else if _, known, _ = x86GFNIProperties(ins.Op, ins, "amd64"); known {
						_, _, err = consumer.lowerGFNI(ins.Op, ins)
					} else {
						_, _, err = consumer.lowerPackedBitCount(ins.Op, ins)
					}
					if err != nil {
						t.Fatal("unbound instruction-emitter unit failed", ins.Raw, err)
					}
					if broadcast {
						width = 4
						if strings.HasSuffix(member.name, "Q") || strings.HasSuffix(member.name, "PD") || member.immediate {
							width = 8
						}
					}
					if strings.Count(output.String(), fmt.Sprintf("load volatile <%d x i8>", width)) != 1 {
						t.Fatal("dead native input lost its exact observable width", ins.Raw, output.String())
					}
				})
			}
		}
	}
}

func TestX86VectorValueVoidInputsCannotBorrowImplementationSlots(t *testing.T) {
	for _, member := range x86NativeVectorValueMembers() {
		immediate, second := "", "Z1,"
		if member.immediate {
			immediate = "$99,"
		}
		if member.unary {
			second = ""
		}
		for _, variant := range []string{"unknown-registers", "known-registers", "native-pointer", "unknown-pointer"} {
			t.Run(member.name+"/"+variant, func(t *testing.T) {
				prefix, input, args, declaration := "", "Z0", 0, "func Value()"
				if variant != "unknown-registers" {
					prefix = "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
				}
				if variant == "native-pointer" || variant == "unknown-pointer" {
					prefix = "MOVQ p+0(FP),AX\nMOVL $1,DX\n" + prefix
					input, args, declaration = "3(AX)(DX*2)", 8, "func Value(p *[128]byte)"
					if variant == "unknown-pointer" {
						prefix = strings.Replace(prefix, "p+0(FP),AX", "p+0(FP),DI", 1)
					}
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s %s%s,%sZ2\nRET\n",
					args, prefix, member.name, immediate, input, second)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					known := variant == "known-registers" || variant == "native-pointer"
					if known && (ir == "" || err != nil) {
						t.Fatal("complete initialized Void control was lost", api, err)
					}
					if !known && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
						t.Fatal("Void value family borrowed zeroed implementation slots or an unknown address", api, err)
					}
				}
			})
		}
	}
}
