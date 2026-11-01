package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86LegacyIntegerNativeResultSource(arch, op, address string, dead bool) (string, string) {
	move, result, args, offset := "MOVQ", "uint64", 16, 8
	if arch == "386" {
		move, result, args, offset = "MOVL", "uint32", 8, 4
	}
	final := move + " X0,AX"
	if dead {
		final = move + " $7,AX"
	}
	body := fmt.Sprintf("TEXT ·Value(SB),4,$16-%d\n%s p+0(FP),AX\nMOVL $2,CX\nPXOR X0,X0\n%s %s,X0\n%s\n%s AX,ret+%d(FP)\nRET\n",
		args, move, op, address, final, move, offset)
	return body, "func Value(p *[16]byte) " + result + "\n"
}

func TestX86LoweredLegacyIntegerNativeReadCompleteThreeAPIs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			for _, address := range []string{"(AX)", "8(AX)(CX*4)"} {
				for _, dead := range []bool{false, true} {
					source, declaration := x86LegacyIntegerNativeResultSource(arch, op, address, dead)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/%s/%s/dead%t/%s", arch, op, address, dead, api), func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if err != nil {
								t.Fatal("original native full-tuple legacy arithmetic did not supply continued result bytes", err)
							}
							mnemonic := strings.ToLower(op)
							if op == "PADDL" || op == "PADDD" {
								mnemonic = "paddd"
							} else if op == "PSUBL" {
								mnemonic = "psubd"
							}
							if !strings.Contains(ir, "asm sideeffect \""+mnemonic+" ($2), $0\"") || !strings.Contains(ir, "=x,0,r,~{memory}") ||
								strings.Contains(ir, "fixed_local_native") {
								t.Fatal("fault/alignment/full m128 read changed or borrowed local backing", ir)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86LoweredLegacyIntegerNativeReadDoesNotAuthenticateDeclarationQuery(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			source, declaration := x86LegacyIntegerNativeResultSource(arch, op, "(AX)", false)
			pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			sigs, err := goSigsForAsmFile(pkg, file, func(symbol string) string { return strings.TrimPrefix(symbol, "·") }, arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sigs["Value"], arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("declaration-only observer borrowed paired native continued execution", arch, op, err)
			}
		}
	}
}

func TestX86LoweredLegacyIntegerNativeReadRequiresWholeInputsAndKeepsState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			ins := x86PureGPUnknownInstruction(t, op+" 8(AX)(CX*4),X0")
			makeState := func() x86ResultState {
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.pointerGP[0], state.gp[1], state.xmm[0] = true, 0xff, 0xffff
				state.xmm[1], state.vectorUpper[0] = 0x2579, 0xfedcba9876540000
				return state
			}
			for missing := 0; missing < 16; missing++ {
				state := makeState()
				state.xmm[0] &^= uint16(1) << uint(missing)
				before := state.clone()
				if accepted, known := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, arch); accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("native source initialized an unknown old destination byte", arch, op, missing, accepted, known)
				}
			}
			for _, kind := range []string{"unknown pointer", "unknown index", "partial index", "numerical base"} {
				state := makeState()
				switch kind {
				case "unknown pointer":
					state.pointerGP[0] = false
				case "unknown index":
					state.gp[1] = 0
				case "partial index":
					state.gp[1] = 3
				case "numerical base":
					state.pointerGP[0], state.gp[0] = false, 0xff
				}
				if accepted, known := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, arch); accepted || !known {
					t.Fatal("native source borrowed an unproved address", arch, op, kind, accepted, known)
				}
			}
			for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
				state := makeState()
				state.flags = flags
				before := state.clone()
				if accepted, known := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, arch); !accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("paired full-tuple arithmetic changed unrelated bytes, pointer facts or FLAGS", arch, op, flags, accepted, known)
				}
			}
		}
	}
}

func TestX86LoweredLegacyIntegerNativeReadCannotBorrowOtherRoles(t *testing.T) {
	for _, op := range x86LegacyIntegerArithmeticTestNames {
		for _, address := range []string{"X1", "a+0(FP)", "value-32(SP)", "·data(SB)", "(SP)", "(BP)", "(FS)", "(GS)"} {
			ins := x86PureGPUnknownInstruction(t, op+" "+address+",X0")
			state := x86ResultState{shapeOnly: true, flags: x86ByteFlagsAll}
			state.xmm[0], state.xmm[1] = 0xffff, 0xffff
			if accepted, _ := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, "amd64"); accepted {
				t.Fatal("native conditional source reader borrowed a different operand role", op, address)
			}
		}
		for name, change := range map[string]func(*Instr){
			"physical":              func(i *Instr) { i.x86Encoded = true },
			"raw source":            func(i *Instr) { i.x86SourceRaw = &x86SourceRawInstruction{} },
			"address size":          func(i *Instr) { i.x86AddressBits = 32 },
			"unbound address size":  func(i *Instr) { i.x86UnboundAddressOverride = true },
			"segment":               func(i *Instr) { i.x86SegmentPrefix = 0x64 },
			"numerical certificate": func(i *Instr) { i.x86NumericalRead = &x86NumericalReadCertificate{} },
		} {
			ins := x86PureGPUnknownInstruction(t, op+" (AX),X0")
			change(&ins)
			state := x86ResultState{shapeOnly: true}
			state.xmm[0] = 0xffff
			if accepted, _ := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, "amd64"); accepted {
				t.Fatal("native conditional source reader borrowed an independent physical/certificate role", op, name)
			}
		}
	}
	for _, instruction := range []string{"PADDB (AX),M0", "VPADDD (AX),X0,X1", "VPSUBD (AX),Y0,Y1"} {
		ins := x86PureGPUnknownInstruction(t, instruction)
		state := x86ResultState{shapeOnly: true}
		if accepted, _ := x86ResultLegacyIntegerNativeReadStep(ins, &state, nil, 0, "amd64"); accepted {
			t.Fatal("MMX or VEX tuple borrowed the legacy m128 result rule", instruction)
		}
	}
}

func TestX86LoweredLegacyIntegerNativeReadFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			for index, op := range x86LegacyIntegerArithmeticTestNames {
				name := fmt.Sprintf("LegacyNative%d", index)
				source, declaration := x86LegacyIntegerNativeResultSource(target.arch, op, "(AX)", false)
				assembly.WriteString(strings.ReplaceAll(source, "Value", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Value", name))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete original legacy native family", api, err)
				}
				if strings.Count(ir, "define ") != 17 || strings.Count(ir, "asm sideeffect ") != 17 {
					t.Fatal("complete family/source or original native opcode denominator changed", api)
				}
				for _, optimized := range []bool{false, true} {
					input := ir
					if optimized {
						input = x86UndefinedTrapOptimizedIR(t, input)
					}
					compileLLVMToObject(t, llc, target.triple, "legacy-native.ll", "legacy-native.o", input)
				}
			}
		})
	}
}

func TestX86LegacyIntegerNativeMemoryCompleteFeatureInference(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			for _, address := range []string{"(AX)", "8(AX)(CX*4)", "·constant(SB)"} {
				instruction := x86PureGPUnknownInstruction(t, op+" "+address+",X0")
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}})
				if !strings.Contains(features, "+sse2") {
					t.Fatalf("complete legacy m128 instruction requires XMM registers: %s/%s/%s: %q", arch, op, address, features)
				}
			}
		}
	}
}
