package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestX86ABI0Mode32CanonicalBoolDirectCallRevokesDirection(t *testing.T) {
	for _, result := range []string{"bool", "void"} {
		for _, direction := range []string{"CLD", "STD"} {
			for _, shape := range []bool{false, true} {
				name := result + "/" + direction + "/reaching"
				if shape {
					name = result + "/" + direction + "/source-shape"
				}
				t.Run(name, func(t *testing.T) {
					plan, state, owned := x86ABI0BoolCallDomainState(t)
					if result == "void" {
						file, err := Parse(ArchAMD64, x86ABI0BoolVoidCallSource)
						if err != nil {
							t.Fatal(err)
						}
						pkg := mustGoPackage(t, "directions", "package directions\n"+x86ABI0BoolVoidCallDeclarations)
						resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
						sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
						if err != nil {
							t.Fatal(err)
						}
						source, err := prepareX86ABI0BoolCalls(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
						if err != nil || source == nil {
							t.Fatal("actual void CALL observation missing", err)
						}
						plan = source.callers["·probe"]
						state.boolCalls, state.boolOutgoing, state.boolOutgoingCanonical = plan, nil, nil
					}
					state.shapeOnly = shape
					if accepted, known := x86ResultDirectionStep(x86ScalarLaneInstruction(t, direction), &state, "386"); !accepted || !known || state.direction == x86ResultDirectionUnknown {
						t.Fatal("actual typed DF producer did not run")
					}
					before := state.clone()
					ordinal := -1
					for index := range plan.calls {
						ordinal = index
					}
					if ordinal < 0 {
						t.Fatal("complete source CALL member missing")
					}
					ins := plan.function.Instrs[ordinal]
					if accepted, known := x86ABI0BoolCallStep(ordinal+100, ins, &state, owned, 4, "386"); accepted || !known || !reflect.DeepEqual(before, state) {
						t.Fatal("unknown source CALL acquired a direction/result effect")
					}
					// Deliberately call the independent producer without the shared
					// CFG's post-transfer wrapper. Its own machine-clobber boundary
					// must revoke DF for both existing result and no-result roles.
					if accepted, known := x86ABI0BoolCallStep(ordinal, ins, &state, owned, 4, "386"); !accepted || !known || state.direction != x86ResultDirectionUnknown {
						t.Fatal("direct CALL retained the caller's direction fact", state.direction)
					}
					if !reflect.DeepEqual(state.fp, before.fp) || !reflect.DeepEqual(state.canonicalFP, before.canonicalFP) {
						t.Fatal("direction revocation changed independent caller FP knowledge")
					}
					if result == "void" && (len(state.boolOutgoing) != 0 || len(state.boolOutgoingCanonical) != 0) ||
						result == "bool" && (!state.boolOutgoing[4] || !state.boolOutgoingCanonical[4]) {
						t.Fatal("DF revocation created or erased a declared outgoing result role")
					}
				})
			}
		}
	}
}

func TestX86DirectionTypedBoolAndVoidWholeCallThreeAPIs(t *testing.T) {
	for _, result := range []string{"bool", "void"} {
		for _, direction := range []string{"CLD", "STD"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(result+"/"+direction+"/"+api, func(t *testing.T) {
					source, declaration := x86ABI0BoolCallAssembly(x86ABI0BoolCallBody, x86ABI0BoolCallLeaf), x86ABI0BoolCallDeclarations
					target := "CALL ·callee(SB)"
					if result == "void" {
						source, declaration, target = x86ABI0BoolVoidCallSource, x86ABI0BoolVoidCallDeclarations, "CALL ·notify(SB)"
					}
					source = strings.Replace(source, target, direction+"\n"+target+"\nCLD", 1)
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", "i386-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("complete typed CALL/DF composition rejected", err)
					}
				})
			}
		}
	}
}
