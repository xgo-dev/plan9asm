package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func x86LogicalFPDivideVoidSource(t *testing.T, arch, op, divisorType string, offset int64) (string, string) {
	t.Helper()
	declaration := "func Value(low,high uint64,divisor " + divisorType + ",tail uint64)"
	pkg := mustGoPackage(t, "example.invalid/logicalfpdivide", "package logicalfpdivide\n"+declaration+"\n")
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Frame.Params) != 4 || sig.Frame.Params[2].Offset != 16 {
		t.Fatal("independent typed fixture lost its low/high/divisor argument positions", sig.Frame)
	}
	extent := int64(0)
	for _, slot := range sig.Frame.Params {
		if end := slot.Offset + x86FrameScalarBytes(slot.Type, arch); end > extent {
			extent = end
		}
	}
	move := "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s low+0(FP),AX\n%s high+8(FP),DX\n%s divisor%+d(FP)\nRET\n",
		extent, move, move, op, offset), declaration
}

type x86LogicalFPDivideMutation struct {
	name, source, declaration string
	accepted                  bool
}

func x86LogicalFPDivideVoidMutations(t *testing.T, arch, op string, bits int, original, declaration string) []x86LogicalFPDivideMutation {
	t.Helper()
	move := "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var mutations []x86LogicalFPDivideMutation
	for _, change := range []string{"missing-AX", "missing-AH", "missing-DX", "hole", "pointer", "negative", "past-frame", "unwritten-result"} {
		source, decl := original, declaration
		switch change {
		case "missing-AX":
			source = strings.Replace(source, move+" low+0(FP),AX\n", "", 1)
		case "missing-AH":
			source = strings.Replace(source, move+" low+0(FP),AX", "MOVB low+0(FP),AL", 1)
		case "missing-DX":
			source = strings.Replace(source, move+" high+8(FP),DX\n", "", 1)
		case "hole":
			source, decl = x86LogicalFPDivideVoidSource(t, arch, op, "uint8", 17)
		case "pointer":
			source, decl = x86LogicalFPDivideVoidSource(t, arch, op, "*byte", 16)
		case "negative":
			source, decl = x86LogicalFPDivideVoidSource(t, arch, op, "uint64", -1)
		case "past-frame":
			source, decl = x86LogicalFPDivideVoidSource(t, arch, op, "uint64", 128)
		case "unwritten-result":
			source, decl = x86LogicalFPDivideSource("Value", op, arch, bits, false)
			source = strings.Replace(source, "divisor+16(FP)", "quotient+24(FP)", 1)
		}
		// On AMD64 a pointer and uint64 have the same physical argument
		// extent. Their identical assembly bytes must still consume distinct
		// real Go declaration roles, never a fabricated numerical pointer.
		if source == original && decl == declaration {
			t.Fatal("logical FP source mutation did not apply", change)
		}
		mutations = append(mutations, x86LogicalFPDivideMutation{change, source, decl, change == "missing-DX" && bits == 8})
	}
	return mutations
}

// Observe each complete body once, not once per public API. Unique TEXT names
// allow a single original Go object without changing any instruction/offset.
func x86LogicalFPDivideWholeGoPrior(t *testing.T, arch, triple string, sources []string) {
	t.Helper()
	var combined strings.Builder
	for index, source := range sources {
		if strings.Count(source, "TEXT ·Value(SB)") != 1 {
			t.Fatal("logical FP original body lost its unique complete TEXT")
		}
		combined.WriteString(strings.Replace(source, "TEXT ·Value(SB)", fmt.Sprintf("TEXT ·Prior%d(SB)", index), 1))
	}
	x86LEAActualTargetGoObject(t, arch, triple, combined.String())
}

func TestX86ImplicitDivideLogicalFPVoidInputsAndIndependentStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				original, declaration := x86LogicalFPDivideVoidSource(t, arch, row.name, "uint64", 16)
				mutations := x86LogicalFPDivideVoidMutations(t, arch, row.name, row.bits, original, declaration)
				priors := []string{original}
				for _, mutation := range mutations {
					priors = append(priors, mutation.source)
				}
				x86LogicalFPDivideWholeGoPrior(t, arch, triple, priors)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, original, declaration, arch, triple, api); err != nil || ir == "" {
							t.Fatal("dead division must consume its complete owned logical inputs", err)
						}
						for _, mutation := range mutations {
							t.Run(mutation.name, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, mutation.source, mutation.declaration, arch, triple, api)
								if mutation.accepted {
									if err != nil || ir == "" {
										t.Fatal("byte division invented a DX input", err)
									}
									return
								}
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.name) {
									t.Fatal("logical FP division borrowed missing bytes, pointer bits or unrelated Context", mutation.name, err)
								}
							})
						}
					})
				}
			})
		}
	}
}

func TestX86ImplicitDivideLogicalFPStatusAndDirectionControl(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple, move, push, pop, word := "x86_64-unknown-linux-gnu", "MOVQ", "PUSHFQ", "POPQ", 8
		if arch == "386" {
			triple, move, push, pop, word = "i386-unknown-linux-gnu", "MOVL", "PUSHFL", "POPL", 4
		}
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				declaration := "func Value(low,high,divisor uint64) uintptr"
				prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s low+0(FP),AX\n%s high+8(FP),DX\n", 24+word, move, move)
				original := prefix + "STD\n" + row.name + " divisor+16(FP)\n" + push + "\n" + pop + " BX\n" +
					"AND" + move[3:] + " $0x400,BX\nCLD\n" + move + " BX,ret+24(FP)\nRET\n"
				reads := []string{"SETCS BX", "SETPS BX", "SETEQ BX", "SETMI BX", "SETOS BX", "LAHF"}
				statusSources := make(map[string]string)
				priors := []string{original}
				for _, read := range reads {
					result := "BX"
					if read == "LAHF" {
						result = "AH"
					}
					source := strings.Replace(prefix, fmt.Sprint(24+word), "25", 1) + "CMPL AX,AX\n" +
						row.name + " divisor+16(FP)\n" + read + "\nMOVB " + result + ",ret+24(FP)\nRET\n"
					statusSources[read] = source
					priors = append(priors, source)
				}
				x86LogicalFPDivideWholeGoPrior(t, arch, triple, priors)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, original, declaration, arch, triple, api); err != nil || ir == "" {
							t.Fatal("logical division discarded independently defined DF/private FLAGS transport", err)
						}
						for _, read := range reads {
							t.Run(read, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, statusSources[read], "func Value(low,high,divisor uint64) uint8", arch, triple, api)
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), strings.Fields(read)[0]) {
									t.Fatal("division exposed undefined status or failed before the observed status reader", read, err)
								}
							})
						}
					})
				}
			})
		}
	}
}

func TestX86ImplicitDivideLogicalFPDoesNotCreateCrossTargetOrPhysicalStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			for _, sourceKind := range []string{"tmp-8(SP)", "(BP)", "(SI)", "cell(SB)"} {
				t.Run(arch+"/"+row.name+"/"+sourceKind, func(t *testing.T) {
					source, declaration := x86LogicalFPDivideVoidSource(t, arch, row.name, "uint64", 16)
					source = strings.Replace(source, "divisor+16(FP)", sourceKind, 1)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("logical FP inputs authenticated unowned native/frame/static storage", sourceKind, api, err)
						}
					}
				})
			}
			for _, target := range []string{"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown"} {
				t.Run(arch+"/"+row.name+"/"+target, func(t *testing.T) {
					source, declaration := x86LogicalFPDivideVoidSource(t, arch, row.name, "uint64", 16)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, target, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("logical FP division replaced native #DE with a portable result", target, api, err)
						}
					}
				})
			}
		}
	}
}
