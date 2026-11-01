package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Reuse the independent complete Go encoder directory, not production-map keys.
// The two mask-data broadcasts have no memory row and remain separate.
func x86BroadcastNativeFixture(arch, row string, dead bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	body := fmt.Sprintf("%s p+0(FP),AX\nMOVL $1,DX\n", move)
	if strings.Contains(row, "K3,") {
		body += "MOVL $5,CX\nKMOVD CX,K3\n"
		if !strings.Contains(row, ".Z ") {
			body += "VPXORD Z2,Z2,Z2\n"
		}
	}
	body += strings.Replace(row, "table<>+0(SB)", "3(AX)(DX*2)", 1) + "\n"
	if dead {
		body += "MOVL $7,AX\n"
	} else {
		body += "VPEXTRD $0,X2,AX\n"
	}
	body += fmt.Sprintf("MOVL AX,ret+%d(FP)\nRET\n", word)
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word+4, body),
		"func Value(p *[64]byte) uint32"
}

func TestX86BroadcastPairedNativeReadCompleteFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86BroadcastMemoryRows()
	if len(rows) != 104 {
		t.Fatal("independent complete broadcast directory changed", len(rows))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, dead := range []bool{false, true} {
				for start := 0; start < len(rows); start += 64 {
					end := start + 64
					if end > len(rows) {
						end = len(rows)
					}
					t.Run(fmt.Sprintf("dead-%t/batch-%d", dead, start/64), func(t *testing.T) {
						var assembly, declarations strings.Builder
						var names []string
						for index, row := range rows[start:end] {
							source, declaration := x86BroadcastNativeFixture(target.arch, row, dead)
							name := fmt.Sprintf("Broadcast%d", index)
							names = append(names, name)
							assembly.WriteString(strings.ReplaceAll(source, "Value", name))
							declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
						}
						x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
								if err != nil {
									t.Fatal("complete broadcast lost its paired native input", err)
								}
								for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
									x86BroadcastRequireNativeLoads(t, text, names)
									for _, level := range []string{"-O0", "-O2"} {
										x86PackedStringCompileObject(t, llc, target.triple, text, level)
									}
								}
							})
						}
					})
				}
			}
		})
	}
}

func x86BroadcastRequireNativeLoads(t *testing.T, ir string, names []string) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		function := module.NamedFunction(name)
		if function.IsNil() || function.FirstBasicBlock().IsNil() || !strings.Contains(function.String(), "load volatile") {
			t.Fatal("live or dead broadcast discarded its original function or native access", name)
		}
	}
}

func TestX86BroadcastPairedNativeReadKeepsSourceAndQueryBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range x86BroadcastMemoryRows() {
			source, declaration := x86BroadcastNativeFixture(arch, row, false)
			body := source[strings.Index(source, "\n")+1:]
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, body)
			for _, check := range []func(Func, FuncSig, string) error{
				CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
			} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone query acquired paired native backing", arch, row, err)
				}
			}
			remove := []string{fmt.Sprintf("%s p+0(FP),AX\n", move), "MOVL $1,DX\n"}
			if strings.Contains(row, "K3,") {
				remove = append(remove, "KMOVD CX,K3\n")
				if !strings.Contains(row, ".Z ") {
					remove = append(remove, "VPXORD Z2,Z2,Z2\n")
				}
			}
			for _, missing := range remove {
				changed := strings.Replace(source, missing, "", 1)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("broadcast invented a missing native input", arch, row, missing, api, err)
					}
				}
			}
		}
	}
}

func TestX86BroadcastMaskDataCompleteResultInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, mask := range []int{0, 3, 7} {
					row := fmt.Sprintf("%s K%d,%s2", name, mask, bank)
					t.Run(arch+"/"+row, func(t *testing.T) {
						for _, consumer := range x86ResultGPSIMDConsumers {
							for _, known := range []bool{false, true} {
								state := x86ResultState{flags: x86ByteFlagsAll}
								state.writeVector(2, 64, 0, false)
								state.masks[mask] = known
								before := state.clone()
								if accepted := consumer.step(x86YMMReadSource(t, row), &state, nil, 0, arch); accepted != known {
									t.Fatal("mask-data broadcast lost its actual input requirement", consumer.name, known)
								}
								if known && (state.vectorBytes(2) != ^uint64(0) || state.flags != before.flags) ||
									!known && !reflect.DeepEqual(state, before) {
									t.Fatal("mask-data broadcast invented bits or lost EVEX upper zeroing", consumer.name)
								}
							}
						}
					})
				}
			}
		}
	}
}
