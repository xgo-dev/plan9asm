package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Preserve every original Go row and every public Context check. The named
// 386 high banks have no physical binding: retain those exact rows as Context,
// not as objects using a fictitious software register. All remaining original
// rows still receive direct-emitter objects; initialized public five-target
// programs live in TestX86SqrtInitializedFiveTargetObjects.
func x86SqrtOriginalFormatObjects(t *testing.T, source, name, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSource(t, source, name, arch, triple)
	local := *file
	local.Funcs = append([]Func(nil), file.Funcs...)
	local.Funcs[0].Instrs = nil
	contextRows := 0
	for _, ins := range file.Funcs[0].Instrs {
		if _, known, err := x86SqrtProperties(ins, arch); known && err != nil {
			if arch != "386" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original Go row became malformed", ins.Raw, err)
			}
			contextRows++
			continue
		}
		local.Funcs[0].Instrs = append(local.Funcs[0].Instrs, ins)
	}
	if arch == "386" && contextRows == 0 || arch == "amd64" && contextRows != 0 {
		t.Fatal("original physical-bank Context partition changed", arch, contextRows)
	}
	t.Logf("original source retained; %d unbound mode32 register rows remain Context", contextRows)
	return x86ScalarFormatObjectUnit(t, &local, signatures, arch, triple, 0)
}

func TestX86SqrtEveryInputByteAndUpperAlias(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86SqrtInputRows(arch) {
			if strings.Contains(row, "(AX)") {
				continue // Native inputs have separate address and access tests.
			}
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				base := strings.Split(string(ins.Op), ".")[0]
				legacy := !strings.HasPrefix(base, "V")
				scalar := strings.HasSuffix(base, "SS") || strings.HasSuffix(base, "SD")
				width := 16
				if strings.HasSuffix(row, "Y2") {
					width = 32
				} else if strings.HasSuffix(row, "Z2") {
					width = 64
				}
				input := width
				if scalar {
					input = 4
					if strings.HasSuffix(base, "SD") {
						input = 8
					}
				}
				required := x86CallerVectorByteMask(int64(input))
				for missing := -1; missing < 192; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.gp[5], state.pointerGP[7], state.callerAddressGP[7], state.masks[1] = 0x53, true, true, true
					for register := 0; register < 3; register++ {
						state.xmm[register], state.vectorUpper[register] = 0xffff, ^uint64(0xffff)
					}
					want := true
					if missing >= 0 {
						register, bit := missing/64, uint(missing%64)
						value := state.vectorBytes(register) &^ (uint64(1) << bit)
						state.xmm[register], state.vectorUpper[register] = uint16(value), value&^0xffff
						want = !(register == 0 && int(bit) < input || register == 2 && int(bit) < input &&
							strings.Contains(row, "K1") && !strings.Contains(row, ".Z"))
					}
					before := state.clone()
					accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
					if accepted != want {
						t.Fatalf("missing byte %d: accepted=%t want=%t", missing, accepted, want)
					}
					if want {
						value := required
						if legacy && scalar {
							value |= before.vectorBytes(2)
						} else if scalar {
							value |= before.vectorBytes(1) & (0xffff &^ required)
						}
						before.writeVector(2, width, value, legacy)
					}
					if !reflect.DeepEqual(state, before) {
						t.Fatalf("missing byte %d changed unrelated state or invented copied upper bytes", missing)
					}
				}
			})
		}
	}
}

func TestX86SqrtLogicalFieldBoundsAndAddressIdentity(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := "Q"
		if target.arch == "386" {
			word = "L"
		}
		for _, body := range []string{
			"LEA%s x+1(FP),AX\nSQRTSS (AX),X0",
			"LEA%s x+0(FP),AX\nSQRTSD (AX),X0",
			"LEA%s ret+RESULT(FP),AX\nSQRTSS (AX),X0",
			"LEA%s x+0(FP),AX\nMOVL $0,AX\nSQRTSS (AX),X0",
			"LEA%s x+0(FP),AX\nMOVL $0,CX\nSQRTSS (AX)(CX*1),X0",
			"LEA%s x+0(FP),AX\nSQRTPS (AX),X0",
		} {
			t.Run(target.triple+"/"+body, func(t *testing.T) {
				declaration := "func view(x float32) float32"
				source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration,
					fmt.Sprintf(body, word)+"\nMOVSS X0,ret+RESULT(FP)")
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("logical sqrt read escaped its exact declared field", api, err)
					}
				}
			})
		}
	}
}
