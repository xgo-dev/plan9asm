package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86GPSIMDNativeOracle = []struct {
	op, original string
	width        int
}{
	{"MOVL", "MOVL", 4},
	{"MOVQ", "MOVQ", 8},
	{"MOVD", "MOVD", 8}, // Go's MOVD is the qword alias.
	{"VMOVD", "MOVL", 4},
	{"VMOVQ", "MOVQ", 8},
}

func x86GPSIMDNativeFixture(name, arch, op, address, destination string, lane int) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	extract := "PEXTRD"
	if strings.HasPrefix(op, "V") {
		extract = "VPEXTRD"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DX\nMOVL $1,BX\n%s %s,%s\n%s $%d,%s,AX\nMOVL AX,ret+%d(FP)\nRET\n",
		name, word+4, move, op, address, destination, extract, lane, destination, word)
	return source, fmt.Sprintf("func %s(p *[8]byte) uint32\n", name)
}

func TestX86GPSIMDNativeResultsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86GPSIMDNativeOracle {
				for _, address := range []string{"(DX)", "-1(DX)(BX*1)"} {
					for _, destination := range []string{"X0", "X17"} {
						if destination == "X17" && (target.arch == "386" || !strings.HasPrefix(row.op, "V")) {
							continue // High banks retain their independent grammar/physical-mode checks.
						}
						for lane := 0; lane < 4; lane++ {
							asm, decl := x86GPSIMDNativeFixture(fmt.Sprintf("F%d", count), target.arch, row.op, address, destination, lane)
							source.WriteString(asm)
							declarations.WriteString(decl)
							count++
						}
					}
				}
			}
			want := 56
			if target.arch == "386" {
				want = 40
			}
			if count != want {
				t.Fatal("incomplete native GP/X source and zero-lane matrix", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("GP/X memory read lost its numerical/zero result bytes:", err)
					}
					if strings.Count(ir, "load volatile i") != count {
						t.Fatal("numerical continuation lost a paired native read")
					}
					compileLLVMToObject(t, llc, target.triple, "gp-x-native.ll", "gp-x-native.o", ir)
				})
			}
		})
	}
}

func TestX86GPSIMDNativeResultsRetainSourceBoundaries(t *testing.T) {
	for _, row := range x86GPSIMDNativeOracle {
		t.Run(row.op, func(t *testing.T) {
			source, declaration := x86GPSIMDNativeFixture("Value", "amd64", row.op, "(DX)", "X0", 0)
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", strings.TrimSpace(declaration),
				strings.ReplaceAll(strings.SplitN(source, "\n", 2)[1], "ret+8(FP)", "ret0+8(FP)"))
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone query acquired native memory", err)
				}
			}
			load := row.op + " (DX),X0"
			missing := strings.Replace(source, load, "CMPL BX,$0\nJE after\n"+load+"\nafter:", 1)
			for name, bad := range map[string]string{
				"unknown base":       strings.Replace(source, "(DX)", "(SI)", 1),
				"unknown index":      strings.Replace(source, "(DX)", "(DX)(SI*1)", 1),
				"pointer index":      strings.Replace(source, "(DX)", "(DX)(DX*1)", 1),
				"virtual frame":      strings.Replace(source, "(DX)", "(SP)", 1),
				"unknown static":     strings.Replace(source, "(DX)", "·external(SB)", 1),
				"numeric base":       strings.Replace(source, load, "MOVL $42,DX\n"+load, 1),
				"unknown store data": strings.Replace(source, load, load+"\n"+row.op+" X1,(DX)", 1),
				"missing path":       missing,
			} {
				t.Run(name, func(t *testing.T) {
					goAssemblerOracleOutput(t, "amd64", bad, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, bad, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unproved native transfer boundary accepted", api, err)
						}
					}
				})
			}
		})
	}
}

func TestX86GPSIMDNativeResultBytesAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86GPSIMDNativeOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" -1(DX)(BX*1),X1")
				form, known, err := x86GPSIMDTransferProperties(ins, arch)
				if !known || err != nil || form.bits != row.width*8 {
					t.Fatal("native memory width changed", form, err)
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				base, _, _ := x86ResultGP(DX, 4, arch)
				index, _, _ := x86ResultGP(BX, 4, arch)
				state.pointerGP[base], state.gp[index] = true, 0xff
				state.writeVector(1, 64, 0x0123456789ab0080, false)
				before := state.clone()
				want := uint64(0x0123456789abffff)
				if strings.HasPrefix(row.op, "V") {
					want = ^uint64(0)
				}
				if !x86ResultGPSIMDTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) ||
					state.vectorBytes(1) != want || state.flags != before.flags ||
					state.gp != before.gp || state.pointerGP != before.pointerGP {
					t.Fatal("native transfer lost loaded/zero bytes or changed unrelated state")
				}
				for _, mutation := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment"} {
					changed, rejected := ins, before.clone()
					switch mutation {
					case "decoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "raw return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address":
						changed.x86AddressBits = 32
					case "unbound address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					}
					if x86ResultGPSIMDTransferWithNativeMemory(changed, form, &rejected, nil, 0, arch, true) || !reflect.DeepEqual(rejected, before) {
						t.Fatal("unbound instruction origin acquired native result bytes", mutation)
					}
				}
			})
		}
	}
}
