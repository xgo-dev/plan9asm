package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86DirectiveResultInitialization(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, directive := range []string{
			"PCALIGN $16",
			"PCALIGNMAX $16,$7",
			"PCDATA $0,$-1",
			"FUNCDATA $0,metadata(SB)",
		} {
			t.Run(arch+"/"+directive, func(t *testing.T) {
				body := fmt.Sprintf("MOVL $1,AX\n%s\nMOVL AX,ret0+0(FP)\nRET", directive)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
				for name, check := range map[string]func(Func, FuncSig, string) error{
					"public":  CheckX86ABI0ResultInitialization,
					"private": checkX86ScalarFPResultInitialization,
				} {
					if err := check(file.Funcs[0], sig, arch); err != nil {
						t.Errorf("%s: valid directive changed numerical availability: %v", name, err)
					}
				}
			})
		}
	}
}

func x86DirectiveValidForms() []string {
	forms := []string{
		"PCDATA $0,$-1", "PCDATA $1,$2",
		"FUNCDATA $0,metadata(SB)", "FUNCDATA $1,metadata<>+0(SB)",
		"FUNCDATA $2,metadata+(4-4)(SB)",
	}
	for _, alignment := range []int{8, 16, 32, 64, 128, 256, 512, 1024, 2048} {
		forms = append(forms, fmt.Sprintf("PCALIGN $%d", alignment))
		for _, limit := range []int{0, alignment - 1} {
			forms = append(forms, fmt.Sprintf("PCALIGNMAX $%d,$%d", alignment, limit))
		}
	}
	return forms
}

func TestX86DirectiveNumericalStateUnchanged(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86DirectiveValidForms() {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, row)
				for _, transfer := range []func(Instr, *x86ResultState, []bool, int64, string) bool{
					x86ResultTransfer, x86ScalarFPResultTransfer,
				} {
					for _, shape := range []bool{false, true} {
						state := x86ResultState{fp: []bool{true, false}, auto: []bool{false, true},
							pointerFP: map[int64]bool{0: true}, shapeOnly: shape, flags: x86ByteFlagCF}
						for index := range state.gp {
							state.gp[index] = uint8(index * 7)
							state.pointerGP[index] = index%2 == 0
						}
						for index := range state.xmm {
							state.xmm[index] = uint16(index * 31)
							state.vectorUpper[index] = uint64(index) << 40
						}
						state.masks[3] = true
						before := state.clone()
						if !transfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
							t.Fatal("directive changed definedness or pointer/flag identity")
						}
					}
				}
			})
		}
	}
}

func TestX86DirectiveMalformedAndUnknownEffects(t *testing.T) {
	rows := []string{
		"PCALIGN", "PCALIGN $16,$1", "PCALIGN $0", "PCALIGN $4", "PCALIGN $24", "PCALIGN $4096",
		"PCALIGN $-16", "PCALIGN $16.0", "PCALIGN $(missing)", "PCALIGN AX", "PCALIGN 16(AX)", "PCALIGN.Z $16",
		"PCALIGNMAX", "PCALIGNMAX $16", "PCALIGNMAX $16,$0,$1", "PCALIGNMAX $16,$16", "PCALIGNMAX $16,$-1",
		"PCALIGNMAX $24,$1", "PCALIGNMAX $16,$1.0", "PCALIGNMAX $16,AX", "PCALIGNMAX AX,$1", "PCALIGNMAX $16,$missing",
		"PCDATA $0", "PCDATA $0,$1,$2", "PCDATA AX,$1", "PCDATA $0,$1.0", "PCDATA $0,$missing", "PCDATA.Z $0,$1",
		"FUNCDATA $0", "FUNCDATA $0,$1", "FUNCDATA AX,metadata(SB)", "FUNCDATA $0.0,metadata(SB)",
		"FUNCDATA $0,metadata", "FUNCDATA $0,metadata(FP)", "FUNCDATA $0,metadata(SB)(AX)",
		"FUNCDATA $0,metadata(SB)(AX*1)", "FUNCDATA $0,metadata+missing(SB)", "FUNCDATA.Z $0,metadata(SB)",
		"FUNCDATA $0,$metadata(SB)", "FUNCDATA $0,metadata+4(SB)", "FUNCDATA $-1,metadata(SB)",
		"PCDATA $-1,$0", "PCDATA $0,$2147483648", "PCDATA $0,$-2147483649",
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			ins := x86PureGPUnknownInstruction(t, row)
			if _, known, err := x86DirectiveProperties(ins); !known || err == nil {
				t.Fatal("invalid directive accepted", known, err)
			}
			for _, target := range x86RawReturnTargets {
				for _, dead := range []bool{false, true} {
					body := row + "\nMOVL $1,ret+0(FP)\nRET"
					if dead {
						body = "MOVL $1,ret+0(FP)\nRET\n" + row
					}
					source := "TEXT ·view(SB),4,$0-4\n" + body + "\n"
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api); err == nil {
							t.Fatal("malformed source bypassed full source grammar", target.triple, dead, api)
						}
					}
				}
			}
		})
	}
	for _, row := range []string{"BYTE $0x90", "WORD $0x9090", "LONG $0", "QUAD $0", "NO_LOCAL_POINTERS", "UNDEF", "NOT_A_DIRECTIVE"} {
		if _, known, _ := x86DirectiveProperties(x86PureGPUnknownInstruction(t, row)); known {
			t.Fatal("unregistered pseudo/native operation acquired numerical noop", row)
		}
	}
}

func TestX86DirectiveDoesNotInitializeOrAuthorizeEffects(t *testing.T) {
	for _, row := range []string{"PCALIGN $16", "PCALIGNMAX $16,$7", "PCDATA $0,$-1", "FUNCDATA $0,metadata(SB)"} {
		for name, body := range map[string]string{
			"missing result": row + "\nRET",
			"unknown GP":     row + "\nMOVL AX,ret0+0(FP)\nRET",
			"unknown vector": row + "\nMOVL X0,ret0+0(FP)\nRET",
			"unknown flags":  row + "\nJE missing\nMOVL $1,ret0+0(FP)\nmissing:\nRET",
			"native pointer": "MOVL $1,AX\n" + row + "\nMOVL (AX),BX\nMOVL BX,ret0+0(FP)\nRET",
			"raw bytes":      row + "\nBYTE $0x90\nMOVL $1,ret0+0(FP)\nRET",
			"unknown dead":   "MOVL $1,ret0+0(FP)\nRET\n" + row + "\nNOT_A_DIRECTIVE\nRET",
		} {
			t.Run(row+"/"+name, func(t *testing.T) {
				for _, arch := range []string{"amd64", "386"} {
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
					for _, check := range []func(Func, FuncSig, string) error{
						CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
					} {
						if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("directive supplied missing numerical/native authority", err)
						}
					}
				}
			})
		}
	}
}

func TestX86DirectiveThreeAPIsFiveLLVMTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			body := strings.Join(x86DirectiveValidForms(), "\n")
			source := "TEXT ·view(SB),4,$0-4\nMOVL $305419896,AX\n" + body + "\nMOVL AX,X0\nMOVL X0,ret+0(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, api)
			}
		})
	}
}

func TestX86DirectiveCommonGoFormats(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		// Old x86 backends predate alignment directives. The shared grammar
		// and LLVM tests above still run there, while these original-Go forms
		// are genuinely common to every supported compiler.
		for _, row := range []string{"PCDATA $0,$-1", "FUNCDATA $0,metadata<>+0(SB)"} {
			goAssemblerOracleOutput(t, arch, "TEXT value(SB),4,$0-0\n"+row+"\nRET\n", "", true)
		}
	}
}

func TestX86DirectiveLayoutIsNotNumericalAuthority(t *testing.T) {
	for _, row := range []string{"PCALIGN $32", "PCALIGNMAX $32,$0", "PCALIGNMAX $32,$31"} {
		t.Run(row, func(t *testing.T) {
			for _, arch := range []string{"amd64", "386"} {
				source := "TEXT refer(SB),4,$0-0\nMOVL data(SB),AX\nRET\nTEXT data(SB),4,$0-0\n" + row + "\nLONG $0xdeadbeef\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				for pass := 0; pass < 2; pass++ {
					file, err = normalizeX86RawFile(file, arch)
					if err != nil {
						t.Fatal(err)
					}
					if file.Funcs[1].X86RawAlign != 32 || string(file.Funcs[1].X86RawText) != string([]byte{0xef, 0xbe, 0xad, 0xde}) {
						t.Fatal("layout-only directive lost exact raw TEXT alignment/bytes")
					}
				}
				framed, err := Parse(ArchAMD64, strings.Replace(source, "TEXT data(SB),4,$0-0", "TEXT data(SB),4,$16-0", 1))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := normalizeX86RawFile(framed, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("layout-only directive authorized a native source frame", err)
				}
				// A native byte jump cannot infer its displacement across an
				// alignment boundary from ordinary numerical no-op semantics.
				crossing, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\nBYTE $0xeb\nBYTE $2\n"+row+"\nBYTE $0x90\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := normalizeX86RawFile(crossing, arch); err == nil {
					t.Fatal("unknown native byte jump crossed layout boundary")
				}
			}
		})
	}
}
