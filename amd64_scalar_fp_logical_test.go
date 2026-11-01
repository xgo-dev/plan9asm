package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent Go yxm/ymm and AVX _yvaddsubpd/_yvandnpd/_yvblendmpd
// witnesses. Do not derive the private-consumer denominator from its registry.
var x86ScalarFPLogicalOpcodes = []string{
	"ANDPS", "ANDPD", "ANDNPS", "ANDNPD", "ORPS", "ORPD", "XORPS", "XORPD",
	"PAND", "PANDN", "POR", "PXOR",
	"VANDPS", "VANDPD", "VANDNPS", "VANDNPD", "VORPS", "VORPD", "VXORPS", "VXORPD",
	"VPAND", "VPANDN", "VPOR", "VPXOR",
	"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ",
}

var x86ScalarFPLogicalEVEXOpcodes = []string{
	"VANDPS", "VANDPD", "VANDNPS", "VANDNPD", "VORPS", "VORPD", "VXORPS", "VXORPD",
	"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ",
}

func x86ScalarFPLogicalRow(op string) (row string, destination int) {
	if strings.HasPrefix(op, "V") {
		return op + " X0,X1,X2", 2
	}
	return op + " X0,X1", 1
}

func TestX86ScalarFPLogicalCompleteXFormsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	if len(x86ScalarFPLogicalOpcodes) != 32 {
		t.Fatal("independent Go logical family denominator changed")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86ScalarFPLogicalCompleteSource(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("complete logical inputs lost result initialization: %v", err)
					}
					compileLLVMToObject(t, llc, target.triple, "logical-results-"+api+".ll", "logical-results-"+api+".o", ir)
				})
			}
		})
	}
}

func x86ScalarFPLogicalCompleteSource(t *testing.T, arch string) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	count := 0
	add := func(body, params string, resultOffset int) {
		fmt.Fprintf(&source, "TEXT ·logical%d(SB),4,$0-%d\n%s\nRET\n", count, resultOffset+8, body)
		fmt.Fprintf(&declarations, "func logical%d(%s) uint64\n", count, params)
		count++
	}
	const inputs = "MOVL $1,AX\nMOVL AX,X0\nMOVL $3,BX\nMOVL BX,X1\n"
	for _, op := range x86ScalarFPLogicalOpcodes {
		row, destination := x86ScalarFPLogicalRow(op)
		add(inputs+row+fmt.Sprintf("\nMOVQ X%d,ret+0(FP)", destination), "", 0)
		if !strings.HasPrefix(op, "V") {
			// Complete numerical FP bytes are not a native m128 backing or
			// alignment witness for legacy SSE. Its public Context/fault
			// contract is tested independently of private byte definedness.
			continue
		}
		memory := op + " a+0(FP),X1"
		memory += ",X2"
		add(inputs+memory+fmt.Sprintf("\nMOVQ X%d,ret+16(FP)", destination), "a,b uint64", 16)
	}
	for _, op := range x86ScalarFPLogicalEVEXOpcodes {
		add(inputs+op+".BCST a+0(FP),X1,X2\nMOVQ X2,ret+8(FP)", "a uint64", 8)
		if arch == "amd64" {
			// Go's mode32 parser/grammar has no four-operand masked row.
			// The unmasked and broadcast rows above still compile on both
			// mode32 targets; mask variants are not host-selected skips.
			for _, suffix := range []string{"", ".Z"} {
				init := inputs + "KMOVW AX,K1\n"
				if suffix == "" {
					init += "MOVL AX,X2\n"
				}
				add(init+op+suffix+" X0,X1,K1,X2\nMOVQ X2,ret+0(FP)", "", 0)
			}
		}
	}
	want := 68
	if arch == "amd64" {
		want = 100
	}
	if count != want {
		t.Fatalf("complete independent %s logical source denominator changed: %d want%d", arch, count, want)
	}
	return source.String(), declarations.String()
}

func TestX86ScalarFPLogicalMaskMergeZeroAndCompleteMemoryBytes(t *testing.T) {
	for _, op := range x86ScalarFPLogicalEVEXOpcodes {
		for _, suffix := range []string{"", ".Z"} {
			t.Run(op+suffix, func(t *testing.T) {
				ins := x86YMMReadSource(t, op+suffix+" X0,X1,K1,X2")
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 16; missing++ {
						state := x86ResultState{}
						state.xmm[0], state.xmm[1], state.xmm[2] = 0xffff, 0xffff, 0xffff
						state.masks[1] = true
						if missing >= 0 {
							state.xmm[input] &^= uint16(1) << uint(missing)
						}
						want := state.xmm[0] & state.xmm[1]
						if suffix == "" {
							want &= state.xmm[2]
						}
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") || state.xmm[2] != want {
							t.Fatalf("mask dependency input%d missing%d: got%04x want%04x", input, missing, state.xmm[2], want)
						}
						state.masks[1] = false
						before := state.clone()
						if x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(before, state) {
							t.Fatal("unknown mask acquired a write or numerical proof")
						}
					}
				}
			})
		}
	}
	for _, op := range x86ScalarFPLogicalOpcodes {
		variants := []string{op}
		for _, evex := range x86ScalarFPLogicalEVEXOpcodes {
			if op == evex {
				variants = append(variants, op+".BCST", op+".BCST.Z")
			}
		}
		for _, name := range variants {
			t.Run(name+"/FP-memory", func(t *testing.T) {
				row := name + " a+0(FP),X1"
				if strings.HasSuffix(name, ".Z") {
					row += ",K1,X2"
				} else if strings.HasPrefix(name, "V") {
					row += ",X2"
				}
				ins := x86YMMReadSource(t, row)
				width := 16
				if strings.Contains(name, ".BCST") {
					width = 4
					if strings.HasSuffix(op, "PD") || strings.HasSuffix(op, "Q") {
						width = 8
					}
				}
				for missing := -1; missing < width; missing++ {
					state := x86ResultState{fp: make([]bool, 16)}
					owned := make([]bool, 16)
					state.xmm[1], state.xmm[2], state.masks[1] = 0xffff, 0xffff, true
					for i := range owned {
						owned[i], state.fp[i] = true, i != missing
					}
					if got := x86ScalarFPResultTransfer(ins, &state, owned, 16, "amd64"); got != (missing == -1) {
						t.Fatalf("potential FP read width%d missing%d: accepted%t", width, missing, got)
					}
				}
			})
		}
	}
}

func TestX86ScalarFPLogicalEveryByteAndExactZeroIdiom(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ScalarFPLogicalOpcodes {
			t.Run(arch+"/"+op, func(t *testing.T) {
				row, destination := x86ScalarFPLogicalRow(op)
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				for input := 0; input < 2; input++ {
					for missing := -1; missing < 16; missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.xmm[0], state.xmm[1] = 0xffff, 0xffff
						if missing >= 0 {
							state.xmm[input] &^= uint16(1) << uint(missing)
						}
						want := state.xmm[0] & state.xmm[1]
						before := state.clone()
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || state.xmm[destination] != want {
							t.Fatalf("%s input%d missing%d: initialized bytes=%04x, want %04x", row, input, missing, state.xmm[destination], want)
						}
						before.xmm[destination] = want
						if strings.HasPrefix(op, "V") {
							before.vectorUpper[destination] = ^uint64(0xffff)
						}
						if !reflect.DeepEqual(before, state) {
							t.Fatal("logical definedness changed unrelated GP/FP/flags/mask/pointer state")
						}
					}
				}
				zero := strings.Contains(op, "XOR") || strings.Contains(op, "ANDN")
				if strings.HasPrefix(op, "V") {
					ins.Args[1] = ins.Args[0]
				} else {
					ins.Args[0] = ins.Args[1]
				}
				state := x86ResultState{}
				want := uint16(0)
				if zero {
					want = 0xffff
				}
				if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || state.xmm[destination] != want {
					t.Fatalf("exact register zero idiom %s: got %04x want %04x", op, state.xmm[destination], want)
				}
			})
		}
	}
}

func TestX86ScalarFPLogicalKeepsUnknownResultAndNativeMemoryBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"unknown input":       "PXOR X0,X1\nMOVQ X1,ret+0(FP)",
		"partial low qword":   "MOVSS $1.0,X2\nMOVSS X2,X0\nPXOR X0,X1\nMOVQ X1,ret+0(FP)",
		"native pointer read": "MOVQ $1,AX\nPXOR (AX),X0\nMOVQ X0,ret+0(FP)",
		"unknown global read": "PXOR input(SB),X0\nMOVQ X0,ret+0(FP)",
		"missing result":      "PXOR X0,X0\nMOVQ X0,output(SB)",
		"unknown global data": "MOVQ X0,output(SB)\nMOVQ X0,ret+0(FP)",
		"unknown merge":       "PXOR X0,X0\nMOVL $1,AX\nKMOVW AX,K1\nVPXORD X0,X0,K1,X2\nMOVQ X2,ret+0(FP)",
		"unknown mask":        "PXOR X0,X0\nVPXORD.Z X0,X0,K1,X2\nMOVQ X2,ret+0(FP)",
		"unknown wider bank":  "VPXOR Y0,Y2,Y1\nMOVQ X1,ret+0(FP)",
	} {
		t.Run(name, func(t *testing.T) {
			source := "TEXT ·view(SB),4,$0-8\n" + body + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint64\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s acquired result or memory permission: %v\n%s", api, err, ir)
				}
			}
		})
	}
}

func TestX86ScalarFPLogicalNumericalSBStoreKeepsIndependentResult(t *testing.T) {
	const source = "GLOBL slot<>(SB),16,$8\nTEXT ·view(SB),4,$0-8\nPXOR X0,X0\nMOVQ X0,slot<>(SB)\nMOVQ X0,ret+0(FP)\nRET\n"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint64\n", target.arch, target.triple, api)
					if err != nil || !strings.Contains(ir, "store volatile i64") {
						t.Fatalf("numeric SB side effect lost before independent result: %v", err)
					}
					compileLLVMToObject(t, llc, target.triple, "logical-sb-"+api+".ll", "logical-sb-"+api+".o", ir)
				})
			}
		})
	}
}
