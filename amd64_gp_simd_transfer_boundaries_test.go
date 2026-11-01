package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GPSIMDTransferRejectsCompleteSiblingInvalidFormats(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		rows := []string{op + ".Z AX,X0", op + ".BCST (AX),X0", op + ".SAE X0,AX"}
		for _, args := range []string{"Y0,X1", "Z0,X1", "K1,X1", "X0,Y1", "X0,Z1", "X0,K1", "$7,X1", "$1.25,X1",
			"X32,X0", "X0,X32", "X0,K1,X1", "X0,$1", "X0,$1.25", "(AX)(SP*1),X1"} {
			rows = append(rows, op+" "+args)
		}
		if op == "MOVL" || op == "VMOVD" {
			rows = append(rows, op+" X0,X1")
		}
		for _, row := range rows {
			t.Run(row, func(t *testing.T) {
				for _, arch := range []string{"amd64", "386"} {
					source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					ins := x86YMMReadSource(t, row)
					if _, known, err := x86GPSIMDTransferProperties(ins, arch); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("invalid syntax became an owned valid/context form", row, arch, known, err)
					}
					if x86CallerVectorMoveKnown(ins) {
						t.Fatal("invalid sibling acquired caller effect")
					}
					x86RequireZeroMaskAPIOutcome(t, arch, source, false)
				}
			})
		}
	}
}

func TestX86GPSIMDTransferActualCallerKeepsSafetyBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"unknown GP":             "VMOVD BX,X1\nVMOVSS X1,(DX)",
		"partial GP":             "MOVB $1,BX\nVMOVD BX,X1\nVMOVSS X1,(DX)",
		"pointer bits":           "VMOVQ DI,X1\nVMOVSS X1,(DX)",
		"stack identity":         "MOVQ SP,X1\nVMOVSS X1,(DX)",
		"frame identity":         "MOVQ BP,X1\nVMOVSS X1,(DX)",
		"undefined X":            "VMOVD X0,AX\nMOVL AX,(DX)",
		"partial X for qword":    "MOVSS (DI),X2\nMOVSS X2,X0\nVMOVQ X0,AX\nMOVL AX,(DX)",
		"unknown memory":         "VMOVD (BX),X1\nVMOVSS X1,(DX)",
		"length overread":        "VMOVQ 4(CX),X1\nVMOVSS X1,(DX)",
		"result overread":        "MOVQ (DX),X1\nVMOVSS X1,(DX)",
		"input write":            "VMOVUPS (DI),X0\nVMOVD X0,(DI)",
		"length write":           "VMOVUPS (DI),X0\nVMOVQ X0,(CX)",
		"wide result":            "VMOVUPS (DI),X0\nVMOVQ X0,(DX)",
		"result overlap":         "VMOVUPS (DI),X0\nVMOVD X0,1(DX)",
		"pointer lost as GP":     "VMOVUPS (DI),X0\nVMOVQ X0,DI\nVMOVD (DI),X1\nVMOVSS X1,(DX)",
		"g identity overwritten": "VMOVUPS (DI),X0\nVMOVQ X0,R14\nVMOVSS X0,(DX)",
		"unknown join":           "CMPQ AX,$0\nJE joined\nVMOVD AX,X1\njoined:\nVMOVSS X1,(DX)",
		"legacy upper unknown":   "MOVL AX,X1\nVEXTRACTF128 $1,Y1,X0\nVMOVSS X0,(DX)",
		"MMX native state":       "MOVQ X0,M0\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound state acquired caller permission", err)
			}
		})
	}
}

func TestX86GPSIMDTransferParserRejectsInvalidScale(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		source := "TEXT f(SB),4,$0-0\n" + op + " X0,(AX)(CX*3)\nRET\n"
		t.Run(op, func(t *testing.T) {
			if _, err := Parse(ArchAMD64, source); err == nil ||
				!strings.Contains(err.Error(), `invalid x86 symbolic address register/scale group: "(CX*3)"`) {
				t.Fatal("parser repaired an invalid scale token", err)
			}
			for _, arch := range []string{"amd64", "386"} {
				goAssemblerOracleOutput(t, arch, source, "", false)
			}
			for _, target := range x86RawReturnTargets {
				if _, err := x86ScalarFPBitViewAPI(t, strings.Replace(source, "f(SB)", "·view(SB)", 1),
					"func view()", target.arch, target.triple, "Go"); err == nil ||
					!strings.Contains(err.Error(), `invalid x86 symbolic address register/scale group: "(CX*3)"`) {
					t.Fatal("Go API repaired an invalid original scale", target.triple, err)
				}
			}
		})
	}
}

func TestX86GPSIMDTransferFPCompleteFieldsThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		bits := 32
		if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
			bits = 64
		}
		for _, input := range []string{"uint64", fmt.Sprintf("[%d]byte", bits/8)} {
			fixture := x86ScalarFPBitFixture{name: op + "/" + input,
				declaration: fmt.Sprintf("func view(x %s) uint%d\n", input, bits),
				body:        op + " x+0(FP),X1\n" + op + " X1,ret+8(FP)"}
			for _, target := range x86RawReturnTargets {
				t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
					source := x86ScalarFPBitAssembly(t, fixture, target.arch)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete independent field lost its data", api, err)
						}
						compileLLVMToObject(t, llc, target.triple, "transfer-fp-"+api+".ll", "transfer-fp-"+api+".o", ir)
					}
				})
			}
		}
	}
}
