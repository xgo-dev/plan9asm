package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86SignedPackedIntegerFloatCallerCompleteInitializedForms(t *testing.T) {
	for _, op := range []string{"CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"} {
		banks := []string{"X"}
		if strings.HasPrefix(op, "V") {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			src := bank
			if strings.HasSuffix(op, "PD") {
				src = "X"
				if bank == "Z" {
					src = "Y"
				}
			}
			modes := []string{""}
			if strings.HasPrefix(op, "V") {
				modes = []string{"", "K1,", "K7,"}
			}
			for _, input := range []string{src + "0", "(DI)"} {
				for _, mode := range modes {
					name := op
					if mode == "K7," {
						name += ".Z"
					}
					row := fmt.Sprintf("%s %s,%s%s1", name, input, mode, bank)
					t.Run(row, func(t *testing.T) {
						body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\nKMOVQ AX,K7\n" + row + "\nVMOVSS X1,(DX)"
						assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
						goAssemblerOracleOutput(t, "amd64", assembly, "", true)
						pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
						if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
}

func TestX86SignedPackedIntegerFloatCallerRetainsFailures(t *testing.T) {
	for name, body := range map[string]string{
		"unknown input":          "VCVTDQ2PS Y0,Y1\nVMOVSS X1,(DX)",
		"partial dword":          "MOVSS (DI),X2\nMOVSS X2,X0\nCVTPL2PS X0,X1\nVMOVSS X1,(DX)",
		"unknown merge":          "VMOVUPS (DI),Z0\nKMOVQ AX,K1\nVCVTDQ2PS Z0,K1,Z1\nVMOVSS X1,(DX)",
		"unknown mask":           "VMOVUPS (DI),Z0\nVCVTDQ2PS.Z Z0,K1,Z1\nVMOVSS X1,(DX)",
		"pointer mask":           "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVCVTDQ2PS.Z Z0,K1,Z1\nVMOVSS X1,(DX)",
		"unknown base":           "VCVTDQ2PD (BX),Y1\nVMOVSS X1,(DX)",
		"private stack":          "VCVTDQ2PS (SP),Y1\nVMOVSS X1,(DX)",
		"FP pointer data":        "CVTPL2PD a+0(FP),X1\nVMOVSS X1,(DX)",
		"zero mask envelope":     "MOVL $0,AX\nKMOVQ AX,K1\nVCVTDQ2PS.Z (DX),K1,Z1\nVMOVSS X1,(DX)",
		"source write":           "VCVTDQ2PS (DI),Y1\nVMOVSS X1,(DI)",
		"wide result":            "VCVTDQ2PD (DI),Y1\nVMOVUPS Y1,(DX)",
		"join":                   "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),Y0\njoined:\nVCVTDQ2PS Y0,Y1\nVMOVSS X1,(DX)",
		"unknown upper alias":    "VMOVUPS (DI),X0\nCVTPL2PS X0,X1\nVCVTDQ2PS Y1,Y2\nVMOVSS X2,(DX)",
		"MMX transport":          "MOVQ (DI),M0\nCVTPL2PS M0,X1\nVMOVSS X1,(DX)",
		"unsigned unknown upper": "MOVOU (DI),X0\nVCVTUDQ2PS Y0,Y1\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved conversion got caller permission: %v", err)
			}
		})
	}
}

func TestX86SignedPackedIntegerFloatGPTransferDefinesCompleteXInput(t *testing.T) {
	// MOVQ GP -> X initializes the low qword and zeroes all remaining X
	// bytes. In contrast, the register MOVSS negative above preserves the
	// unknown upper twelve bytes of its destination.
	body := "MOVQ AX,X0\nCVTPL2PS X0,X1\nVMOVSS X1,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal("complete GP/X input lost its caller-defined bytes", err)
	}
}

func TestX86SignedPackedIntegerFloatIndependentByteEffects(t *testing.T) {
	for _, row := range x86SignedPackedFloatRows("amd64") {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		f, _, err := x86SignedPackedFloatProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if f.memory >= 0 || f.mmx {
			continue
		}
		for missing := -1; missing < f.inputBytes; missing++ {
			input := x86CallerVectorByteMask(int64(f.inputBytes))
			if missing >= 0 {
				input &^= uint64(1) << uint(missing)
			}
			for _, old := range []uint64{0, ^uint64(0)} {
				state := x86SourceStackState{vectors: map[Reg]uint64{x86CallerVectorRoot(ins.Args[0].Reg): input}, masks: map[Reg]bool{"K1": true, "K3": true, "K7": true}}
				destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
				if destination != x86CallerVectorRoot(ins.Args[0].Reg) {
					state.vectors[destination] = old
				} else {
					old = input
				}
				valid := missing < 0 && (f.mask < 0 || f.zeroing || old&x86CallerVectorByteMask(int64(f.byteWidth)) == x86CallerVectorByteMask(int64(f.byteWidth)))
				if got := x86CallerSignedPackedFloatStep(&ins, f, &state, nil); got != valid {
					t.Fatalf("%s missing%d merge%016x got%t want%t", row, missing, old, got, valid)
				}
				if valid {
					want := ^uint64(0)
					if f.spec.legacy {
						want = old | x86CallerVectorByteMask(16)
					}
					if state.vectors[destination] != want {
						t.Fatal("alias/upper byte effect", row)
					}
				}
			}
		}
	}
}
