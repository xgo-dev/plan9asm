package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultSlotMoveWidthKeepsScalarMode32Boundary(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
			for _, operands := range []string{"AX,(DI)", "(DI),AX", "$17,(DI)"} {
				t.Run(arch+"/"+op+"/"+operands, func(t *testing.T) {
					original := x86YMMReadSource(t, op+" "+operands)
					local := x86GoMOVQSourceInstruction(original)
					want := int64(8)
					if arch == "386" {
						want = 0
					}
					if got := x86ResultSlotMoveBytes(local, arch); got != want {
						t.Fatalf("scalar fallback width=%d want=%d; original %s", got, want, original.Raw)
					}
					if original.Op != Op(op) || original.Raw != op+" "+operands {
						t.Fatal("descriptor rewrote original source identity")
					}
				})
			}
		}
		for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q", "VMOVQ"} {
			for _, operands := range []string{"X0,(DI)", "(DI),X0"} {
				t.Run(arch+"/legal_X_m64/"+op+"/"+operands, func(t *testing.T) {
					ins := x86GoMOVQSourceInstruction(x86YMMReadSource(t, op+" "+operands))
					if got := x86ResultSlotMoveBytes(ins, arch); got != 8 {
						t.Fatalf("actual legal X/m64 width=%d want8", got)
					}
				})
			}
		}
	}
}

func TestX86ResultSlotMoveWidthWholeProofAndThreeAPIs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, triple := "Q", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, triple = "L", "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
			for _, operation := range []struct{ name, body string }{
				{"GP_store", "MOVWORD $17,AX\n " + op + " AX,(DI)"},
				{"GP_load", "MOVL $17,(DI)\n MOVL $0,4(DI)\n " + op + " (DI),AX\n " + op + " AX,(DI)"},
				{"immediate", op + " $17,(DI)"},
			} {
				t.Run(arch+"/"+op+"/"+operation.name, func(t *testing.T) {
					body := "LEA" + word + " ret+0(FP),DI\n " + strings.ReplaceAll(operation.body, "WORD", word) + "\n RET"
					_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint64", body)
					accept := arch == "amd64"
					if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); accept && err != nil || !accept && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("private proof accept=%t: %v", accept, err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint64", arch, triple, api)
							if accept && (err != nil || ir == "") || !accept && (err == nil || ir != "") {
								t.Fatalf("complete ordinary I64 source %s accept=%t: %v", api, accept, err)
							}
							if !accept && !strings.Contains(err.Error(), "outside Go 1.27's MOVD/ymovq forms") {
								t.Fatalf("bad mode32 GP-only source lost its explicit form rejection: %v", err)
							}
						})
					}
				})
			}
		}
		for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q", "VMOVQ"} {
			t.Run(arch+"/legal_X_m64/"+op, func(t *testing.T) {
				body := fmt.Sprintf("LEA%s ret+0(FP),DI\n PXOR X0,X0\n %s X0,(DI)\n %s (DI),X1\n %s X1,(DI)\n RET", word, op, op, op)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint64", body)
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal(err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if _, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint64", arch, triple, api); err != nil {
							t.Fatal(err)
						}
					})
				}
			})
		}
	}
}
