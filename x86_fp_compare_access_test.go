package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Keep this FP consumer on the same complete ycmpb/ycmpl/yxorb/ytestl
// grammar as lowering, including both memory directions and immediate classes.
func TestX86FPAccessBytesScalarCompareCompleteForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"CMP", "TEST"} {
			for _, suffix := range []string{"B", "W", "L", "Q"} {
				if arch == "386" && suffix == "Q" {
					continue // Go's Q rows are independently rejected below.
				}
				t.Run(arch+"/"+stem+suffix, func(t *testing.T) {
					op := stem + suffix
					rows := []string{"a+0(FP),AX", "AX,a+0(FP)"}
					for _, immediate := range []string{"0", "127", "128", "-128", "-129", "65535", "2147483648", "4294967295"} {
						row := "a+0(FP),$" + immediate
						if stem == "TEST" {
							row = "$" + immediate + ",a+0(FP)"
						}
						rows = append(rows, row)
					}
					var source strings.Builder
					for index, row := range rows {
						fmt.Fprintf(&source, "TEXT form%d(SB),4,$0-8\n%s %s\nRET\n", index, op, row)
					}
					goAssemblerOracleOutput(t, arch, source.String(), "", true)
					file, err := Parse(ArchAMD64, source.String())
					if err != nil {
						t.Fatal(err)
					}
					for _, fn := range file.Funcs {
						ins := fn.Instrs[1]
						before := append([]Operand(nil), ins.Args...)
						for index, operand := range ins.Args {
							width, write, known := X86FPAccessBytes(ins, index, arch)
							want := map[string]int64{"B": 1, "W": 2, "L": 4, "Q": 8}[suffix]
							if operand.Kind != OpFP {
								if known || write || width != 0 {
									t.Fatal("non-FP operand acquired a byte span", ins.Raw, index)
								}
							} else if !known || write || width != want {
								t.Errorf("%s operand %d = %d/%t/%t, want %d/false/true", ins.Raw, index, width, write, known, want)
							}
						}
						if !reflect.DeepEqual(before, ins.Args) {
							t.Fatal("byte observation changed original operands")
						}
					}
				})
			}
		}
	}
}

func TestX86FPAccessBytesScalarCompareRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := []string{"CMPB a+0(FP),X0", "TESTL a+0(FP),$1", "CMPL $1,a+0(FP)",
			"CMPL a+0(FP),b+4(FP)", "TESTW a+0(FP),X0", "CMPW a+0(FP)", "CMPL a+0(FP),AX,CX"}
		if arch == "386" {
			rows = append(rows, "CMPQ a+0(FP),AX", "TESTQ AX,a+0(FP)", "CMPL a+0(FP),R8")
		}
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-8\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				for index := range ins.Args {
					if width, write, known := X86FPAccessBytes(ins, index, arch); known || write || width != 0 {
						t.Fatal("rejected original compare acquired a byte span", width, write, known)
					}
				}
			})
		}
	}
}

func TestX86FPCompareWidthDoesNotInitializeResult(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, compare := range []string{"CMPL ret0+0(FP),$7", "TESTL $7,ret0+0(FP)"} {
			t.Run(arch+"/"+compare, func(t *testing.T) {
				body := compare + "\nMOVL $1,ret0+0(FP)\nRET"
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for index, operand := range file.Funcs[0].Instrs[1].Args {
					if operand.Kind != OpFP {
						continue
					}
					width, write, known := X86FPAccessBytes(file.Funcs[0].Instrs[1], index, arch)
					if !known || width != 4 || write {
						t.Fatal("complete read lost its width", width, write, known)
					}
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("read-only width observation initialized an unwritten result", err)
				}
			})
		}
	}
}
