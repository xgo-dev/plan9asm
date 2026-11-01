package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86FPAccessBytesCompleteSourceIdentity(t *testing.T) {
	for _, opcode := range []string{
		"MOVB", "MOVW", "MOVL", "MOVQ",
		"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD",
		"MOVSS", "MOVSD", "VMOVSS", "VMOVSD",
	} {
		register := "AX"
		if opcode == "MOVB" {
			register = "AL"
		} else if len(opcode) > 4 || opcode == "MOVO" {
			register = "X0"
		}
		canonical := "TEXT ·probe(SB),4,$0-64\n" + opcode + " value+0(FP)," + register + "\nRET\n"
		file, err := Parse(ArchAMD64, canonical)
		if err != nil {
			t.Fatal(err)
		}
		for _, modified := range []string{opcode + ".BAD", strings.ToLower(opcode)} {
			t.Run(modified, func(t *testing.T) {
				// These are actual original assembler failures, not inferred
				// rejection from a framework which omits old SDK execution.
				source := strings.Replace(canonical, "\n"+opcode+" ", "\n"+modified+" ", 1)
				goAssemblerOracleOutput(t, "amd64", source, "", false)
				ins := file.Funcs[0].Instrs[1]
				ins.Op = Op(modified) // explicit constructed API mutation
				if width, _, known := X86FPAccessBytes(ins, 0, "amd64"); known || width != 0 {
					t.Fatalf("unclosed original source identity %q inferred %d/%v", modified, width, known)
				}
			})
		}
	}
}

func TestX86FPAccessBytesCompleteGPSIMDMemoryRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
			for _, row := range []struct {
				name, source string
				index        int
				write        bool
			}{
				{"load", op + " value+0(FP),X0", 0, false},
				{"store", op + " X0,value+0(FP)", 1, true},
			} {
				t.Run(arch+"/"+row.name+"/"+op, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-64\n" + row.source + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					form, known, err := x86GPSIMDTransferProperties(ins, arch)
					if !known || err != nil || form.memory != row.index {
						t.Fatalf("official GP/X memory row not modeled: form=%+v known=%t err=%v", form, known, err)
					}
					width, write, known := X86FPAccessBytes(ins, row.index, arch)
					if !known || write != row.write || width != int64(form.bits/8) {
						t.Fatalf("FP access differs from GP/X row: width=%d write=%t known=%t form=%+v", width, write, known, form)
					}
					wantWidth := int64(8)
					if op == "MOVL" || op == "VMOVD" {
						wantWidth = 4
					}
					if width != wantWidth {
						t.Fatalf("native width=%d, want independently selected %d", width, wantWidth)
					}
				})
			}
		}
	}
}

func TestX86FPAccessBytesCompleteMMXMemoryRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD"} {
			wantWidth := int64(8)
			if op == "MOVL" {
				wantWidth = 4
			}
			for register := 0; register < 8; register++ {
				bank := fmt.Sprintf("M%d", register)
				for _, row := range []struct {
					name, source string
					index        int
					write        bool
				}{
					{"load", op + " value+0(FP)," + bank, 0, false},
					{"store", op + " " + bank + ",value+0(FP)", 1, true},
				} {
					t.Run(arch+"/"+op+"/"+bank+"/"+row.name, func(t *testing.T) {
						source := "TEXT ·Value(SB),4,$0-64\n" + row.source + "\nRET\n"
						goAssemblerOracleOutput(t, arch, source, "", true)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						width, write, known := X86FPAccessBytes(ins, row.index, arch)
						if !known || write != row.write || width != wantWidth {
							t.Fatalf("official MMX memory row is not observed: width=%d write=%t known=%t", width, write, known)
						}
						if width, write, known := X86FPAccessBytes(ins, 1-row.index, arch); known || width != 0 || write {
							t.Fatal("register acquired an FP access", width, write, known)
						}
					})
				}
			}
		}
	}
}
