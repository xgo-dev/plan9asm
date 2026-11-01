package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86ResultMoveMaskForms = []string{
	"PMOVMSKB X0,AX", "MOVMSKPS X0,AX", "MOVMSKPD X0,AX",
	"VPMOVMSKB X0,AX", "VPMOVMSKB Y0,AX",
	"VMOVMSKPS X0,AX", "VMOVMSKPS Y0,AX",
	"VMOVMSKPD X0,AX", "VMOVMSKPD Y0,AX",
}

func TestX86ResultMoveMaskEveryByteAndPreservedState(t *testing.T) {
	for _, line := range x86ResultMoveMaskForms {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+line+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := file.Funcs[0].Instrs[1]
		width := 16
		if strings.Contains(line, " Y") {
			width = 32
		}
		for missing := -1; missing < width; missing++ {
			state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagOF}
			state.xmm[0], state.vectorUpper[0] = 0xffff, ^uint64(0xffff)
			if missing >= 0 && missing < 16 {
				state.xmm[0] &^= 1 << uint(missing)
			} else if missing >= 16 {
				state.vectorUpper[0] &^= 1 << uint(missing)
			}
			before := state
			accepted, known := x86ResultMoveMaskStep(instruction, &state, nil, 0, "amd64")
			if !known || accepted != (missing == -1) {
				t.Fatalf("%s missing byte=%d: accepted=%t known=%t", line, missing, accepted, known)
			}
			want := before
			if accepted {
				want.gp[0] = 0xff // r32 result defines the complete zero-extended RAX.
			}
			if !reflect.DeepEqual(state, want) {
				t.Fatalf("%s changed vector/FLAGS/other GP state at missing byte=%d", line, missing)
			}
		}
	}
}

func TestX86ABI0ResultMoveMaskWholeFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		typ, move := "uint64", "MOVQ"
		if arch == "386" {
			typ, move = "uint32", "MOVL"
		}
		for _, instruction := range x86ResultMoveMaskForms {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				body := "VZEROALL\n" + instruction + "\n" + move + " AX,ret0+0(FP)\nRET"
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() "+typ, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatalf("source-defined mask must define its zero-extended GP result: %v", err)
				}
			})
		}
	}
}

func TestX86ABI0ResultMoveMaskUnknownBytesAndFlags(t *testing.T) {
	for _, instruction := range x86ResultMoveMaskForms {
		for _, prefix := range []string{"", "MOVB $1,AX\nPINSRB $0,AX,X0\n"} {
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint64",
				prefix+instruction+"\nMOVQ AX,ret0+0(FP)\nRET")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("unknown vector bytes became mask bits: %s %s: %v", prefix, instruction, err)
			}
		}
		for _, defined := range []bool{false, true} {
			prefix := "VZEROALL\n"
			if defined {
				prefix += "MOVL $1,BX\nCMPL BX,$0\n"
			}
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint8",
				prefix+instruction+"\nSETEQ ret0+0(FP)\nRET")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
			if defined && err != nil || !defined && !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("mask changed FLAGS definedness=%t: %s: %v", defined, instruction, err)
			}
		}
	}
	for _, sourceRegister := range []string{"X8", "Y8", "M0"} {
		op := "VPMOVMSKB"
		if sourceRegister == "M0" {
			op = "PMOVMSKB"
		}
		body := fmt.Sprintf("%s %s,AX\nMOVL AX,ret0+0(FP)\nRET", op, sourceRegister)
		_, file, sig, source := x86ResultInitializationFixture(t, "386", "func Value() uint32", body)
		goAssemblerOracleOutput(t, "386", source, "", true)
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "386"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("mask acquired an unbound physical source role: %s: %v", sourceRegister, err)
		}
	}
}
