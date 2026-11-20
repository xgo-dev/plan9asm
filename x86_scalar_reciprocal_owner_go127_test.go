//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarReciprocalExistingOwnersPrecedeNativeFamilies(t *testing.T) {
	owners := x86CaptureNativeFamilyOwnerOracle(t)
	for _, op := range []string{"MOVSS", "MOVSD", "RCPSS", "RSQRTSS", "VRCPSS", "VRSQRTSS"} {
		for _, memory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/memory=%t", op, memory), func(t *testing.T) {
				text, declaration, target := x86ScalarReciprocalOwnerProgram(op, memory)
				owners.checkProgram(t, text, declaration, target)
			})
		}
	}
}

func x86ScalarReciprocalOwnerProgram(op string, memory bool) (source, declaration, target string) {
	load, scalar := "MOVSS", "uint32"
	if op == "MOVSD" {
		load, scalar = "MOVSD", "uint64"
	}
	input, preload := "(AX)", ""
	if !memory {
		input, preload = "X0", load+" (AX),X0\n"
	}
	args, destination := input+",X1", "X1"
	if strings.HasPrefix(op, "V") {
		args, destination = input+",X1,X2", "X2"
	}
	target = op + " " + args
	source = "TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),AX\nMOVQ upper+16(FP),BX\n" +
		"MOVUPS (BX),X1\nSTC\n" + preload + target + "\nMOVUPS " + destination + ",(DI)\nSETCS 16(DI)\nSTMXCSR 20(DI)\nRET\n"
	declaration = fmt.Sprintf("func Value(out *[24]byte,input *%s,upper *[16]byte)\n", scalar)
	return source, declaration, target
}
