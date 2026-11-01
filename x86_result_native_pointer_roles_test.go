package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86ResultIncomingPointerIdentityBodies(arch string) map[string]string {
	move, add, lea := "MOVQ", "ADDQ", "LEAQ"
	if arch == "386" {
		move, add, lea = "MOVL", "ADDL", "LEAL"
	}
	load := move + " x+0(FP),AX\n"
	return map[string]string{
		"copy":          load + move + " AX,CX\n",
		"offset":        load + add + " $4,AX\n",
		"index":         load + "MOVL $2,CX\n" + lea + " 8(AX)(CX*4),DX\n",
		"lea":           load + "MOVL $1,CX\n" + lea + " 4(AX)(CX*2),DX\n",
		"both branches": load + "MOVL $0,DX\nCMPL DX,$0\nJE other\n" + move + " AX,CX\nJMP end\nother:\n" + move + " AX,CX\nend:\nNOP\n",
	}
}

func TestX86ABI0ResultInitializationIncomingPointerRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word := int64(8)
		move, lea := "MOVQ", "LEAQ"
		if arch == "386" {
			word = 4
			move, lea = "MOVL", "LEAL"
		}
		load := move + " x+0(FP),AX\n"
		finish := fmt.Sprintf("MOVL $42,ret0+%d(FP)\nRET", word)
		for name, body := range x86ResultIncomingPointerIdentityBodies(arch) {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x *[8]uint32) uint32", body+finish)
				goAssemblerOracleOutput(t, arch, source, "", true)
				original := fmt.Sprintf("%#v %#v", file.Funcs[0], sig)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal(err)
				}
				if original != fmt.Sprintf("%#v %#v", file.Funcs[0], sig) {
					t.Fatal("initialization observation changed original source/signature")
				}
			})
		}
		for name, body := range map[string]string{
			"declared pointer read": load + "MOVL (AX),BX\n",
			"unknown base":          "MOVL (AX),BX\n",
			"unknown index":         load + "MOVL (AX)(CX*4),BX\n",
			"partial pointer":       load + "MOVB $1,AX\nMOVL (AX),BX\n",
			"numerical overwrite":   load + "MOVL $1,AX\nMOVL (AX),BX\n",
			"numeric address":       move + " $1,AX\nMOVL (AX),BX\n",
			"pointer as number":     load + "MOVL AX,BX\n",
			"missing branch origin": load + "MOVL $0,DX\nCMPL DX,$0\nJE other\n" + move + " AX,CX\nJMP end\nother:\nNOP\nend:\nMOVL (CX),BX\n",
			"mixed branch origin":   load + "MOVL $0,DX\nCMPL DX,$0\nJE other\n" + move + " AX,CX\nJMP end\nother:\nMOVL $1,CX\nend:\nMOVL (CX),BX\n",
			"physical write":        load + "MOVL $1,(AX)\nMOVL (AX),BX\n",
			"call":                  load + "CALL ·Other(SB)\nMOVL (AX),BX\n",
			"symbol address":        "MOVL global(SB),BX\n",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x *uint32) uint32", body+fmt.Sprintf("MOVL BX,ret0+%d(FP)\nRET", word))
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err == nil {
					t.Fatal("unclosed native role acquired a result initialization observation")
				}
			})
		}
		_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(x *uint32) uint32", load+lea+" (AX),DX\n"+finish)
		changed := sig
		changed.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
		changed.Frame.Params[0].Type = I64
		if arch == "386" {
			changed.Frame.Params[0].Type = I32
		}
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], changed, arch); err == nil {
			t.Fatal("numeric parameter inherited the original incoming pointer origin")
		}
		if reflect.DeepEqual(sig, changed) {
			t.Fatal("signature role negative did not change its actual input")
		}
	}
}
