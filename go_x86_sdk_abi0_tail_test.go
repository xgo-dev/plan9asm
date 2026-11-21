package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSDK386ABI0TailProjectsOnlyDirectBranches(t *testing.T) {
	const branch = "JMP shared(SB)"
	const source = `TEXT ·First(SB),4,$0-8
 MOVL $5,BX
 JMP shared(SB)
TEXT ·Second(SB),4,$0-8
 MOVL $9,BX
 JMP shared(SB)
TEXT shared(SB),516,$0
 MOVL value+0(FP),AX
 ADDL BX,AX
 MOVL AX,ret+4(FP)
 RET
`
	for _, row := range []struct {
		name       string
		source     string
		needsProof bool
	}{
		{"direct", source, false},
		{"offset", strings.Replace(source, branch, "JMP shared+1(SB)", 1), true},
		{"call", strings.Replace(source, branch, "CALL shared(SB)\n RET", 1), true},
		{"address", strings.Replace(source, branch, "LEAL shared(SB),AX\n RET", 1), true},
		{"data", source + "DATA table<>+0(SB)/4,$shared(SB)\nGLOBL table<>(SB),8,$4\n", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			original, err := Parse(ArchAMD64, row.source)
			if err != nil {
				t.Fatal(err)
			}
			before := x86DirectTailSnapshot(original)
			helpers := sdkABI0TailHelpers(original)
			if !helpers["shared"] || len(helpers) != 1 {
				t.Fatalf("same-file caller/helper discovery changed: %v", helpers)
			}
			projected, err := projectSDKABI0Tail(original, helpers)
			if !reflect.DeepEqual(original, before) {
				t.Fatal("projection altered the original file")
			}
			if row.needsProof {
				if !errors.Is(err, ErrProbeNeedsContext) || projected != nil {
					t.Fatalf("unbound reference published a projection: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, fn := range projected.Funcs[:2] {
				jump := fn.Instrs[len(fn.Instrs)-1]
				if jump.Op != OpJMP || jump.Args[0].Sym != "shared<>(SB)" || jump.Raw != branch {
					t.Fatal("projection lost the original tail or its diagnostic spelling", jump)
				}
			}
			if projected.Funcs[2].Sym != "shared<>" {
				t.Fatal("helper was not projected as a direct tail node")
			}
		})
	}
}
