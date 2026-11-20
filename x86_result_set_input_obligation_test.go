package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ConditionalSetVoidRequiresActualPredicateFlags(t *testing.T) {
	// The independent complete yscond inventory also covers register writes:
	// no result store or native destination is needed to consume FLAGS.
	ops := strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS " +
		"SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS")
	if len(ops) != 16 {
		t.Fatal("complete conditional byte family changed")
	}
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		var originals strings.Builder
		for index, op := range ops {
			fmt.Fprintf(&originals, "TEXT ·Original%d(SB),4,$0-0\n%s AH\nRET\n", index, op)
		}
		x86LEAActualTargetGoObject(t, arch, triple, originals.String())
		for _, op := range ops {
			for _, destination := range []string{"AX", "AH"} {
				for _, role := range []string{"void", "unused-bool"} {
					t.Run(arch+"/"+op+"/"+destination+"/"+role, func(t *testing.T) {
						arguments, declaration := 0, "func Value()"
						if role == "unused-bool" {
							arguments, declaration = 1, "func Value(unused bool)"
						}
						prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVL $1,AX\n", arguments)
						ending := op + " " + destination + "\nRET\n"
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, prefix+"CMPL AX,$0\n"+ending,
								declaration, arch, triple, api); err != nil || ir == "" {
								t.Fatal("explicit complete predicate rejected", api, err)
							}
							if ir, err := x86ScalarFPBitViewAPI(t, prefix+ending,
								declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Error("Void register SETcc borrowed initial implementation FLAGS", api, err)
							}
							ir, err := x86ScalarFPBitViewAPI(t, prefix+"CLC\n"+ending,
								declaration, arch, triple, api)
							if op == "SETCC" || op == "SETCS" {
								if err != nil || ir == "" {
									t.Error("actual CF-only predicate rejected", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Error("CF-only producer supplied other predicate bits", api, err)
							}
						}
					})
				}
			}
		}
	}
}
