package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"
)

func amd64RegisterBoolSource(body string) string {
	return "TEXT ·view<ABIInternal>(SB),4,$0-17\n" + body + "\nRET\n"
}

func TestAMD64RegisterBoolCanonicalResultThreeAPIs(t *testing.T) {
	for _, body := range []string{
		"MOVB $0,AX", "MOVB $1,AX", "MOVW $257,AX", "MOVL $257,AX", "MOVQ $257,AX",
		"MOVD $257,AX", "MOVDQ2Q $257,AX", "XORQ AX,AX", "ANDQ $1,AX", "ANDB $1,AX",
		"CMPQ AX,BX\nSETEQ AX", "CMPQ AX,BX\nSETNE BX\nMOVB BX,AX",
		"CMPQ AX,BX\nSETEQ BX\nMOVBQZX BX,AX",
		"MOVB $1,CH\nMOVB CH,AL", "MOVW $257,CX\nMOVB CH,AL",
		"MOVB $0,CX\nMOVB $1,DX\nORB DX,CX\nMOVB CX,AX",
	} {
		t.Run(body, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, amd64RegisterBoolSource(body), "func view(a,b uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Errorf("%s: proven canonical low result byte rejected: %v", api, err)
				}
			}
		})
	}
	for _, op := range strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS") {
		t.Run(op, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, amd64RegisterBoolSource("CMPQ AX,BX\n"+op+" AX"), "func view(a,b uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Errorf("%s: actual Go SETcc canonical byte rejected: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterBoolInitializedIsNotCanonical(t *testing.T) {
	for name, body := range map[string]string{
		"two": "MOVB $2,AX", "three": "MOVB $3,AX", "ff": "MOVB $255,AX",
		"linear-two": "MOVQ $2,AX", "linear-three": "MOVL $3,AX", "linear-ff": "MOVQ $255,AX",
		"incoming-integer": "MOVB AX,AX", "unknown-flags": "SETEQ AX", "wrong-byte": "MOVB $1,AH",
		"widened-unknown-argument": "MOVQ $0,BX\nMOVB $1,AX\nCMPQ AX,BX\nSETEQ AX",
		"noncanonical-overwrite":   "MOVB $1,AX\nINCB AX",
		"vector-overwrite":         "MOVB $1,AX\nPXOR X0,X0\nMOVQ X0,AX",
		"one-noncanonical-edge":    "CMPQ AX,BX\nJE done\nMOVB $2,AX\nJMP exit\ndone:\nMOVB $1,AX\nexit:",
		"raw":                      "BYTE $0x90\nMOVB $1,AX", "FP-result": "MOVB $1,ret+16(FP)",
	} {
		t.Run(name, func(t *testing.T) {
			declaration := "func view(a,b uint64) bool\n"
			if name == "widened-unknown-argument" {
				declaration = "func view(a uint8,b uint64) bool\n"
				body = strings.ReplaceAll(body, "MOVB $1,AX\n", "")
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, amd64RegisterBoolSource(body), declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: arbitrary/unknown/noncanonical result gained an i1 transport: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterBoolDoesNotInitializeUpperGPBytes(t *testing.T) {
	for _, move := range []string{"MOVB", "MOVW"} {
		pkg := mustGoPackage(t, "registerbool", "package registerbool\nfunc view() uint64\n")
		sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		file, err := Parse(ArchAMD64, "TEXT ·view<ABIInternal>(SB),4,$0-8\n"+move+" $1,AX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		consumer := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: sig, goarch: "amd64"}
		if err := consumer.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: a canonical byte manufactured unspecified upper result bytes: %v", move, err)
		}
	}
	for _, declaration := range []string{"func view(a bool) bool\n", "func view(a uint64) (bool,bool)\n"} {
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, amd64RegisterBoolSource("MOVB $1,AX"), declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if api == "Go" && declaration == "func view(a bool) bool\n" {
				// A complete GoModule now supplies its own call-local typed
				// argument plan. It initializes only the declared low byte;
				// the raw APIs and multiple-result boundary remain unchanged.
				// VirtualBoolPortableValues separately executes both bool values.
				if err != nil {
					t.Errorf("complete typed bool argument lost its declaration binding: %v", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s: unbound bool argument/aggregate result was inferred: %v", api, err)
			}
		}
	}
}

func TestAMD64RegisterBoolCanonicalTypedTransferFamilies(t *testing.T) {
	check := func(body string, canonical bool) {
		t.Helper()
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, amd64RegisterBoolSource(body), "func view(a,b uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if canonical && err != nil || !canonical && !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s canonical=%v: %s: %v", api, canonical, body, err)
			}
		}
	}
	// The complete official source extension family, including the unusual
	// word-read ymb rows, composes with physical per-byte facts, not type/name
	// exemptions. A known low byte is retained; sign/zero extension cannot
	// make an arbitrary source low byte canonical.
	for op := range amd64ScalarExtensionMoveSpecs {
		t.Run(string(op), func(t *testing.T) {
			check("MOVQ $257,CX\n"+string(op)+" CX,AX", true)
			check("MOVQ $258,CX\n"+string(op)+" CX,AX", false)
		})
	}
	for _, suffix := range []string{"B", "W", "L", "Q"} {
		for _, op := range []string{"AND", "OR", "XOR"} {
			t.Run(op+suffix, func(t *testing.T) {
				check("MOVQ $1,CX\n"+op+suffix+" CX,AX", op == "AND")
				check("MOVQ $1,CX\nMOVQ $0,AX\n"+op+suffix+" CX,AX", true)
				check("MOVQ $2,CX\nMOVQ $6,AX\n"+op+suffix+" CX,AX", false)
			})
		}
	}
	for op := range x86ConditionalMoveSpecs {
		t.Run(string(op), func(t *testing.T) {
			check("CMPQ AX,BX\nMOVQ $1,CX\nMOVQ $0,AX\n"+string(op)+" CX,AX", true)
			check("CMPQ AX,BX\nMOVQ $2,CX\nMOVQ $0,AX\n"+string(op)+" CX,AX", false)
			check("CMPQ AX,BX\nMOVQ $1,CX\nMOVQ $2,AX\n"+string(op)+" CX,AX", false)
			check("MOVQ $1,CX\nMOVQ $0,AX\n"+string(op)+" CX,AX", false)
		})
	}
	check("CMPQ AX,BX\nJE yes\nMOVB $0,AX\nJMP done\nyes:\nMOVB $1,AX\ndone:", true)
	check("MOVB $1,AH\nMOVB AH,R8\nMOVB R8,AX", false) // Actual REX is not AH.
	check("MOVB $1,CH\nMOVBQSX CH,AX", false)          // Actual REX is not CH.
}

func TestAMD64RegisterBoolCanonicalFactJoinsAndIdentity(t *testing.T) {
	first := x86ResultState{}
	first.gp[0], first.canonicalGP[0] = 255, 255
	second := first
	second.canonicalGP[0] = 254
	if joined := first.intersect(second); joined.gp[0] != 255 || joined.canonicalGP[0] != 254 {
		t.Fatal("canonicality must intersect independently of initialized bytes", joined)
	}
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		file, err := Parse(ArchAMD64, amd64RegisterBoolSource(alias+" $257,AX"))
		if err != nil {
			t.Fatal(err)
		}
		original := file.Funcs[0].Instrs[1]
		facts := x86RegisterCanonicalBytesAfter(original, [16]uint8{}, "amd64")
		if facts[0] != 255 || original.Op != Op(alias) || original.Raw != file.Funcs[0].Instrs[1].Raw {
			t.Fatal("source-only dispatch must preserve original identity and exact canonical bytes", alias, facts)
		}
	}
}
