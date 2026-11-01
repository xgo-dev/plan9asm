package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86LockScalarRMWCarryStackAliasesAndIdentityStayContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := "Q"
		if arch == "386" {
			word = "L"
		}
		for _, width := range []string{"W", word} {
			push, pop := "PUSH"+width+" DX\n", "\nPOPF"+width
			for _, control := range []struct{ name, body string }{
				{"explicit stack store", push + "MOV" + width + " BP,0(SP)" + pop},
				{"derived stack store", push + "MOV" + word + " SP,BX\nMOV" + width + " BP,(BX)" + pop},
				{"unknown vector store", push + "MOVOU X0,0(SP)" + pop},
				{"CSR stack store", push + "STMXCSR 0(SP)" + pop},
				{"SP replacement before push", "MOV" + word + " $0,SP\nMOVL $5,DX\n" + push + "POPF" + width},
				{"POP SP before new push", "PUSH" + word + " BP\nPOP" + word + " SP\nMOVL $5,DX\n" + push + "POPF" + width},
				{"LEA SP before push", "LEA" + word + " 0(SP),SP\nMOVL $5,DX\n" + push + "POPF" + width},
				{"balanced SP adjustment", "SUB" + word + " $16,SP\nMOVL $5,DX\n" + push + "POPF" + width + "\nADD" + word + " $16,SP"},
			} {
				t.Run(arch+"/"+width+"/"+control.name, func(t *testing.T) {
					// These accepted objects are unsafe/unknown-input tripwires.
					// They are never executed as numerical or caller evidence.
					source := x86NamedLockOracleSource(arch, control.body+"\nLOCK\nADCL CX,(SI)")
					x86LockScalarOriginalInstruction(t, arch, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := output.String(), ctx.tmp
					if err := ctx.verifyNamedLockCarry(); !errors.Is(err, ErrProbeNeedsContext) ||
						output.String() != before || ctx.tmp != temporary {
						t.Error("pure CF domain retained stale stack bits or regained replaced SP identity", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, source,
								"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("a stale stack value or replaced SP authorized carry", err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86LockScalarRMWCarryInvalidStackDoesNotInvalidateExplicitCF(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := "Q"
		if arch == "386" {
			word = "L"
		}
		for _, seed := range []string{"CLC", "STC"} {
			source := x86NamedLockOracleSource(arch, "MOV"+word+" $0,SP\n"+seed+"\nLOCK\nADCL CX,(SI)")
			x86LockScalarOriginalInstruction(t, arch, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ctx.goarch = arch
			before, temporary := output.String(), ctx.tmp
			if err := ctx.verifyNamedLockCarry(); err != nil || output.String() != before || ctx.tmp != temporary {
				t.Fatal("explicit CF fact was lost or granted an IR/memory permission", err)
			}
			if strings.Contains(output.String(), "lock;") {
				t.Fatal("a CF-only observation emitted an atomic object")
			}
		}
	}
}
