package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86NamedLockOracleForm struct {
	text   string
	atomic string
}

// This independent inventory follows Intel's nineteen LOCK RMW opcode stems.
// A nonempty atomic field describes an existing lowerer's emitted operation,
// not a memory, caller or source initialization permission.
func x86NamedLockOracleForms(arch string) []x86NamedLockOracleForm {
	widths := "BWL"
	if arch == "amd64" {
		widths += "Q"
	}
	var forms []x86NamedLockOracleForm
	for _, stem := range []string{"ADD", "ADC", "AND", "OR", "SBB", "SUB", "XOR", "CMPXCHG", "XADD", "XCHG"} {
		for _, width := range widths {
			register := "CX"
			if width == 'B' {
				register = "CL"
			}
			atomic := ""
			switch stem {
			case "CMPXCHG":
				atomic = "asm sideeffect \"lock; cmpxchg" + strings.ToLower(string(width))
			case "XADD":
				atomic = "lock; xadd"
			case "XCHG":
				atomic = "asm sideeffect \"xchg"
			default:
				atomic = "lock; " + strings.ToLower(stem+string(width))
			}
			forms = append(forms, x86NamedLockOracleForm{fmt.Sprintf("%s%c %s,(SI)", stem, width, register), atomic})
		}
	}
	for _, stem := range []string{"INC", "DEC", "NEG", "NOT"} {
		for _, width := range widths {
			forms = append(forms, x86NamedLockOracleForm{
				text: fmt.Sprintf("%s%c (SI)", stem, width), atomic: "lock; " + strings.ToLower(stem+string(width)),
			})
		}
	}
	for _, stem := range []string{"BTC", "BTR", "BTS"} {
		for _, width := range strings.TrimPrefix(widths, "B") {
			forms = append(forms, x86NamedLockOracleForm{
				text: fmt.Sprintf("%s%c CX,(SI)", stem, width), atomic: "lock; " + strings.ToLower(stem+string(width)),
			})
		}
	}
	forms = append(forms, x86NamedLockOracleForm{text: "CMPXCHG8B (SI)", atomic: "asm sideeffect \"lock; cmpxchg8b"})
	if arch == "amd64" {
		forms = append(forms, x86NamedLockOracleForm{text: "CMPXCHG16B (SI)", atomic: "asm sideeffect \"lock; cmpxchg16b"})
	}
	return forms
}

func x86NamedLockOracleSource(arch, body string) string {
	load, args := "MOVL", 4
	if arch == "amd64" {
		load, args = "MOVQ", 8
	}
	return fmt.Sprintf(`TEXT ·locked(SB),4,$0-%d
	%s p+0(FP),SI
	MOVL $2,AX
	MOVL $3,BX
	MOVL $4,CX
	MOVL $5,DX
	%s
	RET
`, args, load, body)
}

func TestX86NamedLockCompleteRMWRequiresWholeAtomicBinding(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		forms := x86NamedLockOracleForms(target.arch)
		want := 49
		if target.arch == "amd64" {
			want = 67
		}
		if len(forms) != want {
			t.Fatal("complete LOCK stem/width denominator changed", target.arch, len(forms))
		}
		for _, form := range forms {
			t.Run(target.triple+"/"+form.text, func(t *testing.T) {
				source := x86NamedLockOracleSource(target.arch, "CMPL AX,AX\n\tLOCK\n\t"+form.text)
				actual := x86OrderingHintGoBytes(t, target.arch, source)
				if !strings.Contains(string(actual), string([]byte{0xf0})) {
					t.Fatalf("actual Go object lost named LOCK prefix: %x", actual)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc locked(p *[16]byte)\n", target.arch, target.triple)
						if form.atomic == "" {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("actual Go LOCK RMW silently became a non-atomic operation: error=%v atomicrmw=%v cmpxchg=%v nativeLock=%v", err,
									strings.Contains(ir, "atomicrmw "), strings.Contains(ir, " = cmpxchg "), strings.Contains(ir, "lock;"))
							}
							return
						}
						if err != nil || !strings.Contains(ir, form.atomic) {
							t.Fatalf("existing whole atomic operation changed: %v, required emission=%q", err, form.atomic)
						}
					})
				}
			})
		}
	}
}

func TestX86NamedLockDetachedAndSplitPrefixDoesNotBorrowAtomicBody(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, body := range []string{
			"LOCK",
			"LOCK\n\tLOCK\n\tXADDL CX,(SI)",
			"LOCK\nbody:\n\tXADDL CX,(SI)",
			"LOCK\n\tCMPL CX,(SI)",
			"LOCK\n\tNOP\n\tXADDL CX,(SI)",
		} {
			t.Run(arch+"/"+body, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, "text", x86NamedLockOracleSource(arch, body),
					"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("unbound or split prefix borrowed a following operation", err)
				}
			})
		}
	}
	ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
	before := output.String()
	known, terminated, err := ctx.lowerAtomic("LOCK", Instr{Op: "LOCK", Raw: "LOCK"})
	if !known || terminated || !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
		t.Fatal("standalone helper has no complete ordered instruction to bind", known, terminated, err)
	}
}
