package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86ABI0BoolArchFixture(arch string) (string, string) {
	word, lea, move := 8, "LEAQ", "MOVQ"
	if arch == "386" {
		word, lea, move = 4, "LEAL", "MOVL"
	}
	var source, declarations strings.Builder
	for index, row := range []struct {
		declaration, body string
		args              int
	}{
		{"func Value() bool", "MOVB $0,ret+0(FP)", 1},
		{"func Value() bool", "MOVB $1,ret+0(FP)", 1},
		{"func Value(x uint32) bool", fmt.Sprintf("MOVL x+0(FP),AX\nCMPL AX,$0\nSETEQ ret+%d(FP)", word), word + 1},
		{"func Value(x bool) bool", fmt.Sprintf("MOVB x+0(FP),AL\nMOVB AL,ret+%d(FP)", word), word + 1},
		{"func Value(x bool) bool", fmt.Sprintf("MOVB $2,x+0(FP)\nMOVB x+0(FP),AL\nCMPB AL,$2\nSETEQ ret+%d(FP)", word), word + 1},
		{"func Value() bool", fmt.Sprintf("%s ret+0(FP),AX\n%s AX,BX\nMOVB $1,(BX)", lea, move), 1},
		{"func Value(x bool) bool", fmt.Sprintf("%s x+0(FP),AX\nMOVB $2,(AX)\nMOVB (AX),CL\nCMPB CL,$2\nSETEQ ret+%d(FP)", lea, word), word + 1},
		{"func Value(p *uint32,old,new uint32) bool", fmt.Sprintf("%s p+0(FP),BX\nMOVL old+%d(FP),AX\nMOVL new+%d(FP),CX\nLOCK\nCMPXCHGL CX,(BX)\nSETEQ ret+%d(FP)", move, word, word+4, word+8), word + 9},
	} {
		name := fmt.Sprintf("BoolArch%d", index)
		fmt.Fprintf(&declarations, "%s\n", strings.Replace(row.declaration, "Value", name, 1))
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s\nRET\n", name, row.args, row.body)
	}
	for _, condition := range strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS") {
		name := "Bool" + condition
		fmt.Fprintf(&declarations, "func %s(x uint32) bool\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOVL x+0(FP),AX\nCMPL AX,$0\n%s ret+%d(FP)\nRET\n", name, word+1, condition, word)
	}
	return source.String(), declarations.String()
}

func TestX86ABI0CanonicalBoolArchitectureObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86ABI0BoolArchFixture(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

func TestX86ABI0CanonicalBoolArchitectureNoncanonicalResults(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, body := range []string{
			"MOVB $2,ret+0(FP)\nRET", "MOVB $255,ret+0(FP)\nRET",
			"MOVB $2,AL\nMOVB AL,ret+0(FP)\nRET", "RET",
			"MOVL $1,AX\nCMPL AX,$0\nJNE missing\nMOVB $1,ret+0(FP)\nmissing:\nRET",
		} {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·Value(SB),4,$0-1\n"+body+"\n",
					"func Value() bool", target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("noncanonical or missing bool became logical i1: %s/%s/%s: %v", target.triple, api, body, err)
				}
			}
		}
	}
}

func TestX86AMD64CanonicalBoolDefaultArchitecture(t *testing.T) {
	for _, arch := range []string{"", "amd64"} {
		for _, row := range []struct {
			body string
			good bool
		}{
			{"MOVB $0,ret+0(FP)\nRET", true},
			{"MOVB $1,ret+0(FP)\nRET", true},
			{"MOVB $2,ret+0(FP)\nRET", false},
			{"MOVB $255,ret+0(FP)\nRET", false},
			{"RET", false},
			{"NOP", false},
		} {
			for _, api := range []string{"text", "module"} {
				t.Run(arch+"/"+row.body+"/"+api, func(t *testing.T) {
					_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() bool", row.body)
					options := Options{Goarch: arch, TargetTriple: "x86_64-unknown-linux-gnu",
						ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
						Sigs:       map[string]FuncSig{"Value": sig}}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					published := false
					var err error
					if api == "text" {
						var ir string
						ir, err = Translate(file, options)
						published = ir != ""
					} else {
						module, failure := TranslateModuleInContext(ctx, file, options)
						err, published = failure, !module.IsNil()
						if !module.IsNil() {
							module.Dispose()
						}
					}
					if row.good && (!published || err != nil) || !row.good && (published || !errors.Is(err, ErrProbeNeedsContext)) {
						t.Fatal("default architecture bypassed canonical ABI0 proof", row.good, err)
					}
				})
			}
		}
	}
}

func TestX86AMD64CanonicalBoolKeepsManualRegisterTransport(t *testing.T) {
	for _, arch := range []string{"", "amd64"} {
		for _, instruction := range []string{"CALL", "JMP"} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Manual(SB),4,$0-0\n"+instruction+" Outside(SB)\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: arch, TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{
					"Manual": {Name: "Manual", Ret: I1}, "Outside": {Name: "Outside", Ret: I1},
				}}
				if source, err := prepareX86ABI0BoolCalls(file, options); source != nil || err != nil {
					t.Fatal("manual register signature acquired an undeclared ABI0 byte frame", err)
				}
			})
		}
	}
}

func TestX86ABI0CanonicalBoolArchitectureAliasesAndCalls(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, lea, move := x86ResultPointerWord(target.arch), "LEAQ", "MOVQ"
		if target.arch == "386" {
			lea, move = "LEAL", "MOVL"
		}
		leaf := fmt.Sprintf("TEXT ·leaf(SB),4,$0-%d\nMOVB x+0(FP),AX\nMOVB AX,ret+%d(FP)\nRET\n", word+1, word)
		call := fmt.Sprintf("MOVB x+0(FP),AX\nMOVB AX,0(SP)\nCALL ·leaf(SB)\nMOVB %d(SP),AX\nMOVB AX,ret+%d(FP)", word, word)
		for _, row := range []struct {
			name, body, callee string
			frame              int
			good               bool
		}{
			{"alias-copy", fmt.Sprintf("%s x+0(FP),AX\n%s AX,DX\nMOVB (DX),BX\nMOVB BX,ret+%d(FP)", lea, move, word), "", 0, true},
			{"alias-short-copy", fmt.Sprintf("%s x+0(FP),AX\nMOVW AX,DX\nMOVB (DX),BX\nMOVB BX,ret+%d(FP)", lea, word), "", 0, false},
			{"alias-outside", fmt.Sprintf("%s x+0(FP),AX\nMOVB 1(AX),BX\nMOVB BX,ret+%d(FP)", lea, word), "", 0, false},
			{"alias-raw-result", fmt.Sprintf("%s x+0(FP),AX\nMOVB $2,(AX)\nMOVB (AX),BX\nMOVB BX,ret+%d(FP)", lea, word), "", 0, false},
			{"same-file-call", call, leaf, 16, true},
			{"raw-outgoing-call", strings.Replace(call, "MOVB AX,0(SP)", "MOVB $2,0(SP)", 1), leaf, 16, false},
			{"missing-outgoing-call", strings.Replace(call, "MOVB AX,0(SP)\n", "", 1), leaf, 16, false},
			{"call-kills-flags", call + fmt.Sprintf("\nSETEQ ret+%d(FP)", word), leaf, 16, false},
			{"raw-callee-call", call, strings.Replace(leaf, "MOVB AX,ret+", "MOVB $2,ret+", 1), 16, false},
			{"same-file-tail", "JMP ·leaf(SB)", leaf, 0, true},
			{"raw-callee-tail", "JMP ·leaf(SB)", strings.Replace(leaf, "MOVB AX,ret+", "MOVB $2,ret+", 1), 0, false},
		} {
			declarations := "func Value(x bool) bool\n"
			if row.callee != "" {
				declarations += "func leaf(x bool) bool\n"
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$%d-%d\n%s\n", row.frame, word+1, row.body)
			if !strings.HasPrefix(row.body, "JMP") {
				source += "RET\n"
			}
			source += row.callee
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("canonical byte alias/call contract changed", row.good, err)
					}
				})
			}
		}
	}
}

// This portable oracle exercises the physical byte before canonical RET,
// independently of native LOCK/CMPXCHG and native Go ABI execution.
func TestX86AMD64CanonicalBoolTemporaryBytePortable(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	const source = "TEXT ·Value(SB),4,$0-9\nMOVB $2,x+0(FP)\nMOVB x+0(FP),AL\nCMPB AL,$2\nSETEQ ret+8(FP)\nRET\n"
	// An explicit integer shim avoids borrowing C's _Bool ABI attributes.
	const shim = `
define i32 @BoolByteProbe(i32 %input) {
 %boolean = icmp ne i32 %input, 0
 %result = call i1 @Value(i1 %boolean)
 %output = zext i1 %result to i32
 ret i32 %output
}
`
	const driver = "extern int BoolByteProbe(int);\nint main(void){return BoolByteProbe(0)==1&&BoolByteProbe(1)==1?0:1;}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(x bool) bool", "amd64", triple, api)
			if err != nil {
				t.Fatal(api, err)
			}
			ir += shim
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "bool-byte", triple, text, driver, nil, level)
				}
			}
		})
	}
}
