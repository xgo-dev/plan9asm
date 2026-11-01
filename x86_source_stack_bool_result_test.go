package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86PhysicalBoolTranslate(t *testing.T, arch, triple, api, source string, sig FuncSig, pkg GoPackage) error {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple})
		if result != nil && !result.Module.IsNil() {
			result.Module.Dispose()
		}
		return err
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return err
	}
	opt := x86SourceStackOptions(arch, triple, sig)
	if api == "text" {
		_, err = Translate(file, opt)
		return err
	}
	module, err := TranslateModuleInContext(ctx, file, opt)
	if !module.IsNil() {
		module.Dispose()
	}
	return err
}

func TestX86PhysicalSourceStackBoolCompleteResultThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := int64(8)
		if target.arch == "386" {
			word = 4
		}
		// Exact unchanged bool source from both failed complete CI fixtures.
		source, sig, pkg := x86SourceStackTypedFixture(target.arch, "bool", I1, word, "MOVB",
			"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				if err := x86PhysicalBoolTranslate(t, target.arch, target.triple, api, source, sig, pkg); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestX86PhysicalSourceStackBoolNoncanonicalBytesStayContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := int64(8)
		if target.arch == "386" {
			word = 4
		}
		for _, body := range []string{
			"MOVB $2,AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
			"MOVB $3,@RESULT(SP)\nBYTE $0xc3",
			"MOVB $255,AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
			"MOVB BX,@RESULT(SP)\nBYTE $0xc3",
			"MOVB @WORD(SP),AX\nBYTE $0xc3",
		} {
			source, sig, pkg := x86SourceStackTypedFixture(target.arch, "bool", I1, word, "MOVB", body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%s/%s", target.triple, api, strings.ReplaceAll(body, "\n", ";")), func(t *testing.T) {
					if err := x86PhysicalBoolTranslate(t, target.arch, target.triple, api, source, sig, pkg); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("noncanonical/undefined physical bool accepted: %v", err)
					}
				})
			}
		}
	}
}

func TestX86PhysicalSourceStackBoolAliasesStackAndCFG(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix := int64(8), "Q"
		if target.arch == "386" {
			word, suffix = 4, "L"
		}
		read := "MOVB @WORD(SP),AX\n"
		write := "MOVB AX,@RESULT(SP)\nBYTE $0xc3"
		for _, test := range []struct {
			name, body string
			accepted   bool
		}{
			{"zero", "MOVB $0,AX\n" + write, true},
			{"one", "MOVB $1,AX\n" + write, true},
			{"high byte alias", "MOVB @WORD(SP),AH\nMOVB AH,BL\nMOVB BL,@RESULT(SP)\nBYTE $0xc3", true},
			{"word saved value", read + "PUSHW AX\nMOVW $0,AX\nPOPW AX\n" + write, true},
			{"native saved value", read + "PUSH" + suffix + " AX\nMOV" + suffix + " $0,AX\nPOP" + suffix + " AX\n" + write, true},
			{"restored frame", read + "PUSH" + suffix + " BP\nMOV" + suffix + " SP,BP\nMOV" + suffix + " BP,SP\nPOP" + suffix + " BP\n" + write, true},
			{"raw intermediate", "MOVB $3,@RESULT(SP)\nMOVB @RESULT(SP),AX\nANDB $1,AX\n" + write, true},
			{"observable raw intermediate", "MOVB $2,@RESULT(SP)\nMOVB @RESULT(SP),AX\nSHRB $1,AX\nANDB $1,AX\n" + write, true},
			{"canonical join", "MOVL $0,AX\nCMPL AX,$0\nJE alternate\nMOVB $0,@RESULT(SP)\nJMP done\nalternate:\nMOVB $1,@RESULT(SP)\ndone:\nBYTE $0xc3", true},
			{"noncanonical join", "MOVL $0,AX\nCMPL AX,$0\nJE alternate\nMOVB $0,@RESULT(SP)\nJMP done\nalternate:\nMOVB $3,@RESULT(SP)\ndone:\nBYTE $0xc3", false},
			{"unknown upper byte", read + "MOVB AH,@RESULT(SP)\nBYTE $0xc3", false},
			{"unknown overwritten value", read + "MOVB BL,AL\n" + write, false},
			{"partial slot", "MOVW @WORD(SP),AX\n" + write, false},
			{"padding", "MOVB @WORD+1(SP),AX\n" + write, false},
			{"unbalanced stack", read + "PUSH" + suffix + " AX\n" + write, false},
			{"wrong stack width", read + "PUSHW AX\nPOP" + suffix + " AX\n" + write, false},
			{"input store", "MOVB $2,@WORD(SP)\n" + read + write, false},
			{"pointer escape", read + "MOVB AX,(BX)\n" + write, false},
			{"call", read + "CALL ·callee(SB)\n" + write, false},
		} {
			source, sig, pkg := x86SourceStackTypedFixture(target.arch, "bool", I1, word, "MOVB", test.body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+test.name+"/"+api, func(t *testing.T) {
					err := x86PhysicalBoolTranslate(t, target.arch, target.triple, api, source, sig, pkg)
					if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("physical bool accepted=%t: %v", test.accepted, err)
					}
				})
			}
		}
	}
}

func TestX86PhysicalSourceStackBoolProofAndSignatureCannotBeRebound(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, triple := int64(8), "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, triple = 4, "i386-unknown-linux-gnu"
		}
		source, sig, _ := x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
			"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, arch, x86SourceStackOptions(arch, triple, sig))
		if err != nil {
			t.Fatal(err)
		}
		before := cloneX86ReplayInstrs(file.Funcs[0].Instrs)
		original := normalized.Funcs[0]
		for _, change := range []string{"none", "proof missing", "wrong mode", "wrong header", "changed original", "changed access", "removed access", "changed instruction", "changed raw spelling", "signature result offset", "signature type", "signature input type", "signature custom entry", "forged stack", "copied stack token", "changed stack minimum", "changed stack normalized identity"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				fn := original
				fn.Instrs = cloneX86ReplayInstrs(fn.Instrs)
				copies, err := cloneFixedLocalSigs(map[string]FuncSig{sig.Name: sig})
				if err != nil {
					t.Fatal(err)
				}
				declaration := copies[sig.Name]
				consumer := &amd64Ctx{sig: declaration, fpSourceSig: declaration, fpScalarSource: fn,
					sourceStack: fn.x86SourceStack, goarch: arch, targetTriple: triple}
				switch change {
				case "proof missing":
					consumer.sourceStack = nil
				case "wrong mode":
					consumer.goarch = "arm64"
				case "wrong header":
					consumer.fpScalarSource.ArgSize++
				case "changed original":
					replay := *fn.x86RawReplay
					replay.original = cloneX86ReplayInstrs(replay.original)
					replay.original[1].Raw = "MOVB $1,AX"
					consumer.fpScalarSource.x86RawReplay = &replay
				case "changed access":
					consumer.fpScalarSource.Instrs[1].x86SourceStackFP[0]++
				case "removed access":
					consumer.fpScalarSource.Instrs[1].x86SourceStackFP = nil
				case "changed instruction":
					consumer.fpScalarSource.Instrs[1].Args[0].Mem.Off++
				case "changed raw spelling":
					consumer.fpScalarSource.Instrs[1].Raw = "MOVB $1,AX"
				case "signature result offset":
					consumer.fpSourceSig.Frame.Results[0].Offset++
				case "signature type":
					consumer.fpSourceSig.Ret = I8
				case "signature input type":
					consumer.fpSourceSig.Args[0] = I8
				case "signature custom entry":
					consumer.fpSourceSig.ArgRegs = []Reg{AX}
				case "forged stack":
					consumer.sourceStack = &x86SourceStackProof{word: word}
					consumer.fpScalarSource.x86SourceStack = consumer.sourceStack
				case "copied stack token", "changed stack minimum", "changed stack normalized identity":
					copy := *consumer.sourceStack
					consumer.sourceStack = &copy
					consumer.fpScalarSource.x86SourceStack = &copy
					if change == "changed stack minimum" {
						copy.minimum -= word
					}
					if change == "changed stack normalized identity" {
						copy.normalized[0] ^= 1
					}
				}
				err = consumer.checkSourceStackScalarResultInitialization()
				if change == "none" && err != nil || change != "none" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("changed=%s source-stack result: %v", change, err)
				}
			})
		}
		if !reflect.DeepEqual(before, file.Funcs[0].Instrs) {
			t.Fatal("normalization mutated caller source")
		}
	}
}

func TestX86PhysicalSourceStackBoolCloneAndByteBudget(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word := int64(8)
		if arch == "386" {
			word = 4
		}
		source, sig, _ := x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
			"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		initial := x86SourceStackScalarInitial(file.Funcs[0], sig, arch)
		if initial == nil {
			t.Fatal("actual scalar bool layout rejected")
		}
		copy := initial.clone()
		copy.bytes.fp[0], copy.bytes.canonicalFP[0], copy.bytes.gp[0] = false, false, 255
		if !initial.bytes.fp[0] || !initial.bytes.canonicalFP[0] || initial.bytes.gp[0] != 0 {
			t.Fatal("physical bool CFG state aliases predecessor")
		}
		sig.Frame.Results[0].Offset = 4095
		text := fmt.Sprintf("TEXT ·Value(SB),4,$0-4096\nMOVB %d(SP),AX\n", word) +
			strings.Repeat("MOVB $1,AX\n", 2048) + fmt.Sprintf("MOVB AX,%d(SP)\nBYTE $0xc3\n", word+4095)
		file, err = Parse(ArchAMD64, text)
		if err != nil {
			t.Fatal(err)
		}
		opt := x86SourceStackOptions(arch, "", sig)
		if _, err := normalizeX86RawFile(file, arch, opt); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "byte budget") {
			t.Fatalf("combined physical bool byte-work budget not retained: %v", err)
		}
	}
}

func TestX86PhysicalSourceStackBoolRuntimeFixtureRetainsBothByteRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word := int64(8)
		if arch == "386" {
			word = 4
		}
		source, sigs := x86SourceStackRuntimeSource(arch)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		want := len(x86SourceStackRuntimeCases(arch)) + 3
		if len(file.Funcs) != want || len(sigs) != want {
			t.Fatal("complete old runtime inventory plus two bool roles differs")
		}
		old, _, _ := x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
			"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
		old = strings.ReplaceAll(old, "·Value", "·PhysicalBool")
		if strings.Count(source, old) != 1 {
			t.Fatal("original physical bool source changed")
		}
		for _, driver := range []string{x86SourceStackGoOracle(arch), x86SourceStackCOracle(arch)} {
			if strings.Count(driver, "PhysicalBool(") != 3 || strings.Count(driver, "PhysicalBoolIntermediate(") != 3 || strings.Count(driver, "PhysicalBoolNamedFP(") != 3 {
				t.Fatal("independent original Go/LLVM caller lacks both bool inputs/roles")
			}
		}
	}
}
