package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86Mode32LogicalScalarResultsComposeWithBoundZeroCleanupReturn(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, result := range []struct {
			typ  LLVMType
			move string
		}{{I8, "MOVB $17,AX"}, {I16, "MOVW $4660,AX"}, {I32, "MOVL $2309737967,AX"}} {
			for index, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
				t.Run(fmt.Sprintf("%s/%s/%d", target.triple, result.typ, index), func(t *testing.T) {
					source := "TEXT value(SB),4,$0-0\n" + result.move + "\n" + encoding + "\nRET\n"
					requireX86GoAssemblerResult(t, target.arch, source, true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					sig := FuncSig{Name: "value", Ret: result.typ}
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone declaration query borrowed a raw return contract", err)
					}
					for _, api := range []string{"text", "module"} {
						t.Run(api, func(t *testing.T) {
							options := Options{Goarch: target.arch, TargetTriple: target.triple,
								Sigs: map[string]FuncSig{"value": sig}}
							var ir string
							if api == "text" {
								ir, err = Translate(file, options)
							} else {
								context := llvm.NewContext()
								defer context.Dispose()
								module, moduleErr := TranslateModuleInContext(context, file, options)
								err = moduleErr
								if !module.IsNil() {
									defer module.Dispose()
									ir = module.String()
								}
							}
							if err != nil || ir == "" {
								t.Fatal("complete original zero-cleanup leaf lost its logical AX result", err)
							}
							for _, optimized := range []bool{false, true} {
								text := ir
								if optimized {
									text = x86DwordProductIROptimize(t, text)
								}
								compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "raw-logical-return.ll", "raw-logical-return.o", text)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86Mode32RawLogicalReturnRetainsExactReplayAndSource(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\nMOVL $17,AX\nBYTE $0xc3\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	file, err = NormalizeRawFileForTranslation(file, "386")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Func){
		"unchanged":            func(*Func) {},
		"missing-replay":       func(fn *Func) { fn.x86RawReplay = nil },
		"changed-move":         func(fn *Func) { fn.Instrs[1].Args[0].Imm++ },
		"changed-raw-spelling": func(fn *Func) { fn.Instrs[2].Raw += " changed" },
		"changed-return-width": func(fn *Func) { fn.Instrs[2].x86RawNearReturn.nativeWidth = false },
		"changed-cleanup":      func(fn *Func) { fn.Instrs[2].x86RawNearReturn.cleanup = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = cloneX86ReplayInstrs(fn.Instrs)
			mutate(&fn)
			before := cloneX86ReplayInstrs(fn.Instrs)
			context := amd64Ctx{goarch: "386", fpScalarSource: fn, sig: FuncSig{Name: "value", Ret: I32}}
			selected, err := context.checkRawLogicalScalarResult()
			if !selected || (name == "unchanged" && err != nil) ||
				(name != "unchanged" && !errors.Is(err, ErrProbeNeedsContext)) {
				t.Fatal("raw return acquired a changed or incomplete source role", selected, err)
			}
			if !reflect.DeepEqual(before, fn.Instrs) {
				t.Fatal("logical result consumer edited the sealed original source")
			}
		})
	}
}

func TestX86Mode32RawLogicalReturnsCannotSupplyMissingBytesOrPhysicalEntry(t *testing.T) {
	for _, source := range []string{
		"TEXT value(SB),4,$0-0\nBYTE $0xc3\nRET\n",
		"TEXT value(SB),4,$0-0\nMOVB $17,AX\nBYTE $0xc3\nRET\n",
		"TEXT value(SB),4,$0-0\nMOVL SP,BX\nMOVL $17,AX\nBYTE $0xc3\nRET\n",
		"TEXT value(SB),4,$8-0\nMOVL $17,AX\nBYTE $0xc3\nRET\n",
		"TEXT value(SB),4,$0-0\nMOVL $17,AX\nBYTE $0xc2\nWORD $4\nRET\n",
	} {
		requireX86GoAssemblerResult(t, "386", source, true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"value": {Name: "value", Ret: I32}}})
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("raw RET supplied missing data, stack or entry authority", strings.ReplaceAll(source, "\n", ";"), err)
		}
	}
}
