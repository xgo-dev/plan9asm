package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Go progedit rewrites the whole MOVL/Q TYPE_ADDR family to LEAL/Q before
// classification. A raw near RET must not prohibit a purely numerical,
// stack-unobserving address calculation or inherit unrelated source proofs.
func TestX86RawReturnSourceAddressLeafThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		widths := []string{"L"}
		if target.arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, address := range []string{"8(AX)", "-8(AX)(CX*1)", "16(AX)(CX*2)", "32(AX)(CX*4)", "64(AX)(CX*8)", "8(CX*4)", "(1<<4)(AX)"} {
				t.Run(target.triple+"/"+width+"/"+address, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·addr(SB),4,$0-0\nMOVL $3,AX\nMOVL $2,CX\nMOV%s $%s,BX\nBYTE $0xc3\nRET\n", width, address)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					before := fmt.Sprintf("%#v", file.Funcs)
					pkg := x86AddSubLiteralPackage(t, target.arch, "func addr()\n")
					resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							context := llvm.NewContext()
							defer context.Dispose()
							var ir string
							var err error
							switch api {
							case "text":
								ir, err = Translate(file, options)
							case "module":
								var module llvm.Module
								module, err = TranslateModuleInContext(context, file, options)
								if !module.IsNil() {
									defer module.Dispose()
									ir = module.String()
								}
							case "GoModule":
								var result *GoModuleTranslation
								result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
									GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
								if result != nil && !result.Module.IsNil() {
									defer result.Module.Dispose()
									ir = result.Module.String()
								}
							}
							if err != nil {
								t.Fatal(err)
							}
							compileLLVMToObject(t, llc, target.triple, "raw-return-address.ll", "raw-return-address.o", ir)
							if before != fmt.Sprintf("%#v", file.Funcs) {
								t.Fatal("derived address changed the original source")
							}
						})
					}
				})
			}
		}
	}
}

func TestX86RawReturnSourceAddressCannotInheritProof(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		file, err := Parse(ArchAMD64, "TEXT addr(SB),4,$0-0\nMOVL $8(AX)(CX*4),BX\nBYTE $0xc3\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Name: "addr", Ret: Void}}}
		normalized, err := normalizeX86RawFile(file, arch, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"sourceStack", "fixedLocal", "rawText", "LOCK", "frame", "scalarConstant", "g", "memory", "encodedSibling"} {
			t.Run(arch+"/"+field, func(t *testing.T) {
				copy := *normalized
				copy.Funcs = append([]Func(nil), normalized.Funcs...)
				fn := &copy.Funcs[0]
				fn.Instrs = append([]Instr(nil), fn.Instrs...)
				fn.Instrs[1].Args = append([]Operand(nil), fn.Instrs[1].Args...)
				switch field {
				case "sourceStack":
					fn.x86SourceStack = &x86SourceStackProof{}
				case "fixedLocal":
					fn.x86FixedLocal = &x86FixedLocalProof{}
				case "rawText":
					fn.X86RawText = []byte{0xc3}
				case "LOCK":
					fn.Instrs = append(fn.Instrs, Instr{Op: "LOCK"})
				case "frame":
					fn.FrameSize = 8
				case "scalarConstant":
					fn.Instrs[1].Op = "MOVW"
				case "g":
					fn.Instrs = append(fn.Instrs, Instr{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: "R14"}, {Kind: OpReg, Reg: AX}}})
				case "memory":
					fn.Instrs = append(fn.Instrs, Instr{Op: "MOVL", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: DX}}})
				case "encodedSibling":
					fn.Instrs = append(fn.Instrs, Instr{Op: "MOVL", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, x86Encoded: true})
				}
				before := fmt.Sprintf("%#v", fn)
				if _, err := normalizeX86SourceIntegerAddresses(&copy, options); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("adapter inherited %s proof or native effect: %v", field, err)
				}
				if before != fmt.Sprintf("%#v", fn) || !reflect.DeepEqual(file.Funcs[0].Instrs[1].Args, normalized.Funcs[0].Instrs[1].Args) {
					t.Fatal("rejection modified original instructions")
				}
			})
		}
	}
}
