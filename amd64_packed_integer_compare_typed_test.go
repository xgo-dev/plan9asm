package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var x86PackedIntegerCompareTestNames = []string{
	"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPEQQ",
	"PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ",
	"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ",
	"VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ",
}

func x86PackedIntegerCompareAPI(t *testing.T, source, declaration, arch, triple, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "compare", "package compare\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		module, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: arch, TargetTriple: triple, ResolveSym: resolve,
		})
		if module != nil && !module.Module.IsNil() {
			defer module.Module.Dispose()
			return module.Module.String(), err
		}
		return "", err
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: signatures}
	if api == "text" {
		return Translate(file, options)
	}
	if api != "module" {
		t.Fatal("unknown packed comparison consumer", api)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func TestX86PackedIntegerCompareMode32HighBankActualSourceNeedsContext(t *testing.T) {
	for _, op := range x86PackedIntegerCompareTestNames[8:] {
		for _, operands := range []string{
			"X8,X1,X2", "X1,X8,X2", "X1,X2,X15",
			"Y15,Y1,Y2", "Y1,Y15,Y2", "Y1,Y2,Y8",
			"X20,X1,K2", "X1,X20,K2", "Y20,Y1,K2", "Y1,Y20,K2",
		} {
			for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				t.Run(op+"/"+operands+"/"+triple, func(t *testing.T) {
					source := "TEXT ·query(SB),4,$0-0\n" + op + " " + operands + "\nRET\n"
					x86LEAActualTargetGoObject(t, "386", triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86PackedIntegerCompareAPI(t, source, "func query()\n", "386", triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("actual Go acceptance fabricated a physical high bank: IR=%d err=%v", len(ir), err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86PackedIntegerCompareDispatchIdentityBeforeEmission(t *testing.T) {
	for _, op := range x86PackedIntegerCompareTestNames {
		operands := []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}
		if strings.HasPrefix(op, "V") {
			operands = append(operands, Operand{Kind: OpReg, Reg: "X2"})
		}
		for _, identity := range []Op{"", Op(op), Op(strings.ToLower(op)), "MOVOU", "UNKNOWN"} {
			t.Run(op+"/"+string(identity), func(t *testing.T) {
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = "amd64"
				ins := Instr{Op: identity, Args: operands}
				before, temporary := output.String(), ctx.tmp
				original := fmt.Sprintf("%#v", ins)
				known, terminated, err := ctx.lowerPackedIntegerCompare(Op(op), ins)
				invalid := identity != "" && !strings.EqualFold(string(identity), op)
				if !known || terminated || (err != nil) != invalid ||
					invalid && (before != output.String() || temporary != ctx.tmp) || original != fmt.Sprintf("%#v", ins) {
					t.Fatalf("dispatch identity changed source or emitted before rejection: %v", err)
				}
			})
		}
	}
}

func TestX86PackedIntegerCompareLegacyNativeOpcodeAndVirtualBoundaries(t *testing.T) {
	for _, op := range x86PackedIntegerCompareTestNames[:8] {
		for _, target := range x86RawReturnTargets {
			t.Run(op+"/"+target.triple, func(t *testing.T) {
				source := "TEXT ·query(SB),4,$0-0\n" + op + " (AX),X1\nRET\n"
				x86UnboundVoidFormatSource(t, source, "query", target.arch, target.triple)
				word, move := int(goWordSize(target.arch)), "MOVQ"
				if word == 4 {
					move = "MOVL"
				}
				// Keep the exact original m128 instruction. Only its actual
				// pointer and destructive X input are established here; the
				// complete native-object owner covers the family separately.
				initialized := fmt.Sprintf("TEXT ·query(SB),4,$0-%d\n%s p+0(FP),AX\nPXOR X1,X1\n%s (AX),X1\nRET\n", word, move, op)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, initialized)
				mnemonic := strings.ToLower(strings.ReplaceAll(op, "L", "D"))
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86PackedIntegerCompareAPI(t, initialized, "func query(p *[16]byte)\n", target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized original legacy source rejected", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if !strings.Contains(text, "asm sideeffect \""+mnemonic+" ($2), $0\"") {
							t.Fatal("legacy m128 erased original opcode/fault semantics", api)
						}
					}
				}
			})
		}
		for _, operand := range []string{"a+0(FP)", "16(SP)", "16(BP)"} {
			t.Run(op+"/virtual/"+operand, func(t *testing.T) {
				source := "TEXT ·query(SB),4,$64-16\n" + op + " " + operand + ",X1\nRET\n"
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				ir, err := x86PackedIntegerCompareAPI(t, source, "func query(a,b uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("virtual fields acquired native legacy m128 alignment: IR=%d err=%v", len(ir), err)
				}
			})
		}
	}
}
