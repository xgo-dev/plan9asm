package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86LegacyPackedFloatingNativeMemoryUnboundSourcesBeforeEmission(t *testing.T) {
	for _, op := range []Op{"ADDPS", "ADDPD", "SUBPS", "SUBPD", "MULPS", "MULPD", "DIVPS", "DIVPD"} {
		for _, operand := range []Operand{
			{Kind: OpMem, Mem: MemRef{Base: SP, Off: 16}},
			{Kind: OpMem, Mem: MemRef{Base: BP, Off: -32}},
			{Kind: OpMem, Mem: MemRef{Base: AX, Index: BP, Scale: 1}},
			{Kind: OpFP, FPOffset: 0},
		} {
			t.Run(string(op)+"/"+operand.String(), func(t *testing.T) {
				ins := Instr{Op: op, Args: []Operand{operand, {Kind: OpReg, Reg: "X0"}}}
				c, ir := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				before := ir.String()
				form := x86LegacyPackedFloatContextForm(t, ins)
				if err := c.lowerLegacyPackedFloatingMemory(ins, form); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unbound native memory source accepted: %v", err)
				}
				if ir.String() != before {
					t.Fatal("unbound source rejection emitted IR side effects")
				}
			})
		}
		for _, addressBits := range []int{16, 32} {
			ins := Instr{
				Op: op, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: "X0"}},
				x86AddressBits: addressBits,
			}
			c, ir := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			before := ir.String()
			if err := c.lowerLegacyPackedFloatingMemory(ins, x86LegacyPackedFloatContextForm(t, ins)); !errors.Is(err, ErrProbeNeedsContext) || ir.String() != before {
				t.Fatalf("address-size %d bypassed native source binding or emitted IR: %v", addressBits, err)
			}
		}
	}
}

func x86LegacyPackedFloatContextForm(t *testing.T, ins Instr) x86FloatBinaryForm {
	t.Helper()
	addsub, known, err := x86FloatAddSubProperties(ins, "amd64")
	if known {
		if err != nil {
			t.Fatal(err)
		}
		return addsub.x86FloatBinaryForm
	}
	muldiv, known, err := x86FloatMulDivProperties(ins, "amd64")
	if !known || err != nil {
		t.Fatalf("missing complete typed legacy form: known=%t err=%v", known, err)
	}
	return muldiv.x86FloatBinaryForm
}

func TestX86LegacyPackedFloatingNativeMemoryUnboundSourcesFiveTargets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"ADDPS", "ADDPD", "SUBPS", "SUBPD", "MULPS", "MULPD", "DIVPS", "DIVPD"} {
			for _, operand := range []string{"16(SP)", "-32(BP)", "(AX)(BP*1)"} {
				t.Run(target.triple+"/"+op+"/"+operand, func(t *testing.T) {
					source, sig, pkg := x86OrdinaryBPNativeFixture(t, target.arch, "Value", op+" "+operand+",X0", operand, 0)
					x86InsertExtractGoListing(t, target.arch, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					opt := x86SourceStackOptions(target.arch, target.triple, sig)
					t.Run("Translate", func(t *testing.T) {
						ir, err := Translate(file, opt)
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, operand, ir, err)
					})
					t.Run("TranslateModuleInContext", func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						module, err := TranslateModuleInContext(ctx, file, opt)
						if !module.IsNil() {
							defer module.Dispose()
						}
						ir := ""
						if !module.IsNil() {
							ir = module.String()
						}
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, operand, ir, err)
					})
					t.Run("TranslateGoModule", func(t *testing.T) {
						translation, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
							GOARCH: target.arch, TargetTriple: target.triple,
							ResolveSym: opt.ResolveSym,
						})
						if translation != nil && !translation.Module.IsNil() {
							defer translation.Module.Dispose()
						}
						ir := ""
						if translation != nil && !translation.Module.IsNil() {
							ir = translation.Module.String()
						}
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, operand, ir, err)
					})
				})
			}
		}
	}
}

func TestX86LegacyPackedFloatingNativeMemoryUnboundAddressSizeActualGo(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			opcode  string
			prefix  string
			machine int
		}{
			{"ADDPS", "", 0x58}, {"ADDPD", "BYTE $0x66\n", 0x58},
			{"SUBPS", "", 0x5c}, {"SUBPD", "BYTE $0x66\n", 0x5c},
			{"MULPS", "", 0x59}, {"MULPD", "BYTE $0x66\n", 0x59},
			{"DIVPS", "", 0x5e}, {"DIVPD", "BYTE $0x66\n", 0x5e},
		} {
			t.Run(target.triple+"/"+row.opcode, func(t *testing.T) {
				body := row.prefix + fmt.Sprintf("BYTE $0x67\nBYTE $0x0f\nBYTE $%d\nBYTE $0x03\nRET", row.machine)
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, body)
				x86InsertExtractGoListing(t, target.arch, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := x86SourceStackOptions(target.arch, target.triple, sig)
				decoded, err := decodeX86RawDirectives(file.Funcs[0], target.arch)
				if err != nil {
					t.Fatal(err)
				}
				wantBits := 32
				if target.arch == "386" {
					wantBits = 16
				}
				if len(decoded.Instrs) != 3 || decoded.Instrs[0].Op != "TEXT" ||
					string(decoded.Instrs[1].Op) != row.opcode || decoded.Instrs[1].x86AddressBits != wantBits ||
					decoded.Instrs[1].x86SourceRaw == nil || decoded.Instrs[2].Op != "RET" {
					t.Fatalf("physical address-size/opcode identity lost: %+v", decoded.Instrs)
				}
				t.Run("Translate", func(t *testing.T) {
					_, err := Translate(file, opt)
					x86LegacyFloatMemoryRequireContext(t, err)
				})
				t.Run("TranslateModuleInContext", func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := TranslateModuleInContext(ctx, file, opt)
					if !module.IsNil() {
						defer module.Dispose()
					}
					x86LegacyFloatMemoryRequireContext(t, err)
				})
				t.Run("TranslateGoModule", func(t *testing.T) {
					translation, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
						GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: opt.ResolveSym,
					})
					if translation != nil && !translation.Module.IsNil() {
						defer translation.Module.Dispose()
					}
					x86LegacyFloatMemoryRequireContext(t, err)
				})
			})
		}
	}
}

func TestX86LegacyPackedFloatingNativeMemoryUnboundAddressSizeProducerIdentity(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for index, opcode := range x86LegacyFloatMemoryOpcodes() {
			for _, input := range []struct {
				name, body string
				raw        bool
			}{
				{"native_memory", "BYTE $0x0f\nBYTE $@OP\nBYTE $0x03", true},
				{"register_override", "BYTE $0x67\nBYTE $0x0f\nBYTE $@OP\nBYTE $0xc3", true},
				{"forged_raw_comment", opcode + " (AX),X0 // decoded from BYTE $0x67", false},
			} {
				t.Run(arch+"/"+opcode+"/"+input.name, func(t *testing.T) {
					body := input.body
					if input.raw {
						body = strings.ReplaceAll(body, "@OP", fmt.Sprint([]int{0x58, 0x5c, 0x59, 0x5e}[index/2]))
						if index%2 != 0 {
							body = "BYTE $0x66\n" + body
						}
					}
					source := "TEXT f(SB),4,$0-0\n" + body + "\nRET\n"
					x86InsertExtractGoListing(t, arch, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := decodeX86RawDirectives(file.Funcs[0], arch)
					if err != nil {
						t.Fatal(err)
					}
					if len(decoded.Instrs) != 3 || string(decoded.Instrs[1].Op) != opcode {
						t.Fatalf("lost complete default/register form: %+v", decoded.Instrs)
					}
					instruction := decoded.Instrs[1]
					if instruction.x86AddressBits != 0 || (instruction.x86SourceRaw != nil) != input.raw {
						t.Fatalf("default/register/forged-comment form acquired an override or raw origin: %+v", instruction)
					}
				})
			}
		}
	}
}

func x86LegacyFloatMemoryRequireContext(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("actual Go accepted source acquired native virtual-stack permission: %v", err)
	}
}
