package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Go's assembler accepts these physical encodings through WORD. Named CNT
// is the existing one-GP-destination source form, not a new Go syntax claim.
var arm64NamedSVECountCases = []struct {
	op   Op
	word uint32
}{
	{"CNTB", 0x0420e3e0}, {"CNTH", 0x0460e3e0},
	{"CNTW", 0x04a0e3e0}, {"CNTD", 0x04e0e3e0},
}

func TestARM64NamedSVECountFeatureForms(t *testing.T) {
	for _, row := range arm64NamedSVECountCases {
		for register := 0; register <= 30; register++ {
			instruction := Instr{Op: row.op, Args: []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", register))}}}
			if got := inferFuncTargetFeatures(ArchARM64, Func{Instrs: []Instr{instruction}}); got != "+sve" {
				t.Errorf("%s R%d: features %q, want +sve", row.op, register, got)
			}
		}
		for _, instruction := range []Instr{
			{Op: row.op},
			{Op: row.op, Args: []Operand{{Kind: OpImm, Imm: 0}}},
			{Op: row.op, Args: []Operand{{Kind: OpMem}}},
			{Op: row.op, Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}},
			{Op: Op(string(row.op) + ".S"), Args: []Operand{{Kind: OpReg, Reg: "R0"}}},
		} {
			if got := inferFuncTargetFeatures(ArchARM64, Func{Instrs: []Instr{instruction}}); got != "" {
				t.Errorf("malformed count %+v supplied features %q", instruction, got)
			}
		}
		for _, register := range []Reg{ZR, SP, "RSP", "R31", "R32", "W0", "F0", "V0.B16", "Z0.B"} {
			instruction := Instr{Op: row.op, Args: []Operand{{Kind: OpReg, Reg: register}}}
			if got := inferFuncTargetFeatures(ArchARM64, Func{Instrs: []Instr{instruction}}); got != "" {
				t.Errorf("%s %s supplied features %q", row.op, register, got)
			}
		}
	}
}

func arm64SVECountFeaturesFromIR(t *testing.T, ir string) map[string]bool {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	features := make(map[string]bool)
	for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
		if function.FirstBasicBlock().IsNil() {
			continue
		}
		for _, attribute := range function.GetFunctionAttributes() {
			if attribute.IsString() && attribute.GetStringKind() == "target-features" {
				for _, feature := range strings.Split(attribute.GetStringValue(), ",") {
					features[feature] = true
				}
			}
		}
	}
	return features
}

func TestARM64NamedSVECountLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, row := range arm64NamedSVECountCases {
		original := fmt.Sprintf("TEXT original(SB),$0-0\nWORD $%#08x\nRET\n", row.word)
		requireARM64GoAssemblerResult(t, original, true)
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(string(row.op)+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, triple, targetBackendCase{
						arch: ArchARM64, goarch: "arm64", result: true,
						body: string(row.op) + " R0\nMOVD R0, ret+0(FP)\nRET",
					})
					if err != nil {
						t.Fatal(err)
					}
					if !arm64SVECountFeaturesFromIR(t, ir)["+sve"] {
						t.Fatal("actual count caller lacks required +sve")
					}
					compileLLVMToObject(t, llc, triple, "count.ll", "count.o", ir)
				})
			}
		}
	}
}

func TestARM64SVECountCustomAttributes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, row := range arm64NamedSVECountCases {
		for _, body := range []string{string(row.op) + " R0", fmt.Sprintf("WORD $%#08x", row.word)} {
			for _, attrs := range []string{"nounwind", `nounwind "target-features"="+neon"`} {
				for _, api := range []string{"text", "module"} {
					t.Run(body+"/"+attrs+"/"+api, func(t *testing.T) {
						ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", targetBackendCase{
							arch: ArchARM64, goarch: "arm64", result: true, attrs: attrs,
							body: body + "\nMOVD R0, ret+0(FP)\nRET",
						})
						if err != nil {
							t.Fatal(err)
						}
						features := arm64SVECountFeaturesFromIR(t, ir)
						if !features["+sve"] || !strings.Contains(ir, "nounwind") ||
							strings.Contains(attrs, "+neon") && !features["+neon"] {
							t.Fatalf("required or custom attributes lost: %v", features)
						}
						compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "count.ll", "count.o", ir)
					})
				}
			}
			for _, api := range []string{"text", "module"} {
				t.Run(body+"/disabled/"+api, func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", targetBackendCase{
						arch: ArchARM64, goarch: "arm64", attrs: `nounwind "target-features"="+neon,-sve"`,
						body: body + "\nRET",
					})
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("explicit -sve was overridden: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestARM64NamedSVECountRejectsInvalidForms(t *testing.T) {
	for _, row := range arm64NamedSVECountCases {
		for _, operands := range []string{"", "R0,R1", "$1", "(R0)", "ZR", "RSP", "R31", "F0", "V0.B16", "Z0.B"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(string(row.op)+"/"+operands+"/"+api, func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", targetBackendCase{
						arch: ArchARM64, goarch: "arm64", body: string(row.op) + " " + operands + "\nRET",
					})
					if err == nil || ir != "" {
						t.Fatalf("invalid count form succeeded: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}
