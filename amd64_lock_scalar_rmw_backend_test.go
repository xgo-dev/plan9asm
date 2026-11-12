package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86LockScalarRMWNativeBackendFollowsActualCalls(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		native, otherMode := testTargetTriple("linux", arch), "i386-unknown-linux-gnu"
		if arch == "386" {
			otherMode = "x86_64-unknown-linux-gnu"
		}
		for _, row := range []struct{ instruction, mnemonic string }{
			{"ADCL CX,1(SI)", "adcl"},
			{"ADDB $1,1(SI)", "addb"},
			{"NOTL 1(SI)", "notl"},
			{"BTCL $1,1(SI)", "btcl"},
		} {
			source := x86NamedLockOracleSource(arch, "CMPL AX,AX\nLOCK\n"+row.instruction)
			x86LockScalarOriginalInstruction(t, arch, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.instruction+"/"+api+"/native", func(t *testing.T) {
					ir, err := x86OrderingHintTranslateAPI(t, api, source,
						"package ordering\nfunc locked(p *[16]byte)\n", arch, native)
					if err != nil {
						t.Fatal("complete native LOCK request rejected", err)
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := parseIRModuleInContext(ctx, ir)
					if err != nil {
						t.Fatal(err)
					}
					defer module.Dispose()
					caller := module.NamedFunction("locked")
					if caller.IsNil() {
						t.Fatal("public LOCK source body is absent")
					}
					calls := 0
					for block := caller.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
						for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
							if instruction.IsACallInst().IsNil() {
								continue
							}
							helper := instruction.CalledValue()
							if !strings.HasPrefix(helper.Name(), "__plan9asm_lock_rmw_") {
								continue
							}
							calls++
							if helper.FirstUse().IsNil() || helper.FirstBasicBlock().IsNil() {
								t.Fatal("caller did not reference a defined native helper")
							}
							nativeUse := false
							for body := helper.FirstBasicBlock(); !body.IsNil(); body = llvm.NextBasicBlock(body) {
								for emitted := body.FirstInstruction(); !emitted.IsNil(); emitted = llvm.NextInstruction(emitted) {
									for index := 0; index < emitted.OperandsCount(); index++ {
										assembly := emitted.Operand(index).IsAInlineAsm()
										if assembly.IsNil() {
											continue
										}
										info := assembly.InlineAsmInfo()
										if info.HasSideEffects && strings.Contains(info.Assembly, "lock; "+row.mnemonic) {
											nativeUse = true
										}
									}
								}
							}
							if !nativeUse {
								t.Fatal("actually called helper lost its native atomic instruction")
							}
						}
					}
					if calls != 1 {
						t.Fatal("source body must call exactly one complete LOCK helper", calls)
					}
				})
				for _, triple := range []string{"", otherMode, "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					t.Run(arch+"/"+row.instruction+"/"+api+"/"+triple, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source,
							"package ordering\nfunc locked(p *[16]byte)\n", arch, triple)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "inline assembly") {
							t.Fatal("complete native LOCK escaped an absent or foreign backend", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LockScalarRMWPortableNonLOCKDoesNotAcquireHelpers(t *testing.T) {
	source := "TEXT ·plain(SB),4,$0-0\nMOVL $1,AX\nMOVL $2,BX\nADDL AX,BX\nRET\n"
	for _, arch := range []string{"amd64", "386"} {
		goAssemblerOracleOutput(t, arch, source, "", true)
		for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func plain()", arch, triple, api)
					if err != nil || ir == "" || strings.Contains(ir, "__plan9asm_lock_rmw_") {
						t.Fatal("portable unprefixed scalar operation acquired a native helper or backend", err)
					}
				})
			}
		}
	}
}
