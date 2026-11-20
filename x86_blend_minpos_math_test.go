package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// This private mathematical companion is not execution of the original
// alignment/fault program. It decodes the complete unchanged source, checks
// the exact inventory, and transports m128 through a genuinely unused bank.
// Keep the original legacy register operation: replacing it by VEX would
// incorrectly clear the independently observed upper Y/Z destination aliases.
func x86BlendMinposMathSource(source string, targets, legacyMemory, transports int) (string, error) {
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	if len(file.Data) != 0 || len(file.Globl) != 0 || len(file.UnlinkedPrelude) != 0 || len(file.Funcs) != targets {
		return "", fmt.Errorf("private blend/minimum math needs its entire expected code-only source")
	}
	file, err = normalizeX86RawFile(file, "amd64")
	if err != nil {
		return "", err
	}
	used := [32]bool{}
	for _, fn := range file.Funcs {
		if fn.FrameSize != 0 || fn.ArgSize != 24 && fn.ArgSize != 32 || len(fn.X86RawText) != 0 {
			return "", fmt.Errorf("private math refuses a changed frame/native source role")
		}
		if len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT || fn.Instrs[len(fn.Instrs)-1].Op != OpRET {
			return "", fmt.Errorf("private math needs each original complete TEXT/RET program")
		}
		if fn.x86RawReplay != nil {
			if err := fn.x86RawReplay.validate(fn, "amd64"); err != nil {
				return "", err
			}
		}
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if arg.Kind == OpReg {
					if index, valid := amd64VectorRegisterIndex(arg.Reg, amd64VectorByteWidth(arg.Reg)); valid {
						used[index] = true
					}
				}
			}
		}
	}
	scratch := -1
	for index := 0; index < 8; index++ {
		if !used[index] {
			scratch = index
			break
		}
	}
	if scratch < 0 {
		return "", fmt.Errorf("complete original math source has no unused mode32 X alias bank")
	}
	var result strings.Builder
	gotTargets, gotLegacy, gotTransports := 0, 0, 0
	for _, fn := range file.Funcs {
		fmt.Fprintf(&result, "TEXT %s(SB),4,$0-%d\n", fn.Sym, fn.ArgSize)
		functionTargets := 0
		for _, ins := range fn.Instrs {
			if ins.Op == "TEXT" {
				continue
			}
			form, known, err := x86BlendMinposProperties(ins.Op, ins, "amd64")
			if known {
				if err != nil {
					return "", err
				}
				gotTargets++
				functionTargets++
				if form.legacy && form.memory {
					if ins.Args[form.source].Kind != OpMem || ins.Args[form.source].Mem.Sym != "" {
						return "", fmt.Errorf("private math refuses a different legacy memory role")
					}
					fmt.Fprintf(&result, "VMOVDQU %s,X%d\n", ins.Args[form.source], scratch)
					ins.Args = append([]Operand(nil), ins.Args...)
					ins.Args[form.source] = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", scratch))}
					gotLegacy++
				}
			} else if ins.Op == "MOVOU" && len(ins.Args) == 2 && ins.Args[0].Kind == OpMem && ins.Args[1].Kind == OpReg {
				// A plain VEX replacement of MOVOU would lose the old wider
				// aliases too. Use a separate register-to-register legacy copy.
				if ins.Args[0].Mem.Sym != "" || !isAMD64XReg(ins.Args[1].Reg) {
					return "", fmt.Errorf("private math refuses a different legacy transport role")
				}
				fmt.Fprintf(&result, "VMOVDQU %s,X%d\n", ins.Args[0], scratch)
				ins.Args = append([]Operand(nil), ins.Args...)
				ins.Args[0] = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", scratch))}
				gotTransports++
			} else if ins.Op != "MOVQ" && ins.Op != "VMOVUPS" && ins.Op != OpRET {
				return "", fmt.Errorf("private math refuses unrelated source operation %s", ins.Op)
			}
			args := make([]string, len(ins.Args))
			for index, arg := range ins.Args {
				args[index] = arg.String()
			}
			fmt.Fprintf(&result, "%s %s\n", ins.Op, strings.Join(args, ","))
		}
		if functionTargets != 1 {
			return "", fmt.Errorf("private math lost one original opcode per function: %d", functionTargets)
		}
	}
	if gotTargets != targets || gotLegacy != legacyMemory || gotTransports != transports {
		return "", fmt.Errorf("private math source inventory differs: targets=%d legacy-m128=%d MOVOU=%d", gotTargets, gotLegacy, gotTransports)
	}
	return result.String(), nil
}

func x86BlendMinposPrivateMathCompanion(t *testing.T, source string, targets, legacyMemory, transports int) *File {
	t.Helper()
	originalHash := sha256.Sum256([]byte(source))
	derived, err := x86BlendMinposMathSource(source, targets, legacyMemory, transports)
	if err != nil {
		t.Fatal("private mathematical instrumentation rejected the complete original source", err)
	}
	file, err := Parse(ArchAMD64, derived)
	if err != nil || originalHash != sha256.Sum256([]byte(source)) {
		t.Fatal("private mathematical instrumentation corrupted source/derived grammar", err)
	}
	t.Logf("private blend/minimum mathematical companion: original sha256=%x targets=%d legacy-m128 replacements=%d legacy transport replacements=%d; not original opcode alignment/fault execution", originalHash, targets, legacyMemory, transports)
	return file
}

// Wide virtual aliases must not accidentally require AVX512 on an ordinary
// host. Reuse the strict shared test-only feature projection: exact owned
// definition/profile pairs only, no native asm or active target intrinsic,
// and no changed body byte. This still does not execute original x86 opcodes.
func x86BlendMinposMathIR(file *File, ir string) (string, error) {
	profiles := make(map[string]string)
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		if _, duplicate := profiles[name]; duplicate || len(fn.X86RawText) != 0 {
			return "", fmt.Errorf("private mathematical IR lost its unique ordinary function")
		}
		profiles[name] = inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", fn)
	}
	return x86PackedShiftPortableFeatureProjection(ir, profiles)
}

func TestX86BlendMinposPrivateMathTransportAndBoundaries(t *testing.T) {
	rows := x86BlendMinposCases()
	codes := x86BlendMinposOriginalCodes(t, rows)
	for _, minimum := range []bool{false, true} {
		start, end, targets, memory, transports := 0, 72, 72, 12, 96
		if minimum {
			start, end, targets, memory, transports = 72, 78, 6, 1, 4
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("minimum=%t/raw=%t", minimum, raw), func(t *testing.T) {
				source, declarations := x86BlendMinposProgram(rows[start:end], codes[start:end], "amd64", raw)
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				derived, err := x86BlendMinposMathSource(source, targets, memory, transports)
				if err != nil || strings.Count(derived, "VMOVDQU ") != memory+transports {
					t.Fatal("exact full-source mathematical companion changed its replacement inventory", err)
				}
				// On nonmatching hosts every inserted transport and retained
				// legacy register operation must stay genuinely portable.
				file, err := Parse(ArchAMD64, derived)
				if err != nil {
					t.Fatal(err)
				}
				for _, triple := range []string{"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
					ir, err := x86ScalarFPBitViewAPI(t, derived, declarations, "amd64", triple, "Go")
					if err != nil {
						t.Fatal("private companion still contains a native legacy memory bridge", err)
					}
					if _, err := x86BlendMinposMathIR(file, ir); err != nil {
						t.Fatal("private companion lost exact source/IR feature ownership", err)
					}
				}
				for _, mutation := range []string{"inventory", "extra-op", "frame", "no-scratch"} {
					t.Run(mutation, func(t *testing.T) {
						changed, count := source, targets
						switch mutation {
						case "inventory":
							count++
						case "extra-op":
							changed = strings.Replace(source, "RET", "CPUID\nRET", 1)
						case "frame":
							changed = strings.Replace(source, "$0-", "$8-", 1)
						case "no-scratch":
							var occupied strings.Builder
							// Blend uses banks 0-3, but minimum uses only 0-1.
							// Occupy the entire candidate set, independently of
							// which banks the original builder already touches.
							for index := 0; index < 8; index++ {
								fmt.Fprintf(&occupied, "VMOVUPS Z%d,Z%d\n", index, index)
							}
							changed = strings.Replace(source, "RET", occupied.String()+"RET", 1)
						}
						output, err := x86BlendMinposMathSource(changed, count, memory, transports)
						if err == nil || output != "" {
							t.Fatal("different original source acquired the private mathematical instrumentation", mutation, err)
						}
						if mutation == "no-scratch" && !strings.Contains(err.Error(), "no unused mode32 X alias bank") {
							t.Fatal("occupied scratch banks were rejected for an unrelated source error", err)
						}
					})
				}
			})
		}
	}
}
