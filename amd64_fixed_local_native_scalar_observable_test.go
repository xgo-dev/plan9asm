package plan9asm

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalNativeScalarDeadAccesses(t *testing.T) {
	const declaration = "func Value(p,q *uint64,a uint64) uint64"
	const triple = "x86_64-unknown-linux-gnu"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, row := range []string{
		"SQRTSS (%s),X1", "SQRTSD (%s),X1",
		"VSQRTSS (%s),X1,X2", "VSQRTSD (%s),X1,X2",
		"ADDSS (%s),X1", "ADDSD (%s),X1",
		"VADDSS (%s),X1,X2", "VADDSD (%s),X1,X2",
		"VMOVSS (%s),X1", "VMOVSD (%s),X1",
		"VMOVSS X1,(%s)", "VMOVSD X1,(%s)",
		"ADDB (%s),CL", "ADDW (%s),CX", "ADDL (%s),CX", "ADDQ (%s),CX",
	} {
		for _, base := range []string{"AX", "BP"} {
			operation := fmt.Sprintf(row, base)
			t.Run(operation, func(t *testing.T) {
				body := "MOVQ $1,CX\nMOVQ CX,X1\nMOVQ $0,AX\nMOVQ AX," + base + "\n" +
					operation + "\nMOVQ $0,AX"
				_, _, assembly := fixedLocalInputFixture(t, body)
				pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", triple)
				captureStage, captureCancel := runtimeOracleStageContext(t)
				source, err := CaptureGoAMD64FrameSource(captureStage, pkg, request)
				captureCancel()
				if strings.HasPrefix(operation, "VMOV") {
					x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
					if source != nil {
						if closeErr := source.Close(); closeErr != nil {
							t.Error(closeErr)
						}
					}
					if !errors.Is(err, ErrProbeNeedsContext) ||
						!strings.Contains(err.Error(), "unregistered or truncated whole native VEX/EVEX encoding") {
						t.Fatal("unclosed scalar-move object producer acquired source facts", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := source.Close(); err != nil {
						t.Error(err)
					}
				})
				original, err := goAMD64FrameRead(filepath.Join(request.Directory, request.AssemblyFile))
				if err != nil {
					t.Fatal(err)
				}
				expanded, err := source.preprocess(request.AssemblyFile, original)
				if err != nil {
					t.Fatal(err)
				}
				file, err := ParseWithDefines(ArchAMD64, expanded, nil)
				if err != nil {
					t.Fatal(err)
				}
				stage, cancel := runtimeOracleStageContext(t)
				defer cancel()
				bound, err := source.BindFixedLocal(stage, pkg, file, options)
				if !strings.HasPrefix(operation, "ADD") || strings.HasPrefix(operation, "ADDSS") || strings.HasPrefix(operation, "ADDSD") {
					x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unregistered instruction shape") {
						t.Fatal("unregistered scalar floating family acquired a fixed-local owner", err)
					}
					return
				}
				if err != nil {
					t.Fatal("original scalar source lacks its fixed-local owner", err)
				}
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86PackedFloatStorageAPI(api, file, bound)
						if err != nil || ir == "" {
							t.Fatal("original scalar source did not translate", err)
						}
						for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							observable := regexp.MustCompile(`\b(?:load|store) volatile i(?:8|16|32|64)\b`).MatchString(text)
							for _, line := range strings.Split(text, "\n") {
								observable = observable || strings.Contains(line, "asm sideeffect") &&
									strings.Contains(line, "~{memory}") && strings.Contains(line, "*m")
							}
							if !observable {
								t.Fatal("dead scalar native access lost its observable memory effect", operation, api, text)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, text, level)
							}
						}
					})
				}
			})
		}
	}
}
