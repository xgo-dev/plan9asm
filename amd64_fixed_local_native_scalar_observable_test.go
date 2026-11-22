package plan9asm

import (
	"errors"
	"fmt"
	"path/filepath"
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
			op, _, _ := strings.Cut(operation, " ")
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
				switch op {
				case "SQRTSS", "SQRTSD", "ADDSS", "ADDSD":
					x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unregistered instruction shape") {
						t.Fatal("unregistered legacy scalar floating family acquired a fixed-local owner", err)
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
							var observable bool
							if strings.HasPrefix(op, "V") {
								width := 4
								if strings.HasSuffix(op, "SD") {
									width = 8
								}
								observable = strings.Contains(text, fmt.Sprintf("load volatile <%d x i8>,", width))
								if strings.HasPrefix(op, "VSQRT") {
									observable = observable && strings.Contains(text, "asm sideeffect \""+strings.ToLower(op)+" ")
								} else {
									intrinsic := fmt.Sprintf("@llvm.experimental.constrained.fadd.f%d(", 8*width)
									observable = observable && strings.Contains(text, intrinsic) && strings.Contains(text, "fpexcept.strict")
								}
							} else {
								bits := map[string]int{"ADDB": 8, "ADDW": 16, "ADDL": 32, "ADDQ": 64}[op]
								observable = strings.Contains(text, fmt.Sprintf("load volatile i%d,", bits))
							}
							if !observable {
								t.Fatal("dead scalar native access lost its exact memory or floating effect", operation, api)
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
