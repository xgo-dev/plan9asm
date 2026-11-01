//go:build go1.27

package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestGoX86ResultAUTOCompleteActualFixedLocalNumericalJoinOriginalSourceShape(t *testing.T) {
	numericalResultAUTOCompleteActualFixedLocalJoin(t, "original-source-shape")
}

func TestGoX86ResultAUTOCompleteActualFixedLocalNumericalJoinText(t *testing.T) {
	numericalResultAUTOCompleteActualFixedLocalJoin(t, "text")
}

func TestGoX86ResultAUTOCompleteActualFixedLocalNumericalJoinContext(t *testing.T) {
	numericalResultAUTOCompleteActualFixedLocalJoin(t, "context")
}

func TestGoX86ResultAUTOCompleteActualFixedLocalNumericalJoinGoModule(t *testing.T) {
	numericalResultAUTOCompleteActualFixedLocalJoin(t, "go-module")
}

// Each public owner invokes the complete fresh producer once, with its own
// original deadline and lifecycle. Keep this fixture shared, not its owner.
func numericalResultAUTOCompleteActualFixedLocalJoin(t *testing.T, api string) {
	t.Helper()
	_, pkg, file, bound, source, frame := numericalLocalJoinedFactory(t)
	before, err := x86CallerSourceFingerprint(file)
	if err != nil {
		t.Fatal(err)
	}
	if api == "original-source-shape" {
		frozen, options, err := freezeNumericalReadInputs(file, bound)
		if err != nil {
			t.Fatal("complete original numerical source precondition", err)
		}
		bindings, err := verifyX86FixedLocalBindings(frozen, options)
		if err != nil {
			t.Fatal("complete actual independent fixed-local precondition", err)
		}
		frozen, err = freezeX86FixedLocalFile(frozen, bindings)
		if err != nil {
			t.Fatal(err)
		}
		if err := joinNumericalReadCertificates(frozen, options); err != nil {
			t.Fatal("actual reparse/original-node join precondition", err)
		}
		certificates := 0
		for _, fn := range frozen.Funcs {
			for _, ins := range fn.Instrs {
				if ins.x86NumericalRead != nil {
					certificates++
				}
			}
			instructions, err := x86ResultAUTOReplayInstructions(fn, options.Goarch)
			if err != nil || !reflect.DeepEqual(instructions, file.Funcs[0].Instrs) {
				t.Fatal("actual NUM metadata changed complete original source identity", err)
			}
			if _, err := x86ResultAUTOExtent(fn, options.Goarch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("authenticated NUM metadata granted physical SP logical AUTO storage", err)
			}
		}
		if certificates == 0 {
			t.Fatal("fixture lost its actual numerical source node")
		}
	} else {
		ir := numericalFamilyTranslate(t, api, pkg, file, bound)
		if ir == "" || !strings.Contains(ir, "fixed_local_native") || !strings.Contains(ir, "load volatile") {
			t.Fatal("complete actual joined consumer lost independent local/NUM roles")
		}
	}
	if err := source.Verify(bound.NumericalReads.context); err != nil {
		t.Fatal("original source/storage owner changed", err)
	}
	if err := frame.Verify(bound.NumericalReads.context); err != nil {
		t.Fatal("original frame owner changed", err)
	}
	if after, err := x86CallerSourceFingerprint(file); err != nil || after != before {
		t.Fatal("private joined consumers mutated original whole source")
	}
}

func TestGoX86ResultAUTONumericalReplayExactOriginalNodeGuards(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, file, _, create := numericalConsumerFactory(t, arch)
			source, options := create(t)
			frozen, bound, err := freezeNumericalReadInputs(file, options)
			if err != nil {
				t.Fatal(err)
			}
			fn := frozen.Funcs[0]
			instructions, err := x86ResultAUTOReplayInstructions(fn, arch)
			if err != nil || !reflect.DeepEqual(instructions, file.Funcs[0].Instrs) {
				t.Fatal("complete actual source/mode/ordinal replay precondition", err)
			}
			ordinal := -1
			for index, ins := range fn.Instrs {
				if ins.x86NumericalRead != nil {
					ordinal = index
					break
				}
			}
			if ordinal <= 0 {
				t.Fatal("actual fixture lost original numerical ordinal")
			}
			for name, mutate := range map[string]func(*Func){
				"missing binding":     func(fn *Func) { fn.Instrs[ordinal].x86NumericalRead = &x86NumericalReadCertificate{} },
				"unknown instruction": func(fn *Func) { fn.Instrs[ordinal].Op = "UNKNOWN" },
				"original literal":    func(fn *Func) { fn.Instrs[ordinal].Raw += " " },
				"different ordinal":   func(fn *Func) { fn.Instrs[ordinal-1], fn.Instrs[ordinal] = fn.Instrs[ordinal], fn.Instrs[ordinal-1] },
				"different function":  func(fn *Func) { fn.Sym = "·Other" },
				"coherent different TEXT frame": func(fn *Func) {
					fn.FrameSize = 8
					fn.Instrs[0].Raw = strings.Replace(fn.Instrs[0].Raw, "$0-", "$8-", 1)
				},
				"coherent different tail": func(fn *Func) { fn.Instrs[len(fn.Instrs)-1] = Instr{Op: "NOP", Raw: "NOP"} },
				"decoded instruction":     func(fn *Func) { fn.Instrs[ordinal].x86Encoded = true },
				"SDK literal metadata":    func(fn *Func) { fn.Instrs[ordinal].x86SDKLiteral = &x86SDKLiteralCertificate{} },
				"unrelated private role":  func(fn *Func) { fn.Instrs[0].x86SourceStackFP = map[int]int64{0: 0} },
			} {
				t.Run(name, func(t *testing.T) {
					copy := fn
					copy.Instrs = append([]Instr(nil), fn.Instrs...)
					mutate(&copy)
					if _, err := x86ResultAUTOReplayInstructions(copy, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed original function/instruction/source role was projected away", err)
					}
				})
			}
			if err := source.Verify(bound.NumericalReads.context); err != nil {
				t.Fatal("source mutations in independent copies changed the original owner", err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := x86ResultAUTOReplayInstructions(fn, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("closed original source retained authenticated metadata projection", err)
			}
		})
	}
}
