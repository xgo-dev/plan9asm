package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalResultFeatureAttrs(file *File, binding *x86FixedLocalBinding, name, arch string) (string, string, bool) {
	functions, valid := fixedLocalResultFunctions(file, binding, arch)
	function, found := functions[name]
	return function.attributes, function.inferred, valid && found
}

func TestX86FixedLocalFeatureProjectionUsesCompleteSourceOrder(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·First(SB),4,$0\nAESENC X0,X1\nRET\nTEXT ·Second(SB),4,$0\nPSHUFB X0,X1\nRET")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		binding := &x86FixedLocalBinding{symbols: map[string]string{"·First": "First", "·Second": "Second"},
			signatures: map[string]FuncSig{"First": {Name: "First"}, "Second": {Name: "Second"}}}
		for index, name := range []string{"First", "Second"} {
			attrs, inferred, valid := fixedLocalResultFeatureAttrs(file, binding, name, arch)
			if !valid || attrs != fmt.Sprintf("#%d", featureAttrBase+index) || inferred != attrs {
				t.Fatal("complete renderer reference/order differs", arch, name, attrs, inferred, valid)
			}
		}
		binding.signatures["First"] = FuncSig{Name: "First", Attrs: "nounwind"}
		attrs, inferred, valid := fixedLocalResultFeatureAttrs(file, binding, "First", arch)
		if !valid || attrs != "nounwind" || inferred != "" {
			t.Fatal("supplied attributes became removable inferred metadata")
		}
		attrs, inferred, valid = fixedLocalResultFeatureAttrs(file, binding, "Second", arch)
		if !valid || attrs != fmt.Sprintf("#%d", featureAttrBase) || inferred != attrs {
			t.Fatal("supplied attributes incorrectly consumed a renderer reference")
		}
		delete(binding.symbols, "·First")
		if _, _, valid := fixedLocalResultFeatureAttrs(file, binding, "Second", arch); valid {
			t.Fatal("incomplete unrelated source inventory accepted")
		}
	}
}

func TestGoAMD64FixedLocalResultConsumerExactProofHandoff(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64", bound)
	if err != nil {
		t.Fatal(err)
	}
	fn, sig := normalized.Funcs[0], bound.Sigs[pkg.Path+".Value"]
	attributes, inferred, valid := fixedLocalResultFeatureAttrs(file, sig.x86FixedLocal, sig.Name, "amd64")
	if !valid {
		t.Fatal("actual complete renderer inventory precondition")
	}
	snapshot, err := newX86FixedLocalResultSnapshot(sig.x86FixedLocal, "amd64")
	if err != nil || snapshot == nil || len(snapshot.functions) != 1 {
		t.Fatal("independent call-local original source index", err)
	}
	create := func(fn Func) *amd64Ctx {
		var output strings.Builder
		lower := newX86Ctx(&output, fn, sig, bound.ResolveSym, bound.Sigs, "amd64", bound.TargetTriple, false)
		lower.fpFeatureAttrs, lower.sig.Attrs = inferred, attributes
		return lower
	}
	if err := create(fn).checkLoweredScalarFPResultInitialization(); err != nil {
		t.Fatal("exact existing fixed-local result proof was stolen by logical AUTO replay", err)
	}
	scoped := create(fn)
	scoped.fixedLocalResult = snapshot
	if err := scoped.checkLoweredScalarFPResultInitialization(); err != nil {
		t.Fatal("call-local original source index changed result proof", err)
	}
	if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("private source query gained physical-frame permission", err)
	}
	for name, mutate := range map[string]func(*amd64Ctx){
		"wrong target":           func(c *amd64Ctx) { c.targetTriple = "x86_64-pc-windows-msvc" },
		"wrong mode":             func(c *amd64Ctx) { c.goarch = "386" },
		"missing proof":          func(c *amd64Ctx) { c.fixedLocal = nil },
		"changed declaration":    func(c *amd64Ctx) { c.fpSourceSig.Ret = I32 },
		"changed emitted type":   func(c *amd64Ctx) { c.sig.Ret = I32 },
		"changed emitted attrs":  func(c *amd64Ctx) { c.sig.Attrs = "readnone" },
		"changed inferred attrs": func(c *amd64Ctx) { c.fpFeatureAttrs = "#999" },
		"changed supplied attrs": func(c *amd64Ctx) { c.fpSourceSig.Attrs = "nounwind" },
		"changed frame":          func(c *amd64Ctx) { c.fpScalarSource.FrameSize += 8 },
		"changed emitter frame":  func(c *amd64Ctx) { c.frameSize += 8 },
		"changed raw role":       func(c *amd64Ctx) { c.fpScalarSource.Instrs[1].x86Encoded = true },
		"unknown literal role":   func(c *amd64Ctx) { c.fpScalarSource.Instrs[1].x86SDKLiteral = &x86SDKLiteralCertificate{} },
		"foreign snapshot binding": func(c *amd64Ctx) {
			copy, foreign := *snapshot, *snapshot.binding
			copy.binding = &foreign
			c.fixedLocalResult = &copy
		},
		"foreign snapshot file": func(c *amd64Ctx) {
			copy := *snapshot
			copy.file[0] ^= 1
			c.fixedLocalResult = &copy
		},
		"changed complete source": func(c *amd64Ctx) {
			last := len(c.fpScalarSource.Instrs) - 1
			c.fpScalarSource.Instrs[last] = Instr{Op: "NOP", Raw: "NOP"}
		},
		"missing access": func(c *amd64Ctx) {
			for index := range c.fpScalarSource.Instrs {
				if len(c.fpScalarSource.Instrs[index].x86FixedLocalMemory) != 0 {
					c.fpScalarSource.Instrs[index].x86FixedLocalMemory = nil
					return
				}
			}
			t.Fatal("actual access missing")
		},
		"changed access ordinal": func(c *amd64Ctx) {
			for index := range c.fpScalarSource.Instrs {
				ins := &c.fpScalarSource.Instrs[index]
				if len(ins.x86FixedLocalMemory) != 0 {
					ins.x86FixedLocalMemory = cloneX86ReplayFixedLocalMemory(ins.x86FixedLocalMemory)
					for operand, access := range ins.x86FixedLocalMemory {
						access.ordinal++
						ins.x86FixedLocalMemory[operand] = access
						return
					}
				}
			}
			t.Fatal("actual access missing")
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, scoped := range []bool{false, true} {
				copy := fn
				copy.Instrs = append([]Instr(nil), fn.Instrs...)
				lower := create(copy)
				if scoped {
					lower.fixedLocalResult = snapshot
				}
				mutate(lower)
				if err := lower.checkFixedLocalResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed native/source/private role borrowed original result proof", scoped, err)
				}
			}
		})
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("negative consumers changed actual source owner", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := create(fn).checkFixedLocalResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("closed actual frame owner retained result proof", err)
	}
}
