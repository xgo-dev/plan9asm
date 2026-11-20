package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

var x86CMOVAUTOSources = []string{"tmp(SP)", "UNKNOWN(SP)", "tmp+0(SP)", "tmp+(0*4)(SP)", "tmp-8(SP)", "tmp-(2*4)(SP)"}

func TestX86CMOVFamilyAUTOActualGoPhysicalRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"W", "L", "Q"} {
			if arch == "386" && width == "Q" {
				continue
			}
			for _, source := range x86CMOVAUTOSources {
				t.Run(arch+"/"+width+"/"+source, func(t *testing.T) {
					code := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$16-0\nCMOV"+width+"LE "+source+",AX\nRET\n")
					mode := 64
					if arch == "386" {
						mode = 32
					}
					found := 0
					for len(code) > 0 {
						ins, err := x86asm.Decode(code, mode)
						if err != nil || ins.Len == 0 {
							t.Fatal("independent actual Go object decode", err)
						}
						if ins.Op == x86asm.CMOVLE {
							memory, ok := ins.Args[1].(x86asm.Mem)
							want := int64(16)
							if strings.Contains(source, "-") {
								want = 8
							}
							if !ok || memory.Disp != want || memory.Index != 0 || ins.MemBytes != map[string]int{"W": 2, "L": 4, "Q": 8}[width] {
								t.Fatal("NAME_AUTO is frame+offset, not virtual/native zero", source, ins)
							}
							found++
						}
						code = code[ins.Len:]
					}
					if found != 1 {
						t.Fatal("actual Go did not emit one CMOV", found)
					}
				})
			}
		}
	}
}

func TestX86CMOVFamilyAUTOGrammarThreeAPIFiveTargets(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, source := range x86CMOVAUTOSources {
			var assembly strings.Builder
			for _, name := range x86CMOVOracleNames(target.arch) {
				fmt.Fprintf(&assembly, "%s %s,AX\n", name, source)
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$16-0\n"+name+" "+source+",AX\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				t.Run(target.triple+"/"+name+"/"+source, func(t *testing.T) {
					if _, known, err := x86ConditionalMoveProperties(ins.Op, ins, target.arch); !known || err != nil {
						t.Fatal("accepted NAME_AUTO descriptive offset is not an undefined macro", err)
					}
				})
			}
			original := "TEXT ·Value(SB),4,$16-0\n" + assembly.String() + "RET\n"
			goAssemblerOracleOutput(t, target.arch, original, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+source+"/"+api, func(t *testing.T) {
					_, err := x86OrderingHintTranslateAPI(t, api, original, "package ordering\nfunc Value()\n", target.arch, target.triple)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("legal grammar is not original native storage authority", err)
					}
				})
			}
		}
	}
}

func x86CMOVFixedLocalAssembly(name, op, source string) string {
	shift, restore := "", ""
	if source != "AX" && source != "8(SP)" && source != "tmp-8(SP)" && source != "tmp-(2*4)(SP)" {
		shift, restore = "MOVQ SP,R11\nADDQ $-16,SP\n", "MOVQ R11,SP\n"
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$16-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ AX,0(SP)\nMOVQ AX,8(SP)\n%sCMPQ AX,BX\n%s %s,BX\n%sMOVQ BX,ret+16(FP)\nRET\n", name, shift, op, source, restore)
}

func TestX86CMOVFamilyFixedLocalSourceRoleQueryNotPermission(t *testing.T) {
	for _, op := range x86CMOVOracleNames("amd64") {
		for _, source := range []string{"tmp(SP)", "UNKNOWN(SP)", "tmp-8(SP)", "tmp-(2*4)(SP)", "8(SP)", "(BP)", "AX", "a+0(FP)", "slot+UNKNOWN(SP)"} {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$16-24\n"+op+" "+source+",BX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			want := source != "AX" && source != "a+0(FP)" && source != "slot+UNKNOWN(SP)"
			if got := GoAMD64FixedLocalFrameBindingNeeded(file, "amd64"); got != want {
				t.Errorf("typed source binding query %s %s got=%t want=%t", op, source, got, want)
			}
		}
	}
}

func x86CMOVFixedLocalFixture(t *testing.T, assembly, declarations, target, triple string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	pkg, request := goAMD64FrameTypedFixture(t, declarations, assembly)
	request.Target = target
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{}
	for _, name := range pkg.Types.Scope().Names() {
		sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sigs[sig.Name] = sig
	}
	return pkg, request, file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) }}
}

type x86CMOVFixedLocalKernel struct {
	name, assembly         string
	width, condition, mode int
}

func x86CMOVFixedLocalKernels(includeMoves bool) []x86CMOVFixedLocalKernel {
	var kernels []x86CMOVFixedLocalKernel
	for _, width := range []string{"W", "L", "Q"} {
		for condition, row := range x86CMOVOracleConditions {
			for _, source := range append([]string{"AX", "8(SP)"}, x86CMOVAUTOSources...) {
				name := fmt.Sprintf("F%d", len(kernels))
				kernels = append(kernels, x86CMOVFixedLocalKernel{
					name:      name,
					assembly:  x86CMOVFixedLocalAssembly(name, "CMOV"+width+row.name, source),
					width:     map[string]int{"W": 2, "L": 4, "Q": 8}[width],
					condition: condition,
				})
			}
		}
	}
	if includeMoves {
		for mode, operation := range []string{
			"MOVQ tmp-8(SP),BX",
			"MOVQ AX,tmp-8(SP)\nMOVQ tmp-8(SP),BX",
			"MOVOU tmp-16(SP),X0\nMOVQ X0,BX",
		} {
			name := fmt.Sprintf("F%d", len(kernels))
			kernels = append(kernels, x86CMOVFixedLocalKernel{
				name: name, width: 8, mode: mode + 1,
				assembly: fmt.Sprintf("TEXT ·%s(SB),4,$16-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ AX,0(SP)\nMOVQ BX,8(SP)\n%s\nMOVQ BX,ret+16(FP)\nRET\n", name, operation),
			})
		}
	}
	return kernels
}

func TestX86CMOVFixedLocalCompleteBatchPlan(t *testing.T) {
	for _, includeMoves := range []bool{false, true} {
		kernels := x86CMOVFixedLocalKernels(includeMoves)
		count, batches := 384, 6
		if includeMoves {
			count, batches = 387, 7
		}
		if len(kernels) != count {
			t.Fatal("complete original CMOV/GP/SIMD kernel inventory changed", includeMoves, len(kernels))
		}
		seen := make([]int, count)
		for batch := 0; batch < batches; batch++ {
			start, end, ok := fixedLocalObjectBatchRange(count, batch)
			if !ok || end-start > 64 || end <= start {
				t.Fatal("invalid bounded CMOV batch", batch, start, end, ok)
			}
			for index := start; index < end; index++ {
				seen[index]++
				kernel := kernels[index]
				if kernel.name != fmt.Sprintf("F%d", index) ||
					!strings.HasPrefix(kernel.assembly, "TEXT ·"+kernel.name+"(SB),4,$16-24\n") {
					t.Fatal("batch changed original source symbol or ABI0 frame", index, kernel)
				}
				if index < 384 {
					width := []int{2, 4, 8}[index/128]
					if kernel.width != width || kernel.condition != index/8%16 || kernel.mode != 0 {
						t.Fatal("batch changed independent width/condition/source ordering", index, kernel)
					}
				} else if kernel.width != 8 || kernel.condition != 0 || kernel.mode != index-383 {
					t.Fatal("batch lost original private GP/SIMD AUTO kernel", index, kernel)
				}
			}
		}
		for index, owners := range seen {
			if owners != 1 {
				t.Fatal("missing or duplicated original kernel", index, owners)
			}
		}
		for _, batch := range []int{-1, batches} {
			if _, _, ok := fixedLocalObjectBatchRange(count, batch); ok {
				t.Fatal("out-of-range CMOV batch accepted", count, batch)
			}
		}
	}
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch00(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 0)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch01(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 1)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch02(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 2)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch03(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 3)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch04(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 4)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsLinuxBatch05(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 5)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch00(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 0)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch01(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 1)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch02(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 2)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch03(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 3)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch04(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 4)
}

func TestX86CMOVFamilyFixedLocalAUTOActualObjectsDarwinBatch05(t *testing.T) {
	x86CMOVFixedLocalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 5)
}

func x86CMOVFixedLocalActualObjects(t *testing.T, target, triple string, batch int) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	kernels := x86CMOVFixedLocalKernels(false)
	units, ok := x86CMOVFixedLocalObjectSources(kernels, batch)
	if !ok {
		t.Fatal("invalid complete CMOV object batch", batch, len(kernels))
	}
	count := 0
	for index, unit := range units {
		count += unit.end - unit.start
		t.Run(fmt.Sprintf("source%d", index), func(t *testing.T) {
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, unit.assembly, unit.declarations, target, triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "fixed_local_native") {
					t.Fatal("exact sealed original local storage", err)
				}
				for _, optimize := range []bool{false, true} {
					input := ir
					if optimize {
						input = x86DwordProductIROptimize(t, ir)
					}
					x86CompactExpandRequireAllDefinitions(t, input, unit.names)
					compileLLVMToObject(t, llc, triple, "cmov-fixed-local.ll", "cmov-fixed-local.o", input)
				}
			})
		})
	}
	t.Logf("%s batch%d: %d/%d original condition/width/register/physical/AUTO kernels; %d independent sources, three APIs, original/optimized IR, llc-O0",
		target, batch, count, len(kernels), len(units))
}

func TestX86CMOVFamilyFixedLocalEveryReadAndAuthorityNegatives(t *testing.T) {
	for _, op := range x86CMOVOracleNames("amd64") {
		base := x86CMOVFixedLocalAssembly("Value", op, "tmp(SP)")
		pkg := mustGoPackage(t, "cmovlocal", "package cmovlocal\nfunc Value(a,b uint64) uint64\n")
		sig := x86WordMultiplySignature(t, pkg, "Value")
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[4]]
		mutations := map[string]string{
			"unknown flags":          strings.Replace(base, "CMPQ AX,BX", "MOVQ AX,DX", 1),
			"old target pointer":     strings.Replace(base, "CMPQ AX,BX", "CMPQ AX,BX\nMOVQ SP,BX", 1),
			"g target":               strings.Replace(base, "tmp(SP),BX", "tmp(SP),R14", 1),
			"BP target":              strings.Replace(base, "tmp(SP),BX", "tmp(SP),BP", 1),
			"AUTO saved BP":          strings.Replace(base, "ADDQ $-16,SP", "ADDQ $0,SP", 1),
			"AUTO return":            strings.Replace(base, "tmp(SP)", "tmp+24(SP)", 1),
			"undefined expression":   strings.Replace(base, "tmp(SP)", "slot+UNKNOWN(SP)", 1),
			"AUTO address input":     strings.Replace(base, op+" tmp(SP),BX", "MOVQ $tmp(SP),AX\n"+op+" AX,BX", 1),
			"FP pointer permission":  strings.Replace(base, "tmp(SP)", "p+0(FP)", 1),
			"source private pointer": strings.Replace(base, "MOVQ AX,0(SP)", "MOVQ SP,0(SP)", 1),
		}
		for missing := 0; missing < width; missing++ {
			var stores, old strings.Builder
			for byteIndex := 0; byteIndex < width; byteIndex++ {
				if byteIndex != missing {
					fmt.Fprintf(&stores, "MOVB $1,%d(SP)\n", byteIndex)
				}
			}
			// Old destination reads are potential even when every flag seed
			// makes the predicate true. Byte-state is checked independently.
			old.WriteString("MOVQ b+8(FP),DX\n")
			mutations[fmt.Sprintf("source byte %d", missing)] = strings.Replace(base, "MOVQ AX,0(SP)\n", stores.String(), 1)
			changed, err := Parse(ArchAMD64, strings.Replace(base, "MOVQ b+8(FP),BX\n", old.String(), 1))
			if err != nil {
				t.Fatal(err)
			}
			t.Run(op+fmt.Sprintf("/old byte %d", missing), func(t *testing.T) {
				state := x86FixedLocalState{
					pointers: map[Reg]int64{SP: -16},
					known:    map[Reg]uint8{AX: 255, BX: 255 &^ (1 << uint(missing))},
					bytes:    newFixedLocalByteSet(16), flags: x86ByteFlagsAll,
				}
				for index := int64(0); index < 16; index++ {
					state.bytes.set(index, true)
				}
				for _, ins := range changed.Funcs[0].Instrs {
					if ins.Op == Op(op) {
						if err := fixedLocalStep(&ins, &state, sig, &x86FixedLocalProof{frame: 16}, 0); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("missing old byte became a defined potential input", err)
						}
					}
				}
			})
		}
		for name, source := range mutations {
			t.Run(op+"/"+name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("fixed local memory/flags/pointer/frame authority grew", err)
				}
			})
		}
	}
}

func TestX86CMOVFamilyFixedLocalSharedAUTOExistingFalseCertificate(t *testing.T) {
	// This is never executed: Go's named AUTO displacement is 160+16,
	// while the old private proof mistakenly certified virtual offset 16.
	pkg, _, file, options := fixedLocalFrameFixture(t, "PADDQ tmp+16(SP),X0")
	goAssemblerOracleOutput(t, "amd64", fixedLocalVoidAssembly(file), "", true)
	if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("named AUTO native out-of-frame bytes acquired an offset-zero virtual certificate", err)
	}
}

func TestX86CMOVFamilyFixedLocalSharedAUTOGPAndSIMD(t *testing.T) {
	for _, operation := range []string{"MOVQ tmp-8(SP),BX", "MOVQ AX,tmp-8(SP)\nMOVQ tmp-8(SP),BX", "MOVOU tmp-16(SP),X0\nMOVQ X0,BX"} {
		t.Run(operation, func(t *testing.T) {
			assembly := "TEXT ·Value(SB),4,$16-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ AX,0(SP)\nMOVQ BX,8(SP)\n" + operation + "\nMOVQ BX,ret+16(FP)\nRET\n"
			pkg, request, file, options := x86CMOVFixedLocalFixture(t, assembly, "func Value(a,b uint64) uint64", "linux/amd64", "x86_64-unknown-linux-gnu")
			observer := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := observer.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("the shared original AUTO role needs its actual native displacement", err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "fixed_local_native") {
					t.Fatal("shared scalar/SIMD native offset consumer", err)
				}
			})
		})
	}
}
