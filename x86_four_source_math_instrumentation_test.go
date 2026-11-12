package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Private test-only lane mathematics, retained from the earlier implementation.
// No production path calls it: it does not certify original MXCSR, sequential
// exception priority, physical register effects or native memory faults.
type x86FourSourceMathForm struct {
	amd64FourSourceForm
	mask string
}

func x86FourSourceMathIR(t *testing.T, file *File, signatures map[string]FuncSig, triple string, expected int) string {
	t.Helper()
	count := 0
	ir := x86InstructionFormatObjectUnit(t, file, signatures, "amd64", triple, 0,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			form, known, err := x86FourSourceProperties(ins.Op, ins, "amd64")
			if known {
				if err != nil {
					return true, false, err
				}
				count++
				mathematical := x86FourSourceMathForm{amd64FourSourceForm: form}
				if form.maskIndex >= 0 {
					mathematical.mask, err = c.loadK(ins.Args[form.maskIndex].Reg)
					if err != nil {
						return true, false, err
					}
				}
				if form.spec.mode == amd64FourSourceFMA {
					return c.lowerFourSourceFMA(form.spec, mathematical)
				}
				return c.lowerFourSourceDotWords(form.spec, mathematical)
			}
			terminated, err := c.lowerInstr(0, 0, ins, nil, nil)
			return true, terminated, err
		})
	if count != expected {
		t.Fatal("private mathematical instrumentation lost a complete original opcode", count, expected)
	}
	// These are exact per-function x86 feature groups, not host capabilities.
	// Remove each complete checked group and all its references only here;
	// otherwise LLVM could choose a rare/native ISA in this numerical oracle.
	profiles := make(map[string]int)
	for _, function := range file.Funcs {
		features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", function)
		if features == "" {
			t.Fatal("private mathematical fixture lost its original x86 feature identity")
		}
		profiles[features]++
	}
	groups := regexp.MustCompile(`(?m)^attributes (#[0-9]+) = \{ "target-features"="([^"]+)" \}\r?\n`).FindAllStringSubmatch(ir, -1)
	if len(groups) != len(profiles) {
		t.Fatal("private mathematical feature-group inventory changed", len(groups), len(profiles))
	}
	for _, group := range groups {
		uses, found := profiles[group[2]]
		if !found || uses == 0 || strings.Count(ir, group[0]) != 1 {
			t.Fatal("unobserved private mathematical ISA group", group[2])
		}
		ir = strings.Replace(ir, group[0], "", 1)
		if strings.Count(ir, " "+group[1]) != uses {
			t.Fatal("private mathematical ISA group lost exact function ownership", group[1], uses)
		}
		ir = strings.ReplaceAll(ir, " "+group[1], "")
		delete(profiles, group[2])
	}
	if len(profiles) != 0 || strings.Contains(ir, "target-features") || strings.Contains(ir, " asm ") {
		t.Fatal("private mathematical IR still contains unchecked native/rare machine behavior")
	}
	t.Logf("private four-source mathematical instrumentation: checked replacements=%d; exact x86 feature groups removed=%d; no native inline assembly; not original MXCSR, exception or fault execution", count, len(groups))
	return ir
}

func x86FourSourceOriginalMathCompanion(t *testing.T, original, mainC string) {
	t.Helper()
	observed, oracle := x86FourSourceOriginalProgram(t)
	if original != observed || mainC != oracle {
		t.Fatal("mathematical companion did not consume both complete unchanged original literals")
	}
	file, err := x86FourSourceOriginalMathSource(original, mainC)
	if err != nil {
		t.Fatal(err)
	}
	signatures := x86FourSourceOriginalSignatures()
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := x86FourSourceMathIR(t, file, signatures, triple, 8)
	for index, name := range []string{"foursourcesemantics", "foursourcefaultsuppression"} {
		old := fmt.Sprint("@InstructionFormat", index, "(")
		if strings.Count(ir, old) != 1 {
			t.Fatal("private mathematical C identity lost its single actual function definition", name)
		}
		ir = strings.Replace(ir, old, "@"+name+"(", 1)
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("actual-host mathematical companion requires exact LLVM22 llc/clang")
	}
	t.Log("original complete ASM/C literals retained; derived fault source has six explicit zero producers and seven portable byte transports; no original rare-ISA execution claim")
	x86ConflictFunnelPortableRuntime(t, llc, clang, "four-source-original-mathematics", triple, ir, mainC)
}

// Both positive execution and mutation controls call this actual projector.
// A changed source returns no partially instrumented file, not a later-stage
// t.Fatal that could be mistaken for an expected source rejection.
func x86FourSourceOriginalMathSource(original, mainC string) (*File, error) {
	if fmt.Sprintf("%x", sha256.Sum256([]byte(original))) != "c68bfc687ce73e04389fd0e3f57146554f85d3967d9c44c80ac6e1dbefbd5070" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(mainC))) != "44e5e74ea2f0f24009632362a848a5bc0e9f6c8002e04d8e4310a2f4270bc3a4" {
		return nil, fmt.Errorf("private four-source mathematics needs its two complete unchanged original literals")
	}
	// The original fault TEXT lacks initialized source/accumulator inputs. Its
	// separate public Context remains mandatory. This explicit derived fixture
	// supplies real producers, rather than relying on C passing mask=0 or on
	// the emitter's zero-initialized implementation slots.
	anchor := "\tKMOVQ CX, K1\n\tV4FMADDPS.Z (AX)"
	if strings.Count(original, anchor) != 1 {
		return nil, fmt.Errorf("the complete original fault-source instrumentation anchor changed")
	}
	var producers strings.Builder
	for register := 0; register < 6; register++ {
		fmt.Fprintf(&producers, "\tVPXORD Z%d,Z%d,Z%d\n", register, register, register)
	}
	derived := strings.Replace(original, anchor, "\tKMOVQ CX, K1\n"+producers.String()+"\tV4FMADDPS.Z (AX)", 1)
	file, err := Parse(ArchAMD64, derived)
	if err != nil || len(file.Funcs) != 2 {
		return nil, fmt.Errorf("private mathematics lost the complete original two-TEXT program: %v", err)
	}
	// Original legacy MOVUPS would select the original native bridge. Here
	// all seven are explicit portable byte transports. Their upper-alias
	// difference is outside this instrumented program's C observations; native
	// alias behavior has independent complete initialized/state/object controls.
	transports := 0
	for function := range file.Funcs {
		for index := range file.Funcs[function].Instrs {
			ins := &file.Funcs[function].Instrs[index]
			if ins.Op == "MOVUPS" {
				if len(ins.Args) != 2 {
					return nil, fmt.Errorf("unobserved original legacy byte-transport grammar")
				}
				ins.Op = "VMOVUPS"
				ins.Raw = strings.Replace(ins.Raw, "MOVUPS", "VMOVUPS", 1)
				transports++
			}
		}
	}
	if transports != 7 || file.Funcs[0].Sym != "foursourcesemantics" || file.Funcs[1].Sym != "foursourcefaultsuppression" {
		return nil, fmt.Errorf("private mathematics lost its seven byte transports or two original function identities: %d", transports)
	}
	return file, nil
}

func x86FourSourceOriginalSignatures() map[string]FuncSig {
	result := make(map[string]FuncSig)
	for _, name := range []string{"foursourcesemantics", "foursourcefaultsuppression"} {
		result[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}
	}
	return result
}

func (c *amd64Ctx) lowerFourSourceFMA(spec amd64FourSourceSpec, form x86FourSourceMathForm) (bool, bool, error) {
	activeMaskBits := 16
	if spec.scalar {
		activeMaskBits = 1
	}
	memoryBits, err := c.loadFourSourceMemoryI32(form, activeMaskBits)
	if err != nil {
		return true, false, err
	}
	memoryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <4 x float>\n", memoryName, memoryBits)
	memory := "%" + memoryName
	if spec.scalar {
		return c.lowerFourSourceScalarFMA(spec, form, memory)
	}

	accumulator, err := c.loadFloatingVectorOperand(form.destination, 64, 16, 32)
	if err != nil {
		return true, false, err
	}
	original := accumulator
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", form.sourceBase+sourceIndex))}
		source, loadErr := c.loadFloatingVectorOperand(sourceReg, 64, 16, 32)
		if loadErr != nil {
			return true, false, loadErr
		}
		factor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %s, i32 %d\n", factor, memory, sourceIndex)
		factors := c.splatFMA3Scalar(16, 32, "%"+factor)
		if spec.negative {
			negated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg <16 x float> %s\n", negated, source)
			source = "%" + negated
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x float> @llvm.fma.v16f32(<16 x float> %s, <16 x float> %s, <16 x float> %s)\n", result, source, factors, accumulator)
		accumulator = "%" + result
	}
	if form.mask != "" {
		computedBits := c.newTmp()
		originalBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <16 x i32>\n", computedBits, accumulator)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <16 x i32>\n", originalBits, original)
		masked := amd64ApplyI32LaneMask(c, 16, "%"+computedBits, "%"+originalBits, form.mask, form.zeroing)
		back := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i32> %s to <16 x float>\n", back, masked)
		accumulator = "%" + back
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <64 x i8>\n", out, accumulator)
	return true, false, c.storeZ(form.destination.Reg, "%"+out)
}

func (c *amd64Ctx) lowerFourSourceScalarFMA(spec amd64FourSourceSpec, form x86FourSourceMathForm, memory string) (bool, bool, error) {
	accumulator, err := c.loadXLowF32(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	original := accumulator
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Reg(fmt.Sprintf("X%d", form.sourceBase+sourceIndex))
		source, loadErr := c.loadXLowF32(sourceReg)
		if loadErr != nil {
			return true, false, loadErr
		}
		if spec.negative {
			negated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg float %s\n", negated, source)
			source = "%" + negated
		}
		factor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %s, i32 %d\n", factor, memory, sourceIndex)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call float @llvm.fma.f32(float %s, float %%%s, float %s)\n", result, source, factor, accumulator)
		accumulator = "%" + result
	}
	if form.mask != "" {
		bit := amd64MaskBitI1(c, form.mask, 0)
		fallback := original
		if form.zeroing {
			fallback = "0.000000e+00"
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, float %s, float %s\n", selected, bit, accumulator, fallback)
		accumulator = "%" + selected
	}
	destination, err := c.loadX(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	words := c.newTmp()
	bits := c.newTmp()
	inserted := c.newTmp()
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", words, destination)
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, accumulator)
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 0\n", inserted, words, bits)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, inserted)
	return true, false, c.storePackedMoveOperand(form.destination, 16, "%"+out)
}

func (c *amd64Ctx) lowerFourSourceDotWords(spec amd64FourSourceSpec, form x86FourSourceMathForm) (bool, bool, error) {
	memoryDwords, err := c.loadFourSourceMemoryI32(form, 16)
	if err != nil {
		return true, false, err
	}
	memoryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <8 x i16>\n", memoryName, memoryDwords)
	memory := "%" + memoryName
	destinationBytes, err := c.loadZ(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	original := c.bitcastVectorBytesToIntegerLanes(64, 16, 32, destinationBytes)
	accumulator := original
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Reg(fmt.Sprintf("Z%d", form.sourceBase+sourceIndex))
		sourceBytes, loadErr := c.loadZ(sourceReg)
		if loadErr != nil {
			return true, false, loadErr
		}
		source := c.bitcastVectorBytesToIntegerLanes(64, 32, 16, sourceBytes)
		accumulator = c.emitFourSourceDotStep(accumulator, source, memory, sourceIndex, spec.saturating)
	}
	if form.mask != "" {
		accumulator = amd64ApplyI32LaneMask(c, 16, accumulator, original, form.mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i32> %s to <64 x i8>\n", out, accumulator)
	return true, false, c.storeZ(form.destination.Reg, "%"+out)
}

func (c *amd64Ctx) loadFourSourceMemoryI32(form x86FourSourceMathForm, activeMaskBits int) (string, error) {
	if form.mask == "" {
		bytes, err := c.loadPackedCompareBytes(form.memory, 16)
		if err != nil {
			return "", err
		}
		return c.bitcastVectorBytesToIntegerLanes(16, 4, 32, bytes), nil
	}
	masked := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, form.mask, (uint64(1)<<activeMaskBits)-1)
	active := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, masked)
	seed := c.newTmp()
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i1> poison, i1 %%%s, i32 0\n", seed, active)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i1> %%%s, <4 x i1> poison, <4 x i32> zeroinitializer\n", predicate, seed)
	pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(form.memory)
	if err != nil {
		return "", err
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @llvm.masked.load.v4i32%s(%s align 1 %s, <4 x i1> %%%s, <4 x i32> zeroinitializer)\n",
		loaded, intrinsicSuffix, pointerType, pointer, predicate)
	return "%" + loaded, nil
}

func (c *amd64Ctx) emitFourSourceDotStep(accumulator, source, memory string, sourceIndex int, saturating bool) string {
	result := "poison"
	for lane := 0; lane < 16; lane++ {
		accumulatorLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i32> %s, i32 %d\n", accumulatorLane, accumulator, lane)
		total := ""
		if saturating {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", wide, accumulatorLane)
			total = "%" + wide
		} else {
			total = "%" + accumulatorLane
		}
		for word := 0; word < 2; word++ {
			sourceLane := c.newTmp()
			memoryLane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <32 x i16> %s, i32 %d\n", sourceLane, source, lane*2+word)
			fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %s, i32 %d\n", memoryLane, memory, sourceIndex*2+word)
			wideSource := c.newTmp()
			wideMemory := c.newTmp()
			bits := 32
			if saturating {
				bits = 64
			}
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i%d\n", wideSource, sourceLane, bits)
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i%d\n", wideMemory, memoryLane, bits)
			product := c.newTmp()
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i%d %%%s, %%%s\n", product, bits, wideSource, wideMemory)
			fmt.Fprintf(c.b, "  %%%s = add i%d %s, %%%s\n", next, bits, total, product)
			total = "%" + next
		}
		if saturating {
			total = c.saturateFourSourceI64ToI32(total)
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i32> %s, i32 %s, i32 %d\n", inserted, result, total, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) saturateFourSourceI64ToI32(value string) string {
	above := c.newTmp()
	capped := c.newTmp()
	below := c.newTmp()
	bounded := c.newTmp()
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i64 %s, 2147483647\n", above, value)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 2147483647, i64 %s\n", capped, above, value)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, -2147483648\n", below, capped)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -2147483648, i64 %%%s\n", bounded, below, capped)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", narrowed, bounded)
	return "%" + narrowed
}
