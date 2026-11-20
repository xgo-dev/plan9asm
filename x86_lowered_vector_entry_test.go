package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// Ordinary ABI0 codegen selects one consistent value for undeclared vector
// scratch. The strict source query still ranges over arbitrary physical entry
// values. Defined caller projections remain independent of that choice; an
// explicitly observed scratch value is not all-entry native equivalence.
const x86LoweredVectorMaskSource = `TEXT ·MaskTail(SB),4,$0-25
MOVQ src+0(FP),SI
MOVQ n+8(FP),BX
CMPQ BX,$2
JE two
PINSRB $0,(SI),X0
JMP check
two:
PINSRW $0,(SI),X0
check:
MOVQ $16,CX
SUBQ BX,CX
MOVW $65535,DX
SHRW CX,DX
PMOVMSKB X0,AX
TESTW AX,DX
JNZ invalid
MOVB $1,ok+24(FP)
RET
invalid:
BSFW AX,AX
MOVQ AX,at+16(FP)
MOVB $0,ok+24(FP)
RET
`

const x86LoweredVectorRepeatSource = `DATA repeat<>+0(SB)/8,$0x0100010001000100
DATA repeat<>+8(SB)/8,$0x0100010001000100
GLOBL repeat<>(SB),8,$16
TEXT ·RepeatTail(SB),4,$0-24
MOVQ out+0(FP),DI
MOVQ src+8(FP),SI
MOVQ n+16(FP),BX
CMPQ BX,$2
JE two
PINSRB $0,(SI),X0
JMP shuffle
two:
PINSRW $0,(SI),X0
shuffle:
PSHUFB repeat<>(SB),X0
CMPQ BX,$2
JE pair
PEXTRB $0,X0,(DI)
RET
pair:
PEXTRB $3,X0,3(DI)
PEXTRB $2,X0,2(DI)
PEXTRB $1,X0,1(DI)
PEXTRB $0,X0,(DI)
RET
`

const x86LoweredVectorMaskDeclaration = "func MaskTail(src *byte,n uint64) (at uint64,ok bool)\n"
const x86LoweredVectorRepeatDeclaration = "func RepeatTail(out,src *byte,n uint64)\n"

func x86LoweredVectorMaskFixture(t *testing.T) (Func, FuncSig) {
	t.Helper()
	pkg := mustGoPackage(t, "entry", "package entry\n"+x86LoweredVectorMaskDeclaration)
	sig, err := DeriveGoFuncABI0Signature("MaskTail", pkg.Types.Scope().Lookup("MaskTail").(*types.Func),
		"amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, x86LoweredVectorMaskSource)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig
}

func TestX86LoweredVectorEntryKeepsStrictAuditAndThreeAPIs(t *testing.T) {
	fn, sig := x86LoweredVectorMaskFixture(t)
	if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("the standalone query acquired lowering-owned vector initialization", err)
	}
	// Isolate vector initialization from the public query's independent lack
	// of caller-memory contents. Every scalar input here is source-defined.
	_, _, scalar, _ := x86ResultInitializationFixture(t, "amd64", "func Value(value uint32) uint32", "RET")
	_, partial, scalar, scalarSource := x86ResultInitializationFixture(t, "amd64", "func Value(value uint32) uint32",
		fmt.Sprintf("PINSRD $1,value+0(FP),X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\nRET", scalar.Frame.Results[0].Offset))
	if err := CheckX86ABI0ResultInitialization(partial.Funcs[0], scalar, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("a source-only query borrowed the emitter's initial vector contents", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, fixture := range []struct {
		name, source, declaration string
		width                     int
	}{
		{"runtime-mask-X", x86LoweredVectorMaskSource, x86LoweredVectorMaskDeclaration, 16},
		{"runtime-mask-Y", strings.Replace(x86LoweredVectorMaskSource, "PMOVMSKB X0,AX", "VPMOVMSKB Y0,AX", 1), x86LoweredVectorMaskDeclaration, 32},
		{"runtime-mask-Z", strings.Replace(x86LoweredVectorMaskSource, "PMOVMSKB X0,AX", "VPMOVB2M Z0,K1\nKMOVQ K1,AX", 1), x86LoweredVectorMaskDeclaration, 64},
		{"repeated-selector", x86LoweredVectorRepeatSource, x86LoweredVectorRepeatDeclaration, 16},
		{"undeclared-low-lane-refinement", strings.Replace(scalarSource, "·Value", "·Choose", 1), "func Choose(value uint32) uint32\n", 16},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			t.Run(fixture.name+"/"+triple, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", triple, fixture.source)
				x86RequireNumericNativeSourceContext(t, fixture.source, fixture.declaration, "amd64")
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, "amd64", triple, api)
						if err != nil || ir == "" {
							t.Fatal("ordinary ABI0 refinement was blocked by its separate strict audit", err)
						}
						if strings.Count(ir, fmt.Sprintf("store <%d x i8> zeroinitializer", fixture.width)) != 1 {
							t.Fatal("the fixture must retain its actual allocated vector initializer")
						}
						for _, width := range []int{16, 32, 64} {
							if width != fixture.width && strings.Contains(ir, fmt.Sprintf("alloca <%d x i8>", width)) {
								t.Fatal("a numerical entry observation widened the actual allocation", width)
							}
						}
						x86ResultInitializationObject(t, llc, triple, ir, "vector-entry")
					})
				}
			})
		}
	}
}

func TestX86LoweredVectorEntryKeepsAddressBoolAndSourceGuards(t *testing.T) {
	for _, row := range []struct{ name, source string }{
		{"undefined-address", strings.ReplaceAll(x86LoweredVectorMaskSource, "(SI)", "(R8)")},
		{"undefined-index", strings.ReplaceAll(x86LoweredVectorMaskSource, "(SI)", "(SI)(R8*1)")},
		{"undefined-GP-insert", strings.Replace(x86LoweredVectorMaskSource, "PINSRB $0,(SI),X0", "PINSRB $0,R8,X0", 1)},
		{"noncanonical-success", strings.Replace(x86LoweredVectorMaskSource, "MOVB $1,ok+", "MOVB $2,ok+", 1)},
		{"noncanonical-failure", strings.Replace(x86LoweredVectorMaskSource, "MOVB $0,ok+", "MOVB $2,ok+", 1)},
		{"incoming-frame-write", strings.Replace(x86LoweredVectorMaskSource, "check:\n", "check:\nMOVQ $7,src+0(FP)\n", 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, row.source, x86LoweredVectorMaskDeclaration,
					"amd64", "x86_64-unknown-linux-gnu", api)
				if err == nil || ir != "" {
					t.Fatal("numerical vector initialization widened an independent source role", api, err)
				}
			}
		})
	}
	t.Run("unclosed-CPP", func(t *testing.T) {
		// Parse's documented legacy compatibility ignores includes. The
		// source-owning preprocessing API must resolve every active include
		// before any numerical lowering or vector-entry choice is relevant.
		text, err := PreprocessAssemblySource("#include \"unbound-vector-entry.h\"\n"+x86LoweredVectorMaskSource,
			AssemblyPreprocessOptions{FileName: "vector-entry.s"})
		if err == nil || text != "" || !strings.Contains(err.Error(), "requires a resolver") {
			t.Fatal("numerical vector initialization bypassed active source preprocessing", err)
		}
	})
	fn, sig := x86LoweredVectorMaskFixture(t)
	for _, origin := range []string{"raw TEXT", "source stack", "fixed local"} {
		t.Run(origin, func(t *testing.T) {
			changed := fn
			switch origin {
			case "raw TEXT":
				changed.X86RawText = []byte{0xc3}
			case "source stack":
				changed.x86SourceStack = new(x86SourceStackProof)
			case "fixed local":
				changed.x86FixedLocal = new(x86FixedLocalProof)
			}
			consumer := amd64Ctx{fpScalarSource: changed, sig: sig, fpSourceSig: sig, goarch: "amd64"}
			if err := consumer.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("lowering initialization bypassed the independent native source owner", origin, err)
			}
		})
	}
}

func TestX86LoweredVectorEntryKeepsCachedAuditSeparate(t *testing.T) {
	fn, sig := x86LoweredVectorMaskFixture(t)
	budget := new(x86ResultFlowBudget)
	fn.x86ResultFlowBudget = budget
	var output strings.Builder
	consumer := newX86Ctx(&output, fn, sig, func(name string) string { return strings.TrimPrefix(name, "·") },
		nil, "amd64", "x86_64-unknown-linux-gnu", false)
	if err := consumer.validateMixedBoolResultRole(); err != nil {
		t.Fatal("a canonical ordinary bool contract must permit its numerical code generation", err)
	}
	strict, used := consumer.fpScalarCheckErr, *budget
	if !consumer.fpScalarChecked || !errors.Is(strict, ErrProbeNeedsContext) || used.visits == 0 {
		t.Fatal("code generation erased its independent strict audit", strict, used)
	}
	if !consumer.fpMixedBoolBytes || consumer.abi0BoolResultByteStorage() {
		t.Fatal("a lowering-owned initial value created complete result/frame permissions")
	}
	if err := consumer.scalarFPResultInitialized(); err != nil || consumer.fpScalarCheckErr != strict || *budget != used {
		t.Fatal("a repeated consumer reran or promoted the cached audit", err)
	}
	for _, other := range []error{
		fmt.Errorf("independent failure: %w", strict),
		errors.Join(strict, errors.New("source guard failed")),
	} {
		changed := *consumer
		changed.fpScalarCheckErr = other
		if err := changed.scalarFPResultInitialized(); err != other {
			t.Fatal("a wrapped/joined source failure became a codegen-only outcome", err)
		}
	}
}

// A native whole-bank observer cannot observe a different register realization
// from the vector slots used by ordinary numerical lowering. This applies even
// when all vector bytes are defined and no scalar result requires a proof.
func TestX86LoweredVectorEntryRejectsUnboundPhysicalBankObservers(t *testing.T) {
	for _, opcode := range []string{"FXSAVE64", "XSAVE64"} {
		for _, shape := range []string{"partial-result", "defined-void"} {
			declaration := "func Value(out *byte, value uint32)"
			initialization := "PXOR X0,X0\n"
			if shape == "partial-result" {
				declaration += " uint32"
				initialization = ""
			}
			_, _, signature, _ := x86ResultInitializationFixture(t, "amd64", declaration, "RET")
			body := "MOVQ out+0(FP),DI\n" + initialization +
				"PINSRD $1,value+8(FP),X0\nMOVL $3,AX\nXORL DX,DX\n" + opcode + " (DI)\n"
			if shape == "partial-result" {
				body += fmt.Sprintf("PEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\n", signature.Frame.Results[0].Offset)
			}
			var extent int64
			for _, slots := range [][]FrameSlot{signature.Frame.Params, signature.Frame.Results} {
				for _, slot := range slots {
					if end := slot.Offset + x86FrameScalarBytes(slot.Type, "amd64"); end > extent {
						extent = end
					}
				}
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", extent, body)
			for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
				t.Run(opcode+"/"+shape+"/"+triple, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "amd64", triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("unbound physical bank observer must keep source context: %v\n%s", err, ir)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86LoweredVectorEntryRequiresCompleteAllocationPlan(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(value uint32) uint32", "RET")
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(value uint32) uint32",
		fmt.Sprintf("PINSRD $1,value+0(FP),X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\nRET", sig.Frame.Results[0].Offset))
	fn := file.Funcs[0]
	if len(sig.Frame.Params) != 1 || len(sig.Frame.Results) != 1 {
		t.Fatal("allocation-plan control lost its complete typed ABI0 frame")
	}
	var completeOutput strings.Builder
	complete := newX86Ctx(&completeOutput, fn, sig, func(name string) string { return strings.TrimPrefix(name, "·") },
		nil, "amd64", "x86_64-unknown-linux-gnu", false)
	if err := complete.scalarFPResultInitialized(); err != nil || !errors.Is(complete.fpScalarCheckErr, ErrProbeNeedsContext) || completeOutput.Len() != 0 {
		t.Fatal("complete typed allocation plan did not reach lowering-only refinement", err)
	}
	strict := CheckX86ABI0ResultInitialization(fn, sig, "amd64")
	if !errors.Is(strict, ErrProbeNeedsContext) {
		t.Fatal("the original partial vector must retain its strict audit", strict)
	}
	for _, row := range []struct {
		name   string
		remove func(*amd64Ctx)
	}{
		{"GP", func(c *amd64Ctx) { c.usedRegs = nil }},
		{"X", func(c *amd64Ctx) { c.usedXRegs = nil }},
		{"Y", func(c *amd64Ctx) { c.usedYRegs = nil }},
		{"Z", func(c *amd64Ctx) { c.usedZRegs = nil }},
		{"K", func(c *amd64Ctx) { c.usedKRegs = nil }},
		{"blocks", func(c *amd64Ctx) { c.blocks = nil }},
	} {
		t.Run(row.name, func(t *testing.T) {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("an incomplete lowering allocation plan panicked: %v", value)
				}
			}()
			var output strings.Builder
			consumer := newX86Ctx(&output, fn, sig, func(name string) string { return strings.TrimPrefix(name, "·") },
				nil, "amd64", "x86_64-unknown-linux-gnu", false)
			row.remove(consumer)
			err := consumer.checkLoweredVectorEntry(fn, sig, "amd64",
				func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
					return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
				}, strict)
			if err != strict || output.Len() != 0 {
				t.Fatal("an incomplete allocation plan replaced its original strict audit", err)
			}
		})
	}
}
