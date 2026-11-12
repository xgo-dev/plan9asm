package plan9asm

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const arm64ExtractDiscard = uint64(0xd00df00dbaadbeef)

type arm64ExtractOrderCase struct {
	width, shift int
	form         string
}

func arm64ExtractOrderCases() []arm64ExtractOrderCase {
	var cases []arm64ExtractOrderCase
	for _, width := range []int{32, 64} {
		for shift := 0; shift < width; shift++ {
			cases = append(cases, arm64ExtractOrderCase{width, shift, "distinct"})
			if shift != 0 && shift != 1 && shift != width/2 && shift != width-1 && !(width == 64 && shift == 35) {
				continue
			}
			for _, form := range []string{
				"alias-low", "alias-high", "same-source", "zero-low", "zero-high", "discard", "ror-explicit", "ror-inplace",
			} {
				cases = append(cases, arm64ExtractOrderCase{width, shift, form})
			}
		}
	}
	return cases
}

func (tc arm64ExtractOrderCase) operands() (low, high, destination int) {
	low, high, destination = 4, 5, 6
	switch tc.form {
	case "alias-low":
		destination = 4
	case "alias-high":
		destination = 5
	case "same-source", "ror-explicit":
		high = low
	case "ror-inplace":
		high, destination = low, low
	case "zero-low":
		low = 31
	case "zero-high":
		high = 31
	case "discard":
		destination = 31
	}
	return
}

func (tc arm64ExtractOrderCase) instruction() (instruction, result string) {
	register := func(number int) string {
		if number == 31 {
			return "ZR"
		}
		return fmt.Sprintf("R%d", number)
	}
	low, high, destination := tc.operands()
	op := "EXTR"
	if strings.HasPrefix(tc.form, "ror-") {
		op = "ROR"
	}
	if tc.width == 32 {
		op += "W"
	}
	// Plan 9 places the LOW concatenation word second and HIGH word third.
	// Arm's encoding prints the reverse source order: extr Rd, Rn(high), Rm(low).
	instruction = fmt.Sprintf("%s $%d,%s,%s,%s", op, tc.shift, register(low), register(high), register(destination))
	if tc.form == "ror-explicit" {
		instruction = fmt.Sprintf("%s $%d,%s,%s", op, tc.shift, register(low), register(destination))
	} else if tc.form == "ror-inplace" {
		instruction = fmt.Sprintf("%s $%d,%s", op, tc.shift, register(low))
	}
	result = register(destination)
	if destination == 31 {
		result = "R6" // A write to ZR must leave this full-width canary intact.
	}
	return
}

func (tc arm64ExtractOrderCase) oracle(low, high uint64) uint64 {
	if tc.form == "discard" {
		return arm64ExtractDiscard
	}
	switch tc.form {
	case "same-source", "ror-explicit", "ror-inplace":
		high = low
	case "zero-low":
		low = 0
	case "zero-high":
		high = 0
	}
	// A mathematical 2N-bit concatenation, independent of the lowerer's
	// separate lshr/shl/or instructions and its width-limited intermediates.
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(tc.width)), big.NewInt(1))
	lower := new(big.Int).And(new(big.Int).SetUint64(low), mask)
	upper := new(big.Int).And(new(big.Int).SetUint64(high), mask)
	joined := new(big.Int).Add(new(big.Int).Lsh(upper, uint(tc.width)), lower)
	joined.Rsh(joined, uint(tc.shift)).And(joined, mask)
	return joined.Uint64()
}

func arm64ExtractOrderSource(constants bool) (string, map[string]FuncSig) {
	var source strings.Builder
	signatures := map[string]FuncSig{}
	for index, tc := range arm64ExtractOrderCases() {
		name := fmt.Sprintf("Extract%d", index)
		instruction, result := tc.instruction()
		if constants {
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVD $0x0123456789abcdef,R4\nMOVD $0xfedcba9876543210,R5\n", name)
			signatures[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			}}
		} else {
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVD low+0(FP),R4\nMOVD high+8(FP),R5\n", name)
			signatures[name] = FuncSig{Name: name, Args: []LLVMType{I64, I64}, Ret: I64, Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			}}
		}
		resultOffset := 16
		if constants {
			resultOffset = 0
		}
		fmt.Fprintf(&source, "MOVD $0x%x,R6\n%s\nMOVD %s,ret+%d(FP)\nRET\n", arm64ExtractDiscard, instruction, result, resultOffset)
	}
	return source.String(), signatures
}

func TestARM64EXTRPlan9SourceOrderGoEncoding(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT encoding(SB),4,$0-0\nEXTR $35,R22,R12,R8\n")
	// The official cmd/asm arm64enc.s example's little-endian 888dd693.
	want := []uint32{0x93d68d88}
	for _, tc := range arm64ExtractOrderCases() {
		instruction, _ := tc.instruction()
		source.WriteString(instruction + "\n")
		low, high, destination := tc.operands()
		base := uint32(0x13800000)
		if tc.width == 64 {
			base = 0x93c00000
		}
		want = append(want, base|uint32(low)<<16|uint32(tc.shift)<<10|uint32(high)<<5|uint32(destination))
	}
	source.WriteString("RET\n")
	want = append(want, 0xd65f03c0)
	for _, goos := range []string{"linux", "darwin"} {
		actual := arm64ImmediateOriginalGoBytes(t, source.String(), goos)
		if len(actual) < len(want)*4 {
			t.Fatalf("%s truncated original Go EXTR object: %d bytes", goos, len(actual))
		}
		for index, word := range want {
			if got := binary.LittleEndian.Uint32(actual[index*4:]); got != word {
				t.Fatalf("%s original Go EXTR word %d = %08x, want %08x", goos, index, got, word)
			}
		}
	}
}

func TestARM64EXTRPlan9SourceOrderValues(t *testing.T) {
	source, signatures := arm64ExtractOrderSource(true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, Options{
		Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: signatures,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	options.SetVerifyEach(true)
	if err := module.RunPasses("function(sroa,mem2reg,instcombine,simplifycfg)", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	for index, tc := range arm64ExtractOrderCases() {
		t.Run(fmt.Sprintf("width%d/shift%d/%s", tc.width, tc.shift, tc.form), func(t *testing.T) {
			fn := module.NamedFunction(fmt.Sprintf("Extract%d", index))
			if fn.IsNil() {
				t.Fatal("missing complete numerical fixture")
			}
			returns := 0
			want := tc.oracle(0x0123456789abcdef, 0xfedcba9876543210)
			for block := fn.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
				for inst := block.FirstInstruction(); !inst.IsNil(); inst = llvm.NextInstruction(inst) {
					if inst.InstructionOpcode() != llvm.Ret {
						continue
					}
					returns++
					if inst.OperandsCount() != 1 || inst.Operand(0).Type() != ctx.Int64Type() ||
						inst.Operand(0).IsAConstantInt().IsNil() || inst.Operand(0).ZExtValue() != want {
						t.Fatalf("%s: numerical return = %s, want %016x", fn.Name(), inst.String(), want)
					}
				}
			}
			if returns != 1 {
				t.Fatalf("expected one numerical return, got %d", returns)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64EXTRPlan9SourceOrder(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, signatures := arm64ExtractOrderSource(false)
	var goDecls, goRows, cDecls, cRows strings.Builder
	forms := map[string]int{"distinct": 0, "alias-low": 0, "alias-high": 0,
		"same-source": 1, "ror-explicit": 1, "ror-inplace": 1, "zero-low": 2, "zero-high": 3, "discard": 4}
	for index, tc := range arm64ExtractOrderCases() {
		name := fmt.Sprintf("Extract%d", index)
		fmt.Fprintf(&goDecls, "func %s(uint64,uint64) uint64\n", name)
		fmt.Fprintf(&goRows, "{%s,%d,%d,%d},\n", name, tc.width, tc.shift, forms[tc.form])
		fmt.Fprintf(&cDecls, "extern uint64_t %s(uint64_t,uint64_t);\n", name)
		fmt.Fprintf(&cRows, "{%s,%d,%d,%d},\n", name, tc.width, tc.shift, forms[tc.form])
	}
	// The unchanged source executes first under the actual Go assembler and
	// compiler. These bit-selection oracles do not repeat LLVM's shift/or IR.
	goMain := "package main\n" + goDecls.String() + arm64ExtractGoOracle +
		"var probes = []probe{\n" + goRows.String() + "}\n"
	runARM64GoInternalOracle(t, source, goMain, len(runner) != 0)
	cMain := arm64ExtractCOracle + cDecls.String() + "static struct probe probes[] = {\n" + cRows.String() + "};\n" + arm64ExtractCMain
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	pkg := mustGoPackage(t, "test/extrorder", "package extrorder\n"+goDecls.String())
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: signatures, ResolveSym: resolve}
			var ir string
			switch api {
			case "text":
				ir, err = Translate(file, options)
			case "module":
				var module llvm.Module
				module, err = TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
					ir = module.String()
				}
			case "GoModule":
				var translated *GoModuleTranslation
				translated, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
				})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
					ir = translated.Module.String()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, optimization := range []int{0, 2} {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "extract_order", triple, ir, cMain, runner, optimization)
			}
		})
	}
	t.Logf("%d complete EXTR/EXTRW/ROR rows x 64 original input pairs; actual Go and three APIs, LLVM O0/O2", len(arm64ExtractOrderCases()))
}

const arm64ExtractGoOracle = `
type probe struct { call func(uint64,uint64) uint64; width,shift,mode uint }
func expected(p probe, low,high uint64) uint64 {
  switch p.mode { case 1: high=low; case 2: low=0; case 3: high=0; case 4: return 0xd00df00dbaadbeef }
  var result uint64
  for bit:=uint(0); bit<p.width; bit++ {
    position:=p.shift+bit
    value:=low
    if position>=p.width { value=high; position-=p.width }
    if (value>>position)&1!=0 { result |= uint64(1)<<bit }
  }
  return result
}
func main() {
  values:=[]uint64{0,1,^uint64(0),0x0123456789abcdef,0xfedcba9876543210,1<<63,0xffffffff,0xffffffff00000000}
  for _,p:=range probes { for _,a:=range values { for _,b:=range values {
    if p.call(a,b)!=expected(p,a,b) { panic("original Go EXTR source-order/value mismatch") }
  } } }
}
`

const arm64ExtractCOracle = `#include <stdint.h>
#include <stdio.h>
struct probe { uint64_t (*call)(uint64_t,uint64_t); unsigned width,shift,mode; };
static uint64_t expected(struct probe p,uint64_t low,uint64_t high) {
  switch(p.mode) { case 1: high=low; break; case 2: low=0; break; case 3: high=0; break; case 4: return UINT64_C(0xd00df00dbaadbeef); }
  uint64_t result=0;
  for(unsigned bit=0;bit<p.width;bit++) {
    unsigned position=p.shift+bit;
    uint64_t value=low;
    if(position>=p.width) { value=high; position-=p.width; }
    if((value>>position)&1) result |= UINT64_C(1)<<bit;
  }
  return result;
}
`

const arm64ExtractCMain = `int main(void) {
  const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(1)<<63,UINT64_C(0xffffffff),UINT64_C(0xffffffff00000000)};
  for(unsigned i=0;i<sizeof(probes)/sizeof(probes[0]);i++) {
    for(unsigned a=0;a<8;a++) for(unsigned b=0;b<8;b++) {
      uint64_t want=expected(probes[i],values[a],values[b]);
      uint64_t got=probes[i].call(values[a],values[b]);
      if(got!=want) {
        fprintf(stderr,"EXTR row=%u width=%u shift=%u mode=%u a=%llx b=%llx got=%llx want=%llx\n",i,probes[i].width,probes[i].shift,probes[i].mode,(unsigned long long)values[a],(unsigned long long)values[b],(unsigned long long)got,(unsigned long long)want);
        return 1;
      }
    }
  }
  return 0;
}
`
