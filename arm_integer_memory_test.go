package plan9asm

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestARMRawIntegerMemoryCompleteForms(t *testing.T) {
	const prologue = "TEXT scaled(SB),NOSPLIT,$0-0\nMOVW $256,R5\nMOVW $8,R2\nMOVW $128,R7\nCMP R2,R7\n"
	for _, tc := range []struct {
		word uint32
		want []string
	}{
		{0xe7957082, []string{"shl i32", "load i32"}},              // LDR, LSL #1.
		{0xe75570a2, []string{"lshr i32", "sub i32", "load i8"}},   // LDRB, subtract LSR #1.
		{0xe7555022, []string{"sub i32", ", 0", "load i8"}},        // LDRB, subtract LSR #32.
		{0xe7b57042, []string{"ashr i32", ", 31", "load i32"}},     // LDR, ASR #32 and writeback.
		{0xe6857062, []string{"shl i32", ", 31", "lshr i32"}},      // STR, post-indexed RRX.
		{0x115570d3, []string{"cond_5feffect", "sext i8"}},         // LDRSB.NE with negative immediate.
		{0x55555555, []string{"cond_5feffect", "1365", "zext i8"}}, // LDRB.PL with negative immediate, Go arm.s.
		{0xe0d570b8, []string{"load i16", "zext i16"}},             // LDRH, post-indexed immediate.
		{0xe13570f2, []string{"sub i32", "sext i16"}},              // LDRSH, subtract register with writeback.
		{0xe00570b2, []string{"sub i32", "store i16"}},             // STRH, post-indexed subtract register.
	} {
		t.Run(fmt.Sprintf("%08x", tc.word), func(t *testing.T) {
			src := fmt.Sprintf("%sWORD $%#08x\nRET\n", prologue, tc.word)
			ir := translateARMForTest(t, src, map[string]FuncSig{
				"example.scaled": {Name: "example.scaled", Ret: Void},
			})
			for _, want := range tc.want {
				if !strings.Contains(ir, want) {
					t.Errorf("raw memory instruction lacks %q:\n%s", want, ir)
				}
			}
		})
	}
}

func TestARMRawIntegerMemoryRequiresOriginalState(t *testing.T) {
	for _, tc := range []struct {
		word uint32
		want string
	}{
		{0xe7d57062, "carry"},              // RRX index needs a reaching C write.
		{0xe6f57002, "unprivileged"},       // LDRBT needs an access-mode contract.
		{0xe59f7000, "instruction layout"}, // An immediate PC-relative literal load.
		{0xe49df004, "control-flow"},       // LDR PC with SP writeback is a physical return.
		{0xe4b55001, "unprivileged"},       // Unprivileged transfer stays distinguishable.
		{0xe4955001, "writeback"},          // LDR with base also the destination.
	} {
		t.Run(fmt.Sprintf("%08x", tc.word), func(t *testing.T) {
			src := fmt.Sprintf("TEXT scaled(SB),NOSPLIT,$0-0\nWORD $%#08x\nRET\n", tc.word)
			file, err := Parse(ArchARM, src)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"scaled": {Name: "scaled", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("raw memory instruction error = %v, want %q", err, tc.want)
			}
			if tc.want != "writeback" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("raw memory instruction error lost source context identity: %v", err)
			}
		})
	}
}

func TestARMIntegerMemoryShiftEffects(t *testing.T) {
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, load := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/load=%v", op, load), func(t *testing.T) {
				instruction := op + " R2, g<<0(R1)"
				if load {
					instruction = op + " g<<0(R1), R2"
				}
				source := "TEXT memshift(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireARMGoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{Goarch: "arm", Sigs: map[string]FuncSig{"memshift": {Name: "memshift", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, "load i32, ptr %reg_R10") {
					t.Fatal("shifted address discarded its g/R10 index")
				}
			})
		}
	}
}

func TestARMIntegerMemoryWritebackAndConditionalEffects(t *testing.T) {
	for _, instruction := range []string{"MOVW.W 8(R1), R2", "MOVW.W R2, 8(R1)", "MOVBU.W 8(R1), R2", "MOVH.W 8(R1), R2"} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT memwriteback(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARMGoAssemblerResult(t, source, true)
			ir := translateARMForTest(t, source, map[string]FuncSig{"example.memwriteback": {Name: "example.memwriteback", Ret: Void}})
			writes := 0
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, "store i32") && strings.Contains(line, ", ptr %reg_R1,") {
					writes++
				}
			}
			if writes < 2 { // entry initialization plus actual address writeback
				t.Fatalf("pre-indexed memory operation discarded .W writeback:\n%s", ir)
			}
		})
	}
	const source = "TEXT condmem(SB),$0-0\n\tCMP R0, R0\n\tMOVW.NE.P 8(R1), R2\n\tRET\n"
	requireARMGoAssemblerResult(t, source, true)
	ir := translateARMForTest(t, source, map[string]FuncSig{"example.condmem": {Name: "example.condmem", Ret: Void}})
	if !strings.Contains(ir, "cond_5feffect_5ftaken") {
		t.Fatal("conditional memory load/writeback executes unconditionally")
	}
}

func TestARMIntegerMemoryGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm/asm5.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A(MOV\w+), C_(SHIFTADDR|REG), C_NONE, C_(SHIFTADDR|REG),`).FindAllStringSubmatch(string(data), -1)
	seen := map[string]int{}
	for _, row := range rows {
		if row[2] == row[3] {
			continue
		}
		if _, ok := armIntegerMemorySpecs[row[1]]; !ok {
			t.Errorf("Go C_SHIFTADDR family member %s missing", row[1])
		}
		seen[row[1]]++
	}
	if len(seen) != len(armIntegerMemorySpecs) || len(seen) != 7 {
		t.Fatalf("Go shift-address grammar has %d mnemonics; spec has %d", len(seen), len(armIntegerMemorySpecs))
	}
	for op, count := range seen {
		if count != 2 {
			t.Errorf("%s has %d load/store rows, want two", op, count)
		}
	}
}

func TestARMIntegerMemoryNamedStackOffsets(t *testing.T) {
	for _, tc := range []struct {
		address string
		offset  int64
	}{
		{"w+4(SP)", 4}, {"end-4(SP)", -4}, {"scratch(SP)", 0},
	} {
		for _, load := range []bool{false, true} {
			instruction := "MOVW R7, " + tc.address
			if load {
				instruction = "MOVW " + tc.address + ", R7"
			}
			source := "TEXT stackoffset(SB),$32-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			form, err := parseARMIntegerMemoryForm("MOVW", file.Funcs[0].Instrs[1])
			if err != nil || form.offset.Kind != OpImm || form.offset.Imm != tc.offset {
				t.Errorf("%s: offset=%+v err=%v; want %d", instruction, form.offset, err, tc.offset)
			}
		}
	}
}

type armMemoryTestCase struct {
	op, instruction, suffix, offset string
	load                            bool
}

func armIntegerMemoryCases() []armMemoryTestCase {
	var cases []armMemoryTestCase
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, load := range []bool{false, true} {
			full := op == "MOVW" || load && op == "MOVBU" || !load && (op == "MOVB" || op == "MOVBS" || op == "MOVBU")
			offsets := []string{"0", "4", "-4", "R0<<0"}
			if full {
				for _, shift := range []string{"<<", ">>", "->", "@>"} {
					for _, amount := range []int{0, 1, 31} {
						if shift != "<<" || amount != 0 {
							offsets = append(offsets, fmt.Sprintf("R0%s%d", shift, amount))
						}
					}
				}
			}
			for _, offset := range offsets {
				for _, suffix := range []string{"", ".U", ".W", ".P", ".U.W", ".U.P", ".P.W"} {
					if full && offset == "-4" && strings.Contains(suffix, ".U") {
						continue
					}
					instruction := op + suffix + " R2, " + offset + "(R1)"
					if load {
						instruction = op + suffix + " " + offset + "(R1), R2"
					}
					cases = append(cases, armMemoryTestCase{op, instruction, suffix, offset, load})
				}
			}
		}
	}
	return cases
}

func TestARMIntegerMemoryCompleteFormsAcrossTargets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT memforms(SB),$0-0\n")
	cases := armIntegerMemoryCases()
	t.Logf("checking %d instruction/address combinations", len(cases))
	for _, tc := range cases {
		fmt.Fprintln(&source, tc.instruction)
	}
	source.WriteString("RET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"memforms": {Name: "memforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "mem.ll", "mem.o", ir)
		})
	}
}

func TestARMIntegerMemoryRejectsInvalidFormats(t *testing.T) {
	for _, instruction := range []string{
		"MOVW R0<<R3(R1), R2", "MOVW R0<<32(R1), R2",
		"MOVB R0<<1(R1), R2", "MOVBS R0>>0(R1), R2",
		"MOVH R0@>1(R1), R2", "MOVHU R2, R0<<1(R1)",
		"MOVHS R2, R0->0(R1)", "MOVW.S (R1), R2",
		"MOVW.U -4(R1), R2", "MOVBU.U R2, -4(R1)",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT badmemory(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm", Sigs: map[string]FuncSig{"badmemory": {Name: "badmemory", Ret: Void}}}); err == nil {
				t.Fatal("accepted memory format rejected by Go")
			}
		})
	}
}

// Execute the address-calculation IR on the host without dereferencing synthetic
// 32-bit pointers. Actual ARM memory execution is a separate cross-runtime gate.
func TestARMIntegerMemoryAddressModelRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var ir, declarations, checks strings.Builder
	ir.WriteString("declare i32 @llvm.fshr.i32(i32, i32, i32)\n")
	for i, tc := range armIntegerMemoryCases() {
		file, err := Parse(ArchARM, "TEXT probe(SB),$0-0\n"+tc.instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		form, err := parseARMIntegerMemoryForm(tc.op, file.Funcs[0].Instrs[1])
		if err != nil {
			t.Fatalf("%s: %v", tc.instruction, err)
		}
		name := fmt.Sprintf("address_%d", i)
		fmt.Fprintf(&ir, "define i64 @%s(i32 %%arg0, i32 %%arg1, i1 %%arg2) {\n", name)
		c := newARMCtx(&ir, Func{}, FuncSig{Name: name, Args: []LLVMType{I32, I32, I1}, ArgRegs: []Reg{"R0", "R1", "R2"}, Ret: I64}, nil, nil, false)
		if err := c.emitEntryAllocasAndArgInit(); err != nil {
			t.Fatal(err)
		}
		c.storeFlag(c.flagsCSlot, "%arg2")
		addr, updated, err := c.integerMemoryAddress(form)
		if err != nil {
			t.Fatal(err)
		}
		if !form.writeback {
			updated = "%arg1"
		}
		fmt.Fprintf(&ir, "  %%address = zext i32 %s to i64\n  %%base = zext i32 %s to i64\n  %%hi = shl i64 %%address, 32\n  %%result = or i64 %%hi, %%base\n  ret i64 %%result\n}\n", addr, updated)
		fmt.Fprintf(&declarations, "extern uint64_t %s(uint32_t, uint32_t, _Bool);\n", name)
		for _, value := range []uint32{3, 0x80000003} {
			for carry := uint32(0); carry <= 1; carry++ {
				delta := uint32(0)
				switch tc.offset {
				case "0":
				case "4":
					delta = 4
				case "-4":
					delta = ^uint32(3)
				default:
					var shift string
					var n uint
					fmt.Sscanf(tc.offset, "R0%2s%d", &shift, &n)
					if n == 0 {
						shift = "<<" // Go oplook canonicalizes all non-extension zero shifts.
					}
					switch shift {
					case "<<":
						delta = value << n
					case ">>":
						delta = value >> n
					case "->":
						delta = uint32(int32(value) >> n)
					case "@>":
						delta = bits.RotateLeft32(value, -int(n))
					default:
						t.Fatalf("bad test shift %q", tc.offset)
					}
				}
				if strings.Contains(tc.suffix, ".U") && (strings.HasPrefix(tc.offset, "R") || tc.op == "MOVW" || tc.load && tc.op == "MOVBU" || !tc.load && (tc.op == "MOVB" || tc.op == "MOVBS" || tc.op == "MOVBU")) {
					delta = -delta
				}
				addr, after := uint32(1024)+delta, uint32(1024)
				if strings.Contains(tc.suffix, ".P") || strings.Contains(tc.suffix, ".W") {
					after += delta
				}
				if strings.Contains(tc.suffix, ".P") {
					addr = 1024
				}
				want := uint64(addr)<<32 | uint64(after)
				fmt.Fprintf(&checks, "if (%s(%du, 1024u, %du) != UINT64_C(%d)) { puts(\"%s\"); return 1; }\n", name, value, carry, want, tc.instruction)
			}
		}
	}
	mainC := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0; }\n"
	compileAndRunRuntimeTest(t, llc, clang, "arm_address_model", ir.String(), mainC)
}
