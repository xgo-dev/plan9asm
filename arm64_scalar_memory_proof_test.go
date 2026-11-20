package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64ScalarMemoryCompleteSourceGrammar(t *testing.T) {
	for _, tc := range arm64MemoryAuditForms() {
		ins := arm64ImmediateTestInstruction(t, tc.instruction)
		before := ins
		file, err := Parse(ArchARM64, "TEXT grammar(SB),4,$0-0\n"+tc.instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		fn := file.Funcs[0]
		normalized, err := normalizeARM64ScalarMemoryFrame(fn)
		if err != nil {
			t.Fatalf("%s normalization: %v", tc.instruction, err)
		}
		form, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(ins), normalized.Instrs[1])
		if !handled || err != nil {
			t.Errorf("original Go accepted %s: handled=%v error=%v", tc.instruction, handled, err)
		}
		if !reflect.DeepEqual(ins, before) {
			t.Fatalf("%s mutated source operands", tc.instruction)
		}
		if tc.width == 4 && form.scratch {
			t.Errorf("direct %s acquired source scratch", tc.instruction)
		}
	}
	// The original Go encoder accepts the int32-narrowed field, not a wide
	// update. The real assembler bytes are independently checked by the audit.
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, suffix := range []string{".P", ".W"} {
			ins := arm64ImmediateTestInstruction(t, op+suffix+" $0,4294967551(R0)")
			form, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(ins), ins)
			if !handled || err != nil || form.memory.Mem.Off != 255 || form.scratch {
				t.Fatalf("%s original narrowed writeback: %+v %v", ins.Raw, form, err)
			}
		}
	}
}

func TestARM64ScalarMemoryScratchOrderedProvenance(t *testing.T) {
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, direction := range []bool{false, true} {
			text := op + " 65536(R0),R1"
			if direction {
				text = op + " R1,65536(R0)"
			}
			ins := arm64ImmediateTestInstruction(t, text)
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R0": arm64ControlFromMap(map[string]bool{"label:actual_pc": true}), "R27": arm64ControlFromMap(map[string]bool{"label:old_lr": true})},
				memory: make(map[string]arm64ControlValue),
			}
			state.transfer(ins, ins.Op, false, nil)
			if arm64ControlHas(state.regs["R27"], "label:old_lr") || !arm64ControlHas(state.regs["R27"], "code-derived:") || !arm64ControlHas(state.regs["R27"], "label:actual_pc") {
				t.Fatalf("%s lost address-PC provenance or retained old LR: %+v", text, state.regs["R27"])
			}
			literal := arm64ImmediateTestInstruction(t, op+" -8192(R0),R1")
			state.transfer(literal, literal.Op, false, nil)
			if arm64ControlCount(arm64ControlLabels(state.regs["R27"])) != 0 {
				t.Fatalf("%s literal scratch inherited base/old-R27 code", literal.Raw)
			}
		}
	}
	// The old effective address is read before materialization; the transfer
	// data R27 is read afterwards. This is not a register-independent store.
	ins := arm64ImmediateTestInstruction(t, "MOVD R27,65536(R27)")
	state := &arm64ControlState{
		regs:   map[Reg]arm64ControlValue{"R27": arm64ControlFromMap(map[string]bool{"sp:16": true})},
		memory: make(map[string]arm64ControlValue),
	}
	state.transfer(ins, ins.Op, false, nil)
	if !arm64ControlHas(state.memory["sp:65552"], "sp:65552") || !arm64ControlHas(state.regs["R27"], "sp:65552") {
		t.Fatalf("base/data alias lost ordered address or data: %+v", state)
	}
}

func TestARM64ScalarMemoryScratchPrivateAndNumericEffects(t *testing.T) {
	for _, tc := range []struct {
		text   string
		frame  bool
		offset int64
	}{
		{"MOVD 65536(R0),R1", true, 65552},
		{"MOVD -8192(R0),R1", false, -8192},
		{"MOVD 32768(R0),R1", true, 0}, // Encoder variants retain may-frame, not bounds.
	} {
		ins := arm64ImmediateTestInstruction(t, tc.text)
		address := arm64PrivateFrameAddress{offset: 16, exact: true}
		read := arm64PrivateFrameAddresses{"R0": address, "R27": {offset: 8, exact: true}}
		if !tc.frame {
			delete(read, "R0") // Literal scratch's data address is external storage.
		}
		raw := &arm64RawPrivateFrameState{regs: read.clone(), spills: make(map[int64]arm64PrivateFrameAddress)}
		numeric := newARM64PrivateDataState()
		numeric.regs["R0"] = arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{16, 16}}
		if !tc.frame {
			delete(numeric.regs, "R0")
		}
		numeric.regs["R27"] = arm64PrivateDataNumber(arm64PoolInterval{7, 7})
		numeric.comparison = arm64PrivateDataCompare{valid: true, leftReg: "R27"}
		if !read.transfer(ins, 131072) || !raw.transfer(ins, ins, 131072) {
			t.Fatalf("%s bounded initialized address proof failed", tc.text)
		}
		if _, valid := numeric.transfer(ins, 0, 131072); !valid {
			t.Fatalf("%s numeric proof failed", tc.text)
		}
		for _, addresses := range []arm64PrivateFrameAddresses{read, raw.regs} {
			value, frame := addresses.address("R27")
			if frame != tc.frame || tc.frame && tc.offset != 0 && (!value.exact || value.offset != tc.offset) ||
				tc.frame && tc.offset == 0 && value.exact {
				t.Errorf("%s stale/private scratch: %+v frame=%v", tc.text, value, frame)
			}
		}
		value := numeric.value("R27")
		if value.frame != tc.frame || !tc.frame && value.interval != (arm64PoolInterval{uint64(tc.offset), uint64(tc.offset)}) ||
			tc.frame && tc.offset != 0 && value.interval != (arm64PoolInterval{uint64(tc.offset), uint64(tc.offset)}) || numeric.comparison.valid {
			t.Errorf("%s stale numeric scratch/comparison: %+v", tc.text, value)
		}
		stack := arm64StackState{0: {local: true, low: 16, high: 16}, 27: {local: true, low: 8, high: 8}}
		if !tc.frame {
			stack[0] = arm64StackRange{}
		}
		if err := arm64StackStep(&stack, ins, ins); err != nil {
			t.Fatal(err)
		}
		if stack[27].local != tc.frame || tc.frame && tc.offset != 0 && stack[27].low != tc.offset ||
			tc.frame && tc.offset == 0 && !stack[27].unknown {
			t.Errorf("%s stale stack interval: %+v", tc.text, stack[27])
		}
	}
}

func TestARM64ScalarMemoryCoarsePrivateFrameStoreBoundary(t *testing.T) {
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, tc := range []struct {
			operands string
			accepted bool
		}{
			{"R11,8(RSP)", true}, // Original source-relative store policy.
			{"R11,(R9)", false},  // Derived GP stores require the DATA proof.
			{"R9,8(RSP)", false}, // An SP-relative store cannot spill a frame pointer.
			{"(R9),R11", true},   // The original bounded read remains supported.
			{".P R11,8(RSP)", false},
			{"R11,(RSP)(R7)", false},
		} {
			text := op + " " + tc.operands
			if strings.HasPrefix(tc.operands, ".") {
				text = op + tc.operands
			}
			ins := arm64ImmediateTestInstruction(t, text)
			state := arm64PrivateFrameAddresses{"R9": {offset: 8, exact: true}}
			if got := state.transfer(ins, 32); got != tc.accepted {
				t.Errorf("%s coarse source-only boundary = %v, want %v", text, got, tc.accepted)
			}
		}
	}
}

func TestARM64ScalarMemorySourceScratchAvailability(t *testing.T) {
	for _, tail := range []struct {
		text  string
		valid bool
	}{
		{"MOVD R1,ret+8(FP)\nRET", true},
		{"MOVD $19,R27\nMOVD R27,ret+8(FP)\nRET", true},
		{"MOVD R27,ret+8(FP)\nRET", false},
		{"MOVD R27,R5\nMOVD R5,ret+8(FP)\nRET", false},
		{"CBZ R1,join\nMOVD $19,R27\njoin:\nMOVD R27,ret+8(FP)\nRET", false},
		{"CBZ R1,other\nMOVD $19,R27\nB join\nother:\nMOVD $20,R27\njoin:\nMOVD R27,ret+8(FP)\nRET", true},
	} {
		for _, move := range []struct {
			text    string
			unknown bool
		}{
			{"MOVD 32768(R0),R1", true},
			{"MOVD -257(R0),R1", true},
			{"MOVD 32769(R0),R1", true},
			// Both primary encoders load this exact literal into R27.
			{"MOVD 65537(R0),R1", false},
		} {
			source := "TEXT ·Scratch(SB),4,$0-16\nMOVD input+0(FP),R0\n" + move.text + "\n" + tail.text + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "test/memory", "package memory\nfunc Scratch(input *[131072]byte) uint64\n")
			resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
			sizes := types.SizesFor("gc", "arm64")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
				check := func(api string, err error) {
					valid := tail.valid || !move.unknown
					if valid && err != nil || !valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %s %s tail %q: %v", api, target, move.text, tail.text, err)
					}
				}
				_, err = Translate(file, options)
				check("Translate", err)
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, options)
				if err == nil {
					module.Dispose()
				}
				check("Module", err)
				result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
				if err == nil {
					result.Module.Dispose()
				}
				ctx.Dispose()
				check("GoModule", err)
			}
		}
	}
}

func TestARM64ScalarMemoryDecoderOriginIsPrivate(t *testing.T) {
	source := arm64ImmediateTestInstruction(t, "MOVD 65536(R0),R1")
	source.Raw = "WORD $0xf9400001"
	bytes, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var decodedJSON Instr
	if err := json.Unmarshal(bytes, &decodedJSON); err != nil {
		t.Fatal(err)
	}
	for _, ins := range []Instr{source, decodedJSON} {
		form, handled, err := parseARM64ScalarMemoryForm(ins.Op, ins)
		if !handled || err != nil || !form.scratch || ins.arm64Encoded {
			t.Fatalf("public/Raw text asserted physical decoder identity: %+v %v", form, err)
		}
	}
	raw := arm64ImmediateTestInstruction(t, "WORD $0xf9400361")
	physical, err := decodeARM64RawWordInstruction(raw)
	if err != nil {
		t.Fatal(err)
	}
	form, handled, err := parseARM64ScalarMemoryForm(physical.Op, physical)
	if !handled || err != nil || form.scratch || !physical.arm64Encoded {
		t.Fatalf("genuine physical LDR acquired Go R27 expansion: %+v %v", form, err)
	}
	if _, handled, err := parseARM64ScalarMemoryForm("MOVB", source); !handled || err == nil {
		t.Fatal("conflicting dispatch identity acquired typed memory proof")
	}
	var output strings.Builder
	ctx := &arm64Ctx{b: &output}
	if handled, _, err := ctx.lowerARM64ScalarMemory("MOVB", source); !handled || err == nil || output.Len() != 0 {
		t.Fatalf("invalid dispatch emitted IR: %s %v", output.String(), err)
	}
	t.Logf("decoder-only raw %s remains one physical instruction", fmt.Sprint(raw.Args))
}

func TestARM64ScalarMemoryFrameClassRequiresSourceIdentity(t *testing.T) {
	for _, text := range []string{"MOVD local+0(SP),R1", "MOVD R1,local+0(SP)"} {
		ins := arm64ImmediateTestInstruction(t, text)
		if _, err := normalizeARM64ScalarMemoryFrame(Func{FrameSize: 32, Instrs: []Instr{ins}}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("AUTO acquired a frame from its size alone: %s: %v", text, err)
		}
		file, err := Parse(ArchARM64, "TEXT frame(SB),UNRESOLVED_FLAGS,$32-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0]); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unknown NOFRAME membership supplied AUTO identity: %s: %v", text, err)
		}
	}
	for _, text := range []string{"MOVD.P local+0(SP),R1", "MOVD R1,local+0(SP)(R2)"} {
		file, err := Parse(ArchARM64, "TEXT frame(SB),4,$32-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0]); err == nil {
			t.Fatalf("normalization erased a Go-invalid AUTO role: %s", text)
		}
		if _, known := arm64RawKnownSourceWidth(file.Funcs[0], file.Funcs[0].Instrs[1]); known {
			t.Fatalf("raw-PC width erased a Go-invalid AUTO role: %s", text)
		}
	}
	for _, text := range []string{"MOVD (R0),R1", "MOVD R1,255(R0)"} {
		ins := arm64ImmediateTestInstruction(t, text)
		if width, known := arm64RawKnownSourceWidth(Func{}, ins); !known || width != 4 {
			t.Fatalf("non-frame direct form acquired a new frame requirement: %s", text)
		}
	}
}

func TestARM64ScalarMemoryRejectsOriginalGoInvalidFormats(t *testing.T) {
	for _, instruction := range arm64MemoryAuditRejectedForms() {
		file, err := Parse(ArchARM64, "TEXT rejected(SB),4,$0-0\n"+instruction+"\nRET\n")
		if err != nil {
			continue // A parser rejection is not a successfully lowered format.
		}
		normalized, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0])
		if err != nil {
			continue
		}
		ins := normalized.Instrs[1]
		if _, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(ins), ins); !handled || err == nil {
			t.Errorf("original Go-rejected memory form acquired a typed grammar: %s: handled=%v error=%v", instruction, handled, err)
		}
	}
}

func arm64ScalarMemoryCheckPublicAPIs(t *testing.T, source, declaration, target string, valid bool) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "test/memory", "package memory\n"+declaration)
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(api string, err error) {
		if valid && err != nil || !valid && !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s %s valid=%v: %v\n%s", api, target, valid, err, source)
		}
	}
	options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	_, err = Translate(file, options)
	check("Translate", err)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if err == nil {
		module.Dispose()
	}
	check("Module", err)
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
	if err == nil {
		bound.Module.Dispose()
	}
	check("GoModule", err)
}

func TestARM64ScalarMemoryPhysicalSourceRoles(t *testing.T) {
	const data = "GLOBL payload(SB),8,$16\nDATA payload+0(SB)/8,$17\nDATA payload+8(SB)/8,$19\n"
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, move := range []string{op + " payload(SB),R1", op + " R1,payload(SB)"} {
			for _, readScratch := range []bool{false, true} {
				tail := "RET\n"
				if readScratch {
					tail = "MOVD R27,R30\nRET\n"
				}
				source := "TEXT ·Scratch(SB),4,$0-0\nMOVD $17,R1\nMOVD R30,R27\n" + move + "\n" + tail + data
				requireARM64GoAssemblerResult(t, source, true) // Object only: corrupt LR is never executed.
				for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
					arm64ScalarMemoryCheckPublicAPIs(t, source, "func Scratch()\n", target, !readScratch)
				}
			}
		}
	}
	for _, readScratch := range []bool{false, true} {
		move := ""
		if readScratch {
			move = "MOVD R27,R0\n" // This missing value reaches the actual result.
		}
		source := "TEXT ·Scratch(SB),4,$65536-16\nMOVD input+0(FP),R0\n" + move + "MOVD R0,ret+8(FP)\nRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
			arm64ScalarMemoryCheckPublicAPIs(t, source, "func Scratch(input uint64) uint64\n", target, !readScratch)
		}
	}
}
