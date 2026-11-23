package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalOfficialStackObjects(t *testing.T) {
	paths := x86OfficialAssemblerSourcePaths(t, "amd64")
	goAMD64FramePrepareOwnedToolCache(t)
	for _, base := range []Reg{SP, BP} {
		t.Run(string(base), func(t *testing.T) {
			fixedLocalOfficialStackObjects(t, paths, base)
		})
	}
}

func fixedLocalOfficialStackObjects(t *testing.T, paths []string, base Reg) {
	t.Helper()
	var assembly, declarations strings.Builder
	var names, locations []string
	namedAuto, aligned, stackResult, indexed := 0, 0, 0, 0
	address := "(" + string(base) + ")"
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, source := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(source, "//")
			code = strings.TrimSpace(code)
			if !strings.Contains(code, address) {
				continue
			}
			ins := x86ScalarLaneInstruction(t, code)
			if !errors.Is(ProbeInstruction(ArchAMD64, "amd64", ins), ErrProbeNeedsContext) {
				continue
			}
			memory, operand := initializedOrdinaryProbeMemory("amd64", ins)
			if index := fixedLocalVSIBOperand(ins); index >= 0 {
				memory, operand = ins.Args[index].Mem, index
			}
			location := fmt.Sprintf("%s:%d: %s", filepath.Base(path), line+1, code)
			name := fmt.Sprintf("Value%d", len(names))
			declaration := fmt.Sprintf("func %s()\n", name)
			var body string
			var alignment bool
			if operand < 0 || memory.Base != base {
				if base != SP {
					t.Fatalf("%s: missing physical BP address", location)
				}
				body = fixedLocalOfficialAutoSource(t, name, ins, location)
				namedAuto++
			} else {
				var result, vsib bool
				body, alignment, result, vsib = fixedLocalOfficialStackSource(t, name, ins, memory, location)
				if result {
					body = fixedLocalScalarFloatIntegerStackResult(name, ins.Raw)
					declaration = fmt.Sprintf("func %s(a uint64) uint64\n", name)
					stackResult++
				}
				if vsib {
					indexed++
				}
			}
			if alignment {
				aligned++ // The complete original entry must establish every SP residue.
				file, err := Parse(ArchAMD64, body)
				if err != nil {
					t.Fatal(location, err)
				}
				fn := file.Funcs[0]
				_, err = proveX86FixedLocal(fn, FuncSig{Name: fn.Sym, Ret: Void})
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "residue-dependent native alignment") {
					t.Fatalf("%s: expected the independent alignment guard, got %v", location, err)
				}
				continue
			}
			assembly.WriteString(body)
			declarations.WriteString(declaration)
			names = append(names, name)
			locations = append(locations, location)
		}
	}
	t.Logf("Go SDK stack objects=%d (VSIB=%d, named AUTO=%d, SP result=%d), alignment context=%d",
		len(names), indexed, namedAuto, stackResult, aligned)
	if len(names) == 0 || indexed == 0 || aligned == 0 {
		t.Fatal("missing official stack operands")
	}
	version := runtime.Version()
	if strings.HasPrefix(version, "go1.20.") || strings.HasPrefix(version, "go1.27.") {
		got := [5]int{len(names), indexed, aligned, stackResult, namedAuto}
		want := [5]int{627, 36, 9, 1, 12}
		if base == BP {
			want = [5]int{650, 73, 7, 0, 0}
		}
		if got != want {
			t.Fatalf("%s %s: Go SDK stack corpus counts %v, want %v", version, base, got, want)
		}
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const triple = "x86_64-unknown-linux-gnu"
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), "linux/amd64", triple)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for i, name := range names {
			names[i] = pkg.Path + "." + name
		}
		x86CompactExpandRequireAllDefinitions(t, ir, names)
		object := compileLLVMToObject(t, llc, triple, "official-stack.ll", "official-stack.o", ir)
		requireX86ELFTestFunctions(t, "amd64", object, names, locations)
	})
}

func fixedLocalOfficialAutoSource(t *testing.T, name string, ins Instr, location string) string {
	t.Helper()
	const frame = 128
	for index, operand := range ins.Args {
		if operand.Kind != OpMem || !strings.HasSuffix(operand.Mem.Sym, "(SP)") {
			continue
		}
		memory, err := fixedLocalMemoryAddress(ins, index, frame)
		if err != nil || memory.Index == "" || memory.Scale < 1 || memory.Scale > 8 || memory.Off < frame {
			t.Fatalf("%s: missing original indexed AUTO address: %v", location, err)
		}
		// The original lexical displacement is relative to the top of the
		// frame. Choose a signed index that brings the access into the frame.
		value := -(memory.Off - frame + 8 + memory.Scale - 1) / memory.Scale
		position := memory.Off + value*memory.Scale
		if position < 0 || position+8 > frame {
			t.Fatalf("%s: AUTO fixture escaped its frame", location)
		}
		return fmt.Sprintf("TEXT ·%s(SB),4,$%d-0\nMOVQ $4660,AX\nMOVQ AX,%d(SP)\nMOVQ $%d,%s\n%s\nRET\n",
			name, frame, position, value, memory.Index, ins.Raw)
	}
	t.Fatalf("%s: no named AUTO role", location)
	return ""
}

func fixedLocalOfficialStackSource(t *testing.T, name string, ins Instr, memory MemRef, location string) (
	source string, alignment, stackResult, vsib bool,
) {
	t.Helper()
	var inputs []Operand
	var width int64
	var vexMask Reg
	if form, known, err := x86VSIBProperties(ins, "amd64"); known {
		if err != nil || form.prefetch {
			t.Fatalf("%s: invalid VSIB fixture: %v", location, err)
		}
		inputs = []Operand{form.data, form.mask, {Kind: OpReg, Reg: memory.Index}}
		width = int64(form.spec.elemBits / 8)
		if !form.evex {
			vexMask = form.mask.Reg
		}
		vsib = true
	} else if form, known, err := x86ScalarFloatIntegerProperties(ins, "amd64"); known && err == nil && form.memory {
		if ins.Args[1].Reg == SP {
			return "", false, true, false
		}
		width = int64(form.spec.inputBits / 8)
	} else {
		registers, size, known := initializedVectorOperands("amd64", ins)
		if !known || size <= 0 || size > 64 {
			t.Fatalf("%s: missing bounded typed memory role", location)
		}
		width = size
		for _, input := range registers {
			if input.Kind != OpMem {
				inputs = append(inputs, input)
			}
		}
		if form, known, err := amd64PackedVectorMoveProperties(ins, "amd64"); known && err == nil {
			alignment = form.spec.aligned
		} else if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, "amd64"); known && err == nil {
			alignment = form.move.spec.aligned
		}
	}
	if memory.Off < -(4<<10) || memory.Off > 4<<10 || memory.Off < 0 && memory.Base != BP {
		t.Fatalf("%s: fixture must stay within a bounded frame", location)
	}

	var origin int64
	if memory.Off < 0 {
		origin = -memory.Off
	}
	effective := origin + memory.Off
	scalarIndex := memory.Index != "" && !vsib
	if scalarIndex {
		// Use a nonzero original index so the typed access covers the
		// instruction's scale as well as its displacement.
		effective += memory.Scale
	}
	start, end := effective&^7, (effective+width+7)&^7
	frame := end
	if pointerEnd := (origin + 8) &^ 7; memory.Base == BP && pointerEnd > frame {
		frame = pointerEnd
	}
	var body strings.Builder
	fmt.Fprintf(&body, "TEXT ·%s(SB),4,$%d-0\nMOVQ $1,AX\n", name, frame)
	for offset := start; offset < end; offset += 8 {
		fmt.Fprintf(&body, "MOVQ AX,%d(SP)\n", offset)
	}
	if len(inputs) != 0 {
		initialized, known, err := initializedVectorProbeSequence("amd64", ins, inputs)
		if err != nil || !known {
			t.Fatalf("%s: missing typed register initialization: %v", location, err)
		}
		for _, seed := range initialized[:len(initialized)-1] {
			if seed.Op == "KMOVD" {
				fmt.Fprintf(&body, "MOVQ $-1,AX\nKMOVQ AX,%s\n", seed.Args[1].Reg)
			} else {
				fmt.Fprintln(&body, seed.Raw)
			}
		}
	}
	if vexMask != "" {
		fmt.Fprintf(&body, "VPCMPEQD %s,%s,%s\n", vexMask, vexMask, vexMask)
	}
	if scalarIndex {
		fmt.Fprintf(&body, "MOVQ $1,%s\n", memory.Index)
	}
	if memory.Base == BP {
		// Derive BP from the captured private frame; the original negative
		// displacement and its separate index remain in the target opcode.
		fmt.Fprintf(&body, "LEAQ %d(SP),BP\n", origin)
	}
	fmt.Fprintln(&body, ins.Raw)
	body.WriteString("RET\n")
	return body.String(), alignment, false, vsib
}
