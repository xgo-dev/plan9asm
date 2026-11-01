package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86BitTestCompleteGoEncoderRows(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	start := strings.Index(text, "var ybtl = []ytab{")
	if start < 0 {
		t.Fatal("actual Go omitted the bit-string encoder table")
	}
	actual := strings.SplitN(strings.SplitN(text[start:], "\n}", 2)[0], "[]ytab{", 2)[1]
	got, err := x86SignedPackedFloatGoOpcodeTokens(actual)
	want, wantErr := x86SignedPackedFloatGoOpcodeTokens(`{Zibo_m,2,argList{Yi8,Yml}}, {Zr_m,1,argList{Yrl,Yml}},`)
	if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("complete ordered ybtl rows/classes/zcase/offset changed")
	}
	rows := regexp.MustCompile(`(?m)^\s*\{A(BT(?:C|R|S)?[WLQ]),\s*(\w+),\s*(\w+),\s*opBytes\{([^}]+)\}\},`).FindAllStringSubmatch(text, -1)
	if len(rows) != 12 {
		t.Fatalf("complete Go family changed: %d rows", len(rows))
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		op, suffix := row[1], row[1][len(row[1])-1]
		stem := op[:len(op)-1]
		group := map[string]int{"BT": 4, "BTC": 7, "BTR": 6, "BTS": 5}[stem]
		registerOpcode := map[string]int{"BT": 0xa3, "BTC": 0xbb, "BTR": 0xb3, "BTS": 0xab}[stem]
		prefix := map[byte]string{'W': "Pq", 'L': "Pm", 'Q': "Pw"}[suffix]
		encoding := fmt.Sprintf("0xba,0%d,0x%x", group, registerOpcode)
		if suffix == 'Q' {
			encoding = fmt.Sprintf("0x0f,0xba,0%d,0x0f,0x%x", group, registerOpcode)
		}
		got, err := x86SignedPackedFloatGoOpcodeTokens(row[4])
		want, wantErr := x86SignedPackedFloatGoOpcodeTokens(encoding)
		if seen[op] || row[2] != "ybtl" || row[3] != prefix || err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("complete Go family registration/prefix/opcode changed", row)
		}
		seen[op] = true
	}
	for _, op := range x86BitTestOracleNames("amd64") {
		if !seen[op] {
			t.Fatal("independent witness absent from actual Go optab", op)
		}
	}
}

func TestX86BitTestAllImmediateBytesActualGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		var expected []byte
		source.WriteString("TEXT f(SB),4,$0-0\n")
		count := 0
		for _, op := range x86BitTestOracleNames(arch) {
			stem, suffix := op[:len(op)-1], op[len(op)-1]
			group := byte(map[string]int{"BT": 4, "BTC": 7, "BTR": 6, "BTS": 5}[stem])
			for immediate := -128; immediate < 128; immediate++ {
				for _, destination := range []string{"AX", "7(DX)"} {
					fmt.Fprintf(&source, "%s $%d,%s\n", op, immediate, destination)
					if suffix == 'W' {
						expected = append(expected, 0x66)
					} else if suffix == 'Q' {
						expected = append(expected, 0x48)
					}
					expected = append(expected, 0x0f, 0xba)
					if destination == "AX" {
						expected = append(expected, 0xc0|group<<3)
					} else {
						// Go emits exactly the source displacement, not a new
						// displacement inferred from high immediate bits.
						expected = append(expected, 0x42|group<<3, 7)
					}
					expected = append(expected, byte(immediate))
					ins := x86PureGPUnknownInstruction(t, fmt.Sprintf("%s $%d,%s", op, immediate, destination))
					form, known, err := x86BitTestProperties(ins.Op, ins, arch)
					if !known || err != nil || form.index.Imm != int64(immediate) {
						t.Fatal("typed immediate differs from independent original Go byte", ins, err)
					}
					count++
				}
			}
		}
		source.WriteString("RET\n")
		expected = append(expected, 0xc3)
		actual := x86PackedShiftActualGoBytes(t, arch, source.String())
		if !bytes.Equal(actual, expected) {
			t.Fatalf("%s complete original immediate bytes differ: got %d bytes, want %d", arch, len(actual), len(expected))
		}
		t.Logf("%s: %d actual Go bit-string encodings, every imm8, register and memory", arch, count)
	}
}

func TestX86BitTestCompleteFormsFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, deadRegisters strings.Builder
			var initialized, unknownMemory []x86OriginalGPInitializedFormat
			var deadDeclarations strings.Builder
			privateOnly := 0
			count := 0
			for _, op := range x86BitTestOracleNames(target.arch) {
				rows := []string{"$-128,AX", "$127,CX", "CX,AX", "AX,AX", "SP,BP", "CX,SP",
					"$63,7(DX)", "CX,7(DX)", "CX,-3(DX)(SI*4)", "$1,data-3(SB)", "CX,data+3(SB)",
					"$1,8(FS)", "CX,8(GS)", "$1,4096", "CX,4096"}
				if target.arch == "amd64" {
					rows = append(rows, "R8,R15", "R9,-7(R12)(R11*8)")
				} else {
					rows = append(rows, "$4294967295,AX", "CX,data(SB)(SP)", "$1,data(SB)(BX*4)")
				}
				registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
				if target.arch == "amd64" {
					registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
				}
				for _, register := range registers {
					rows = append(rows, register+",AX", "$1,"+register, "AX,"+register)
				}
				for _, row := range rows {
					body := op + " " + row
					ins := x86PureGPUnknownInstruction(t, body)
					form, known, err := x86BitTestProperties(ins.Op, ins, target.arch)
					if !known || err != nil {
						t.Fatalf("typed shape %s: %v", body, err)
					}
					name := fmt.Sprintf("form%d", count)
					original := fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, body)
					source.WriteString(original)
					hardwareOnly := form.destination.Kind == OpMem && form.destination.Mem.Segment != "" &&
						form.destination.Mem.Base == "" && form.destination.Mem.Index == "" && form.index.Kind == OpImm
					if form.destination.Kind != OpReg && !hardwareOnly {
						unknownMemory = append(unknownMemory, x86OriginalGPInitializedFormat{
							source: original, declaration: "func " + name + "()",
						})
					}
					ordinaryScratch := form.destination.Kind == OpReg &&
						!x86OriginalGPPhysicalRegister(form.destination.Reg, target.arch) &&
						(form.index.Kind != OpReg || !x86OriginalGPPhysicalRegister(form.index.Reg, target.arch))
					if ordinaryScratch {
						// A dead ordinary register scratch is still a valid
						// public source; do not invent NUM to retain that domain.
						deadRegisters.WriteString(original)
						fmt.Fprintf(&deadDeclarations, "func %s()\n", name)
					}
					fixture, reason := x86BitTestOriginalInitializedFormat(target.arch, name, body, form)
					if reason == "" {
						initialized = append(initialized, fixture)
					} else {
						privateOnly++
						t.Logf("original row %d retains format/public-role boundary: %s: %s", count, body, reason)
					}
					count++
				}
			}
			want := map[string]int{"amd64": 780, "386": 336}[target.arch]
			if count != want {
				t.Fatal("original ordered bit-test inventory changed", count, want)
			}
			wantInitialized := map[string]int{"amd64": 636, "386": 248}[target.arch]
			if len(initialized) != wantInitialized || privateOnly != want-wantInitialized {
				t.Fatal("original bit-test input partition changed", len(initialized), privateOnly, wantInitialized)
			}
			// The complete unchanged source retains actual Go objects and
			// three public Context observations. Emit every original row
			// through the same typed family, with no public input claim.
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			formats := *file
			formats.Funcs = nil
			physicalWrites := 0
			for _, function := range file.Funcs {
				instruction := function.Instrs[1]
				form, _, _ := x86BitTestProperties(instruction.Op, instruction, target.arch)
				if target.arch != "386" || form.stem == "BT" || form.destination.Kind != OpReg || form.destination.Reg != SP {
					formats.Funcs = append(formats.Funcs, function)
					continue
				}
				// Go encodes these original physical ESP writes, but the
				// ordinary emitter requires a modeled stack/return contract.
				// Preserve its actual rejection rather than fabricate an object.
				var partial strings.Builder
				resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
				consumer := newX86Ctx(&partial, function, signatures[resolve(function.Sym)], resolve,
					signatures, target.arch, target.triple, false)
				if err := consumer.emitEntryAllocas(); err != nil {
					t.Fatal(err)
				}
				known, terminal, err := consumer.lowerBitTestFamily(instruction.Op, instruction)
				if !known || terminal || err == nil || !strings.Contains(err.Error(), "386 direct SP write is unsupported") {
					t.Fatal("original physical ESP row lost its independent emitter boundary", instruction.Raw, err)
				}
				physicalWrites++
			}
			if want := map[string]int{"amd64": 0, "386": 18}[target.arch]; physicalWrites != want {
				t.Fatal("original physical ESP write inventory changed", physicalWrites, want)
			}
			ir := x86SingleInstructionFormatObjectUnits(t, &formats, signatures, target.arch, target.triple,
				func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
					return c.lowerBitTestFamily(instruction.Op, instruction)
				})
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, target.triple, ir, level)
			}
			for row, fixture := range unknownMemory {
				t.Run(fmt.Sprintf("unbound-memory/row%d", row), func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("unbound original memory format invented inputs", api, err)
						}
					}
				})
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run("dead-registers/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, deadRegisters.String(), deadDeclarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("original pure dead-register domain changed", err)
					}
				})
			}
			x86OriginalGPInitializedFormatObjects(t, initialized, target.arch, target.triple)
			t.Logf("%d original Go formats; %d private LLVM formats; %d explicit physical-emitter rejections; %d exact-row initialized counterparts; %d independent physical/static/address roles",
				count, len(formats.Funcs), physicalWrites, len(initialized), privateOnly)
		})
	}
}

// These test-only inputs name complete Go sources; they carry no product
// permission and are never substituted into the original format inventory.
type x86OriginalGPInitializedFormat struct {
	source, declaration string
}

// Keep original row identity, exact displacement, segment and operand order.
// A real NUM producer is separate from an opaque incoming pointer identity.
func x86BitTestOriginalInitializedFormat(arch, name, body string, form x86BitTestForm) (x86OriginalGPInitializedFormat, string) {
	var numerical []Reg
	if form.index.Kind == OpReg {
		numerical = append(numerical, form.index.Reg)
	}
	pointer := Reg("")
	switch form.destination.Kind {
	case OpReg:
		numerical = append(numerical, form.destination.Reg)
	case OpMem:
		memory := form.destination.Mem
		if memory.Sym != "" {
			return x86OriginalGPInitializedFormat{}, "static bit string needs its independently bound source/storage role"
		}
		if memory.Segment != "" {
			// The hardware base is implicit; an explicit GP is its NUM
			// offset, never an opaque incoming-pointer identity.
			if memory.Base != "" {
				numerical = append(numerical, memory.Base)
			}
		} else {
			if memory.Base == "" {
				return x86OriginalGPInitializedFormat{}, "absolute numerical address has no ordinary opaque-pointer entry role"
			}
			pointer = memory.Base
		}
		if memory.Index != "" {
			numerical = append(numerical, memory.Index)
		}
	default:
		return x86OriginalGPInitializedFormat{}, "absolute/SB operand keeps its independent source-bound address role"
	}
	if pointer != "" && x86OriginalGPPhysicalRegister(pointer, arch) {
		return x86OriginalGPInitializedFormat{}, "physical source frame register needs an independent registered entry"
	}
	for _, register := range numerical {
		if x86OriginalGPPhysicalRegister(register, arch) {
			return x86OriginalGPInitializedFormat{}, "physical source frame register cannot be fabricated as ordinary NUM"
		}
		if register == pointer {
			return x86OriginalGPInitializedFormat{}, "one opaque address identity cannot also provide numerical source/index bytes"
		}
	}
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	var prefix strings.Builder
	arguments, declaration := 0, "func "+name+"()"
	if pointer != "" {
		arguments = word
		declaration = "func " + name + "(p *[64]byte)"
		fmt.Fprintf(&prefix, "%s p+0(FP),%s\n", move, pointer)
	}
	seen := make(map[Reg]bool)
	for _, register := range numerical {
		if !seen[register] {
			fmt.Fprintf(&prefix, "%s $1,%s\n", move, register)
			seen[register] = true
		}
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s%s\nRET\n", name, arguments, prefix.String(), body)
	return x86OriginalGPInitializedFormat{source, declaration}, ""
}

// This ordinary source observer has no physical SP/amd64BP entry role.
// BP remains an ordinary GP in Go's mode32 source contract.
func x86OriginalGPPhysicalRegister(register Reg, arch string) bool {
	return register == SP || arch == "amd64" && register == BP
}

// Batch complete original-format counterparts, never one LLVM process per
// row. All original bytes and private objects remain independently owned.
func x86OriginalGPInitializedFormatObjects(t *testing.T, fixtures []x86OriginalGPInitializedFormat, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for start := 0; start < len(fixtures); start += 32 {
		end := start + 32
		if end > len(fixtures) {
			end = len(fixtures)
		}
		t.Run(fmt.Sprintf("initialized/batch%02d", start/32), func(t *testing.T) {
			var source, declarations strings.Builder
			for _, fixture := range fixtures[start:end] {
				source.WriteString(fixture.source)
				declarations.WriteString(fixture.declaration + "\n")
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("same original instruction with complete ordinary inputs", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				})
			}
		})
	}
}

func TestX86BitTestMalformedAndModeForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BitTestOracleNames(arch) {
			for _, row := range []string{"$128,AX", "$-129,AX", "$1.0,AX", "AL,AX", "X0,AX", "AX,X0", "AX,$1", "AX", "(AX),BX", "$1,(AX)(SP*2)"} {
				body := op + " " + row
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
				ins := x86PureGPUnknownInstruction(t, body)
				if _, known, err := x86BitTestProperties(ins.Op, ins, arch); !known || err == nil {
					t.Errorf("malformed original form admitted: %s %s", arch, body)
				}
			}
			for _, mutate := range []func(*Instr){
				func(i *Instr) { i.Op += ".Z" },
				func(i *Instr) { i.Args[0].ImmRaw = "unknown" },
				func(i *Instr) { i.Args[1].Mem.OffRaw = "unknown" },
				func(i *Instr) { i.Args[1].Mem.Index = CX; i.Args[1].Mem.Scale = 3 },
			} {
				ins := x86PureGPUnknownInstruction(t, op+" $1,(DX)")
				mutate(&ins)
				if _, known, err := x86BitTestProperties(ins.Op, ins, arch); !known || err == nil {
					t.Errorf("typed malformed shape admitted: %s %+v", arch, ins)
				}
			}
		}
	}
	for _, body := range []string{"BTQ AX,BX", "BTCQ $1,(AX)", "BTRQ AX,BX", "BTSQ AX,BX", "BTL R8,AX", "BTSL AX,R15"} {
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
		ins := x86PureGPUnknownInstruction(t, body)
		if _, known, err := x86BitTestProperties(ins.Op, ins, "386"); !known || err == nil {
			t.Error("386 accepted unavailable native encoding", body)
		}
	}
}
