package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86NativeMMXMoveMaskByteEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		// SP and amd64 BP have separate physical frame roles. The original
		// encoding matrix retains those spellings without granting this leaf
		// a logical GP destination; mode386 BP remains an ordinary GP.
		registers := []Reg{AX, CX, DX, BX, SI, DI}
		if arch == "amd64" {
			registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		} else {
			registers = append(registers, BP)
		}
		for bank := 0; bank < 8; bank++ {
			for _, destination := range registers {
				t.Run(fmt.Sprintf("%s/M%d/%s", arch, bank, destination), func(t *testing.T) {
					instruction := fmt.Sprintf("PMOVMSKB M%d,%s", bank, destination)
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(a uint64) uint32",
						fmt.Sprintf("MOVQ a+0(FP),M%d\n%s\nEMMS\nMOVL %s,ret+8(FP)\nRET", bank, instruction, destination))
					plan, err := newX86NativeMMXRegion(file.Funcs[0], sig, arch, x86Legacy127Targets(arch)[0])
					if err != nil || plan == nil {
						t.Fatal("MMX_MOVE_MASK_TYPED_REGION_GAP", err)
					}
					ordinal := plan.begin + 1 // Parse retains the original TEXT instruction.
					ins := file.Funcs[0].Instrs[ordinal]
					if ins.Op != "PMOVMSKB" {
						t.Fatal("independent transfer fixture lost its original mask operation")
					}
					index, _, valid := x86ResultGP(destination, 4, arch)
					if !valid {
						t.Fatal("independent GP fixture invalid")
					}
					if plan.gpRead[index] || !plan.gpWritten[index] {
						t.Fatal("write-only mask result acquired an old-GP dependency")
					}
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagZF, direction: x86ResultDirectionBackward}
					state.nativeMMX[bank] = 0xff
					state.canonicalGP[index] = 0xff
					state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = true, true, 7
					state.resultAddressGP[index] = x86ResultSlotAddress{start: 8, end: 12, valid: true}
					state.boolFrameGP = new([16]x86ResultSlotAddress)
					state.boolFrameGP[index] = state.resultAddressGP[index]
					before := state.clone()
					if accepted, known := plan.transfer(ordinal, ins, &state, nil, 8, arch); !accepted || !known {
						t.Fatal("defined physical MMX source not transferred")
					}
					expected := before.clone()
					expected.gp[index] = 0xff
					expected.canonicalGP[index] = 0xf0
					expected.pointerGP[index], expected.callerAddressGP[index], expected.callerAddressOrigin[index] = false, false, 0
					expected.resultAddressGP[index], expected.boolFrameGP[index] = x86ResultSlotAddress{}, x86ResultSlotAddress{}
					if !reflect.DeepEqual(expected, state) {
						t.Fatal("r32 result changed unrelated source/FLAGS or retained pointer/bool facts", state, expected)
					}
					for missing := 0; missing < 8; missing++ {
						state = before.clone()
						state.nativeMMX[bank] &^= 1 << uint(missing)
						unchanged := state.clone()
						if accepted, known := plan.transfer(ordinal, ins, &state, nil, 8, arch); accepted || !known || !reflect.DeepEqual(state, unchanged) {
							t.Fatal("missing physical source byte supplied a value or mutated state", missing)
						}
					}
					state = before.clone()
					if accepted, known := x86ResultMoveMaskStep(ins, &state, nil, 8, arch); accepted || !known {
						t.Fatal("ordinary observer acquired physical MMX")
					}
					changed := ins
					changed.Raw += " // changed"
					state = before.clone()
					if accepted, known := plan.transfer(ordinal, changed, &state, nil, 8, arch); accepted || !known {
						t.Fatal("private source identity changed")
					}
				})
			}
		}
	}
}

func mmxMoveMaskObjectByteError(disassembly, arch string) error {
	header := regexp.MustCompile(`^[0-9a-f]+ <([^>]+)>:$`)
	owner := ""
	seen := map[string]int{}
	for _, line := range strings.Split(disassembly, "\n") {
		if match := header.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			owner = strings.TrimPrefix(match[1], "_")
			continue
		}
		_, rest, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		var code []byte
		for len(fields) > 0 && len(fields[0]) == 2 {
			value, err := strconv.ParseUint(fields[0], 16, 8)
			if err != nil {
				break
			}
			code, fields = append(code, byte(value)), fields[1:]
		}
		if len(fields) == 0 || fields[0] != "pmovmskb" {
			continue
		}
		bank, err := strconv.Atoi(strings.TrimPrefix(owner, "MMXMaskByte"))
		if !strings.HasPrefix(owner, "MMXMaskByte") || err != nil || bank < 0 || bank > 7 {
			return fmt.Errorf("unowned target mask: %s", line)
		}
		want := []byte{0x44, 0x0f, 0xd7, 0xd0 | byte(bank)}
		if arch == "386" {
			want = []byte{0x0f, 0xd7, 0xc0 | byte(bank)}
		}
		if !bytes.Equal(want, code) {
			return fmt.Errorf("%s physical mask bytes=%x want=%x", owner, code, want)
		}
		seen[owner]++
	}
	for bank := 0; bank < 8; bank++ {
		name := fmt.Sprintf("MMXMaskByte%d", bank)
		if seen[name] != 1 {
			return fmt.Errorf("%s mask count=%d want=1", name, seen[name])
		}
	}
	return nil
}

func TestX86NativeMMXMoveMaskTargetBytes(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc/objdump required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var originals []x86OfficialPackedCase
			for bank := 0; bank < 8; bank++ {
				name := fmt.Sprintf("MMXMaskByte%d", bank)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVQ a+0(FP),M%d\n", name, bank)
				instruction := fmt.Sprintf("PMOVMSKB M%d,BX", bank)
				originals = append(originals, x86OfficialPackedCase{symbol: name, line: strings.Count(source.String(), "\n") + 1, witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: []byte{0x0f, 0xd7, 0xd8 | byte(bank)}}})
				fmt.Fprintln(&source, instruction)
				source.WriteString("EMMS\nMOVL BX,ret+8(FP)\nRET\n")
				fmt.Fprintf(&declarations, "func %s(a uint64) uint32\n", name)
			}
			listing, err := x86ScalarLiteralGoListing(t, target.arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, originals); err != nil {
				t.Fatal("original mask physical bytes", err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						disassembly := x86ExchangeObjectDisassembly(t, llc, objdump, target.triple, ir, level)
						if err := mmxMoveMaskObjectByteError(disassembly, target.arch); err != nil {
							t.Fatal(err)
						}
						// A bank swap between functions must not pass an aggregate count.
						changed := strings.NewReplacer("MMXMaskByte0", "MMXMaskByte1", "MMXMaskByte1", "MMXMaskByte0").Replace(disassembly)
						if mmxMoveMaskObjectByteError(changed, target.arch) == nil {
							t.Fatal("physical-bank/function swap escaped the byte oracle")
						}
					}
				})
			}
		})
	}
}

func TestX86NativeMMXMoveMaskRoleBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, body := range []string{
			"PMOVMSKB M0,AX\nEMMS",                              // No physical source definition.
			"MOVQ a+0(FP),M0\nPMOVMSKB M0,AX",                   // No real tag cleanup.
			"MOVQ a+0(FP),M0\nPMOVMSKB M0,AX\nMOVL $1,CX\nEMMS", // Interrupted physical region.
			"MOVL $0,AX\nCMPL AX,AX\nMOVQ a+0(FP),M0\nPMOVMSKB M0,AX\nEMMS\nPUSHFQ\nPOPQ AX", // Undefined system FLAGS bits are not an integer.
		} {
			if arch == "386" {
				body = strings.ReplaceAll(strings.ReplaceAll(body, "PUSHFQ", "PUSHFL"), "POPQ AX", "POPL AX")
			}
			_, _, _, source := x86ResultInitializationFixture(t, arch, "func Value(a uint64) uint32", body+"\nMOVL AX,ret+8(FP)\nRET")
			if _, err := x86ScalarLiteralGoListing(t, arch, source); err != nil {
				t.Fatal("negative is not real original Go", err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(a uint64) uint32", arch, x86Legacy127Targets(arch)[0], api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("MMX state/input boundary widened", arch, api, body, err)
				}
			}
		}
		// Void still consumes every physical source byte. An unused result
		// does not create a numerical MMX bank or dispense with real EMMS.
		source := "TEXT ·Value(SB),4,$0-8\nPMOVMSKB M0,AX\nEMMS\nRET\n"
		if _, err := x86ScalarLiteralGoListing(t, arch, source); err != nil {
			t.Fatal(err)
		}
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(a uint64)", arch, x86Legacy127Targets(arch)[0], api)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatal("Void supplied an undefined physical MMX source", arch, api, err)
			}
		}
	}
}

func TestX86NativeMMXMoveMaskOriginalGoRegisterBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
		if arch == "amd64" {
			registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		}
		var fixtures []x86OfficialPackedCase
		for bank := 0; bank < 8; bank++ {
			for reg, destination := range registers {
				code := []byte{0x0f, 0xd7, 0xc0 | byte(reg&7)<<3 | byte(bank)}
				if reg >= 8 {
					code = append([]byte{0x44}, code...)
				}
				fixtures = append(fixtures, x86OfficialPackedCase{witness: goasmrules.X86PackedBinaryWitness{Instruction: fmt.Sprintf("PMOVMSKB M%d,%s", bank, destination), Encoding: code, Destination: destination}})
			}
		}
		for start := 0; start < len(fixtures); start += 32 {
			end := start + 32
			if end > len(fixtures) {
				end = len(fixtures)
			}
			batch := append([]x86OfficialPackedCase(nil), fixtures[start:end]...)
			var source strings.Builder
			for i := range batch {
				batch[i].symbol = fmt.Sprintf("MMXMaskBytes%d", start+i)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[i].symbol)
				batch[i].line = strings.Count(source.String(), "\n") + 1
				fmt.Fprintln(&source, batch[i].witness.Instruction)
				source.WriteString("RET\n")
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
				t.Fatal(err)
			}
		}
	}
}
