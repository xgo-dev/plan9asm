package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64RemainderScratchNumericBoundsCannotSurvive(t *testing.T) {
	for _, op := range []string{"REM", "REMW", "UREM", "UREMW"} {
		file, err := Parse(ArchARM64, "TEXT bounds(SB),4,$0-0\n"+op+" R1,R0,R2\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := newARM64PrivateDataState()
		state.regs["R27"] = arm64PrivateDataNumber(arm64PoolInterval{8, 8})
		state.comparison = arm64PrivateDataCompare{leftReg: "R27", valid: true}
		if _, valid := state.transfer(file.Funcs[0].Instrs[1], 1, 64); !valid {
			t.Fatalf("numeric remainder must have known effects: %s", op)
		}
		if state.value("R27") != arm64PrivateDataUnknown || state.comparison.valid {
			t.Fatalf("%s retained pre-DIV quotient bounds/comparison: %+v", op, state)
		}
	}
}

func TestARM64DivideRemainderTypedImplicitEffects(t *testing.T) {
	for _, op := range []string{"SDIV", "SDIVW", "UDIV", "UDIVW", "REM", "REMW", "UREM", "UREMW"} {
		for _, two := range []bool{false, true} {
			text := op + " R1,R0,R2"
			if two {
				text = op + " R1,R2"
			}
			file, err := Parse(ArchARM64, "TEXT effects(SB),4,$0-0\n"+text+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, handled, err := parseARM64GPDataForm(Op(op), ins)
			if !handled || err != nil {
				t.Fatalf("typed form rejected: %s: %v", text, err)
			}
			outputs := arm64GPDataOutputRegisters(form)
			remainder := strings.Contains(op, "REM")
			count := 1
			if remainder {
				count++
			}
			if len(outputs) != count || outputs[0] != "R2" || remainder && outputs[1] != "R27" {
				t.Fatalf("wrong explicit/implicit outputs for %s: %v", text, outputs)
			}
			for _, input := range arm64GPDataInputRegisters(form) {
				state := &arm64ControlState{
					regs:   map[Reg]arm64ControlValue{input: arm64ControlFromMap(map[string]bool{"label:caller": true})},
					memory: make(map[string]arm64ControlValue),
				}
				state.transfer(ins, Op(op), false, nil)
				for _, output := range outputs {
					if !arm64ControlHas(arm64ControlRead(state.regs, output), "code-derived:") {
						t.Fatalf("%s %s -> %s lost code provenance", text, input, output)
					}
				}
				mayFrame := arm64PrivateFrameAddress{offset: 8, exact: true}
				raw := &arm64RawPrivateFrameState{regs: arm64PrivateFrameAddresses{input: mayFrame}, spills: make(map[int64]arm64PrivateFrameAddress)}
				readOnly := raw.regs.clone()
				indexed := newARM64PrivateDataState()
				indexed.regs[input] = arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{8, 8}}
				_, valid := indexed.transfer(ins, 1, 64)
				if raw.transfer(ins, ins, 64) || readOnly.transfer(ins, 64) || valid {
					t.Fatalf("%s consumed private frame input %s as numerical data", text, input)
				}
			}
			if !two {
				mayFrame := arm64PrivateFrameAddress{offset: 8, exact: true}
				raw := &arm64RawPrivateFrameState{
					regs: arm64PrivateFrameAddresses{"R2": mayFrame, "R27": mayFrame}, spills: make(map[int64]arm64PrivateFrameAddress),
				}
				readOnly := raw.regs.clone()
				if !raw.transfer(ins, ins, 64) || !readOnly.transfer(ins, 64) {
					t.Fatalf("write-only destinations acquired false inputs: %s", text)
				}
				for _, output := range outputs {
					if _, present := raw.regs[output]; present {
						t.Fatalf("%s retained stale output frame category %s", text, output)
					}
					if _, present := readOnly[output]; present {
						t.Fatalf("%s retained stale read-only output frame category %s", text, output)
					}
				}
			}
		}
	}
}

func TestARM64DivideRemainderCompleteGoRows(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(bytes)
	for _, family := range []struct {
		name, encoder string
		aliases       []string
	}{
		{"AREM", "16", []string{"REMW", "UREM", "UREMW"}},
		// CRC32 shares this Go operand class, not division semantics.
		{"ASDIV", "1", []string{"SDIVW", "UDIV", "UDIVW", "CRC32B", "CRC32CB", "CRC32CH", "CRC32CW", "CRC32CX", "CRC32H", "CRC32W", "CRC32X"}},
	} {
		rows := regexp.MustCompile(`(?m)^\s*\{`+family.name+`, C_ZREG, C_(?:ZREG|NONE), C_NONE, C_ZREG,(?: C_NONE,)? `+family.encoder+`,`).FindAllString(source, -1)
		if len(rows) != 2 {
			t.Fatalf("Go %s two/three-operand rows changed: %v", family.name, rows)
		}
		block := regexp.MustCompile(`case ` + family.name + `:\s*\n((?:\s*oprangeset\([^\n]+\n)+)`).FindStringSubmatch(source)
		if len(block) != 2 {
			t.Fatalf("Go %s alias table not recognized", family.name)
		}
		aliases := regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block[1], -1)
		if len(aliases) != len(family.aliases) {
			t.Fatalf("Go %s alias family changed: %v", family.name, aliases)
		}
		for index, alias := range aliases {
			if alias[1] != family.aliases[index] {
				t.Fatalf("Go %s alias mismatch: %v", family.name, aliases)
			}
		}
	}
	expansion := regexp.MustCompile(`(?s)case 16:.*?\n\s*case 17:`).FindString(source)
	current := strings.Contains(expansion, "c.oprrr(p, p.As, REGTMP, r, rf)") &&
		strings.Contains(expansion, "c.oprrrr(p, AMSUBW, rt, REGTMP, rf, r)")
	// Go 1.20 uses the same machine sequence but fills the exact register
	// fields after selecting each instruction's base opcode.
	legacy := strings.Contains(expansion, "o1 = c.oprrr(p, p.As)") &&
		strings.Contains(expansion, "o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | REGTMP&31") &&
		strings.Contains(expansion, "o2 = c.oprrr(p, AMSUBW)") &&
		strings.Contains(expansion, "o2 |= (uint32(rf&31) << 16) | (uint32(r&31) << 10) | (REGTMP & 31 << 5) | uint32(rt&31)")
	if !current && !legacy {
		t.Fatal("Go REM quotient/MSUB expansion changed")
	}
	registers, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/a.out.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`REGTMP\s*=\s*REG_R27`).Match(registers) {
		t.Fatal("Go REM scratch identity changed")
	}
}

func TestARM64RemainderImplicitScratchCannotRestoreCaller(t *testing.T) {
	for _, op := range []string{"REM", "REMW", "UREM", "UREMW"} {
		source := fmt.Sprintf(`TEXT ·scratch(SB),4,$0-0
MOVD R30,R27
MOVD $9,R0
MOVD $2,R1
%s R1,R0,R2
MOVD R27,R30
RET
`, op)
		// Stock Go accepts this source, but executing its damaged link would
		// be unsafe. Only object syntax and fail-closed translation are tested.
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{
			"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin",
			"aarch64-pc-windows-msvc", "aarch64-w64-windows-gnu",
		} {
			options := Options{Goarch: "arm64", TargetTriple: triple,
				ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs:       map[string]FuncSig{"scratch": {Name: "scratch", Ret: Void}},
			}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s Translate retained overwritten R27 caller link: %v", op, triple, err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, options)
			if err == nil {
				module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s module retained overwritten R27 caller link: %v", op, triple, err)
			}
			pkg := mustGoPackage(t, "scratch", "package scratch\nfunc scratch()\n")
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: triple, ResolveSym: options.ResolveSym,
			})
			if err == nil {
				bound.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s Go module retained overwritten R27 caller link: %v", op, triple, err)
			}
			ctx.Dispose()
		}
	}
}
