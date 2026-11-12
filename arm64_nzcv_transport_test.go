package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/arm64/arm64asm"
)

func arm64NZCVRegisterName(reg int) string {
	switch reg {
	case 18:
		return "R18_PLATFORM"
	case 28:
		return "g"
	case 31:
		return "ZR"
	default:
		return fmt.Sprintf("R%d", reg)
	}
}

func arm64NZCVInstruction(read, raw bool, reg int) string {
	if raw {
		word := uint32(0xd51b4200)
		if read {
			word = 0xd53b4200
		}
		return fmt.Sprintf("WORD $0x%08x", word|uint32(reg))
	}
	if read {
		return "MRS NZCV," + arm64NZCVRegisterName(reg)
	}
	return "MSR " + arm64NZCVRegisterName(reg) + ",NZCV"
}

func TestARM64NZCVCompleteGoEncodingAndEffects(t *testing.T) {
	// Go asm7 rows 35/36 and SysRegEnc's read/write NZCV entry are
	// independently witnessed by original objects, including platform/g/ZR.
	var source strings.Builder
	for direction := 0; direction < 2; direction++ {
		for reg := 0; reg < 32; reg++ {
			fmt.Fprintf(&source, "TEXT nzcv%d_%d(SB),516,$0-0\n%s\nRET\n",
				direction, reg, arm64NZCVInstruction(direction == 1, false, reg))
		}
	}
	source.WriteString("TEXT zero(SB),516,$0-0\nMSR $0,NZCV\nRET\n")
	directory := t.TempDir()
	input, object := filepath.Join(directory, "nzcv_arm64.s"), filepath.Join(directory, "original.o")
	if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	listing, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", object, input)
	if err != nil {
		t.Fatalf("original Go NZCV grammar: %v\n%s", err, listing)
	}
	disassembly, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "objdump", object)
	if err != nil {
		t.Fatalf("original Go NZCV object: %v\n%s", err, disassembly)
	}
	bodies, err := arm64ScratchObjectBodies(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	for direction := 0; direction < 2; direction++ {
		for reg := 0; reg < 32; reg++ {
			name := fmt.Sprintf("nzcv%d_%d", direction, reg)
			body, exists := bodies[name]
			word := uint32(0xd51b4200) | uint32(direction)<<21 | uint32(reg)
			if !exists || len(body.code) < 2 || body.code[0] != word || body.code[1] != 0xd65f03c0 || len(body.relocs) != 0 {
				t.Fatalf("original Go exact %s encoding missing: %+v", name, body)
			}
			form, valid := decodeARM64RawNZCV(word)
			if !valid || form.read != (direction == 1) {
				t.Fatalf("typed form mismatch: %08x %+v", word, form)
			}
			var code [4]byte
			binary.LittleEndian.PutUint32(code[:], word)
			instruction, err := arm64asm.Decode(code[:])
			if err != nil {
				t.Fatal(err)
			}
			var reads, writes uint32
			if reg != 31 {
				if direction == 1 {
					writes = 1 << uint(reg)
				} else {
					reads = 1 << uint(reg)
				}
			}
			if r, w := form.gpEffects(); r != reads || w != writes {
				t.Fatalf("typed GP effects %s: read=%x write=%x", name, r, w)
			}
			if got, valid := arm64RawContinuationEffectsForWord(word); !valid || got != (arm64RawContinuationEffects{gpReads: reads, gpWrites: writes}) {
				t.Fatalf("raw continuation invented an address/store permission: %s %+v %v", name, got, valid)
			}
			if got, valid := arm64RawPoolGPWrites(word); !valid || got != writes {
				t.Fatalf("raw pool GP effects %s: %x %v", name, got, valid)
			}
			if arm64RawPoolInstructionPreservesNZCV(instruction) != (direction == 1) {
				t.Fatalf("raw pool transferred NZCV incorrectly preserves prior comparison: %s", name)
			}
			scratch, valid := arm64ScratchNativeEffect(instruction)
			if !valid || scratch.reads != (reads&(1<<27) != 0) || scratch.defines != (writes&(1<<27) != 0) || scratch.call {
				t.Fatalf("scratch effect %s: %+v %v", name, scratch, valid)
			}
			effect, valid := arm64ScratchNativeInputEffect(instruction, false)
			if reg == 30 || direction == 1 && (reg == 18 || reg == 28) {
				if valid {
					t.Fatal("NZCV transport supplied a new LR or platform/g output permission")
				}
				continue
			}
			want := arm64ScratchInputEffect{reads: uint64(reads), writes: uint64(writes)}
			if direction == 0 {
				want.writes |= 15 << 31
			} else if reg != 31 {
				want.reads |= 15 << 31
			}
			if !valid || effect != want {
				t.Fatalf("whole-input effect %s: %+v %v, want %+v", name, effect, valid, want)
			}
		}
	}
	if body := bodies["zero"]; len(body.code) < 2 || body.code[0] != 0xd51b421f {
		t.Fatal("Go $0 must be the ZR form, not immediate PSTATE grammar")
	}
	for _, word := range []uint32{0xd53b4220, 0xd51b4220, 0xd53b4400, 0xd51b4400, 0xd53bd040, 0xd51bd040, 0xd5000000} {
		if _, valid := decodeARM64RawNZCV(word); valid {
			t.Fatalf("neighbor system register acquired NZCV authority: %08x", word)
		}
	}
	t.Log("65 original Go forms: all 32 Xt fields in both directions plus exact $0 alias")
}

func TestARM64NZCVRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"MRS NZCV,RSP", "MRS NZCV,F0", "MRS NZCV,V0", "MRS NZCV,(R0)",
		"MRS NZCV,$0", "MRS NZCV", "MRS R0,NZCV", "MRS.W NZCV,R0", "MRS.P NZCV,R0",
		"MSR RSP,NZCV", "MSR F0,NZCV", "MSR V0,NZCV", "MSR (R0),NZCV",
		"MSR $1,NZCV", "MSR $-1,NZCV", "MSR $16,NZCV", "MSR NZCV,R0", "MSR.W R0,NZCV",
		"MRS S3_3_C4_C2_0,R0", "MSR R0,S3_3_C4_C2_0",
		"MRS NZCV,R31", "MSR R31,NZCV", "MRS NZCV,R0,R1", "MSR R0,NZCV,R1",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT bad(SB),516,$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}})
			if err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("invalid format must be rejected as syntax, not accepted or Context: %v", err)
			}
		})
	}
}

func TestARM64NZCVTypedControlFlowAndBoundary(t *testing.T) {
	for _, fixture := range []struct {
		name, body string
		closed     bool
	}{
		{"write-read", "MSR R0,NZCV\nMRS NZCV,R0", true},
		{"zero-immediate", "MSR $0,NZCV\nMRS NZCV,R0", true},
		{"raw-write-read", "WORD $0xd51b4200\nWORD $0xd53b4200", true},
		{"compare-read", "CMP R0,R0\nMRS NZCV,R0", true},
		{"discarded-read", "MRS NZCV,ZR", true},
		{"discarded-raw-read", "WORD $0xd53b421f", true},
		{"write-consumers", "MSR R0,NZCV\nCSET CS,R1\nADC R1,R0", true},
		{"backwards", "B set\nread:\nMRS NZCV,R0\nRET\nset:\nMSR R0,NZCV\nB read", true},
		{"both-branches", "CBZ R0,zero\nMSR R0,NZCV\nB read\nzero:\nMSR ZR,NZCV\nread:\nMRS NZCV,R0", true},
		{"loop", "MSR R0,NZCV\nloop:\nMRS NZCV,R1\nCBNZ R0,loop\nMOVD R1,R0", true},
		{"missing-entry", "MRS NZCV,R0", false},
		{"missing-entry-raw", "WORD $0xd53b4200", false},
		{"missing-gp", "MSR R9,NZCV\nMRS NZCV,R0", false},
		{"missing-gp-raw", "WORD $0xd51b4209\nMRS NZCV,R0", false},
		{"missing-platform-input", "MSR R18_PLATFORM,NZCV\nMRS NZCV,R0", false},
		{"missing-g-input", "MSR g,NZCV\nMRS NZCV,R0", false},
		{"missing-fp-input", "MSR R29,NZCV\nMRS NZCV,R0", false},
		{"platform-output", "MSR R0,NZCV\nMRS NZCV,R18_PLATFORM", false},
		{"g-output", "MSR R0,NZCV\nMRS NZCV,g", false},
		{"platform-output-raw", "MSR R0,NZCV\nWORD $0xd53b4212", false},
		{"g-output-raw", "MSR R0,NZCV\nWORD $0xd53b421c", false},
		{"lr-output", "MSR R0,NZCV\nMRS NZCV,R30", false},
		{"lr-output-raw", "MSR R0,NZCV\nWORD $0xd53b421e", false},
		{"partial-join", "CBZ R0,read\nMSR R0,NZCV\nread:\nMRS NZCV,R0", false},
		{"backedge-only", "loop:\nMRS NZCV,R1\nMSR R0,NZCV\nCBNZ R0,loop\nMOVD R1,R0", false},
		{"discard-does-not-define", "MRS NZCV,ZR\nMRS NZCV,R0", false},
		{"fp-control-between", "MSR R0,NZCV\nMRS FPCR,R1\nMRS NZCV,R0", true},
		{"fp-control-raw-between", "MSR R0,NZCV\nWORD $0xd53b4401\nMRS NZCV,R0", true},
		{"opaque-between", "MSR R0,NZCV\nMRS TPIDR_EL0,R1\nMRS NZCV,R0", false},
		{"opaque-raw-between", "MSR R0,NZCV\nWORD $0xd53bd041\nMRS NZCV,R0", false},
		{"closed-local-ret-preserves", "MSR R0,NZCV\nBL helper\nMRS NZCV,R0\nRET\nhelper:\nRET", true},
		{"local-ret-does-not-supply-entry", "BL helper\nMRS NZCV,R0\nRET\nhelper:\nRET", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source := arm64TypedNativeSource(fixture.body)
			arm64TypedNativeGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				opt := arm64TypedNativeOptions(t, target)
				_, textErr := Translate(file, opt)
				public, publicErr := TranslateModule(file, opt)
				if publicErr == nil {
					public.Dispose()
				}
				ctx := llvm.NewContext()
				module, moduleErr := TranslateModuleInContext(ctx, file, opt)
				if moduleErr == nil {
					module.Dispose()
				}
				pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\nfunc NativeEffects(uint64) uint64\n")
				bound, goErr := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
				})
				if bound != nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				for index, err := range []error{textErr, publicErr, moduleErr, goErr} {
					if fixture.closed && err != nil || !fixture.closed && !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s API%d closed=%v: %v", target, index, fixture.closed, err)
					}
				}
			}
		})
	}
}

func TestARM64NZCVTypedAllAPIsAndObjects(t *testing.T) {
	var body strings.Builder
	for _, raw := range []bool{false, true} {
		for reg := 0; reg < 32; reg++ {
			if reg == 18 || reg == 28 || reg == 30 {
				continue // These machine roles need separate entry/return contracts.
			}
			if reg != 31 {
				fmt.Fprintf(&body, "MOVD $0xa0000000,R%d\n", reg)
			}
			fmt.Fprintln(&body, arm64NZCVInstruction(false, raw, reg))
			fmt.Fprintln(&body, arm64NZCVInstruction(true, raw, reg))
		}
	}
	body.WriteString("MRS NZCV,R0\n")
	source := arm64TypedNativeSource(body.String())
	arm64TypedNativeGoObject(t, source)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			opt := arm64TypedNativeOptions(t, target)
			text, err := Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			public, err := TranslateModule(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			publicIR := public.String()
			public.Dispose()
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Fatal(err)
			}
			moduleIR := module.String()
			module.Dispose()
			pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\nfunc NativeEffects(uint64) uint64\n")
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
			})
			if err != nil {
				t.Fatal(err)
			}
			goIR := bound.Module.String()
			bound.Module.Dispose()
			for api, ir := range []string{text, publicIR, moduleIR, goIR} {
				if strings.Contains(ir, "mrs ") || strings.Contains(ir, "msr ") {
					t.Fatal("NZCV transport must not observe incidental backend physical flags")
				}
				compileLLVMToObject(t, llc, target, fmt.Sprintf("nzcv%d.ll", api), "nzcv.o", ir)
			}
		})
	}
}
