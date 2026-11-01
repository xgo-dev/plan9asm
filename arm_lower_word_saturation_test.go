package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

type armSaturationForm struct {
	name        string
	signed      bool
	halfword    bool
	condition   int
	width       int
	destination int
	source      int
	shift       int
	arithmetic  bool
}

func encodeARMRawSaturation(signed, halfword bool, condition, width, destination, source, shift int, arithmetic bool) uint32 {
	base := uint32(0x06a00010)
	if !signed {
		base = 0x06e00010
	}
	field := width
	if signed {
		field--
	}
	word := uint32(condition)<<28 | base | uint32(field)<<16 |
		uint32(destination)<<12 | uint32(source)
	if halfword {
		return word | 0x00000f20
	}
	word |= uint32(shift) << 7
	if arithmetic {
		word |= 1 << 6
	}
	return word
}

func TestARMRawSaturationFamilyCompleteFormats(t *testing.T) {
	forms := []armSaturationForm{
		{name: "ssat-min", signed: true, condition: 14, width: 1, destination: 0, source: 1},
		{name: "ssat-reported", signed: true, condition: 14, width: 16, destination: 0, source: 0},
		{name: "ssat-max-asr32", signed: true, condition: 0, width: 32, destination: 14, source: 0, arithmetic: true},
		{name: "ssat-lsl31", signed: true, condition: 1, width: 8, destination: 1, source: 14, shift: 31},
		{name: "usat-min", condition: 14, width: 0, destination: 0, source: 1},
		{name: "usat-max-asr32", condition: 0, width: 31, destination: 14, source: 0, arithmetic: true},
		{name: "usat-lsl31", condition: 1, width: 8, destination: 1, source: 14, shift: 31},
		{name: "ssat16-min", signed: true, halfword: true, condition: 14, width: 1, destination: 0, source: 1},
		{name: "ssat16-max", signed: true, halfword: true, condition: 0, width: 16, destination: 14, source: 0},
		{name: "usat16-min", halfword: true, condition: 14, width: 0, destination: 0, source: 1},
		{name: "usat16-max", halfword: true, condition: 1, width: 15, destination: 14, source: 0},
	}
	for _, family := range []struct {
		name     string
		signed   bool
		halfword bool
		minWidth int
		maxWidth int
	}{
		{name: "ssat", signed: true, minWidth: 1, maxWidth: 32},
		{name: "usat", minWidth: 0, maxWidth: 31},
		{name: "ssat16", signed: true, halfword: true, minWidth: 1, maxWidth: 16},
		{name: "usat16", halfword: true, minWidth: 0, maxWidth: 15},
	} {
		for width := family.minWidth; width <= family.maxWidth; width++ {
			forms = append(forms, armSaturationForm{
				name:        fmt.Sprintf("%s-width-%d", family.name, width),
				signed:      family.signed,
				halfword:    family.halfword,
				condition:   14,
				width:       width,
				destination: 0,
				source:      1,
			})
		}
		for condition := 0; condition < 15; condition++ {
			forms = append(forms, armSaturationForm{
				name:        fmt.Sprintf("%s-condition-%d", family.name, condition),
				signed:      family.signed,
				halfword:    family.halfword,
				condition:   condition,
				width:       8,
				destination: 2,
				source:      3,
			})
		}
		if !family.halfword {
			for _, shift := range []int{1, 16, 31} {
				forms = append(forms, armSaturationForm{
					name:        fmt.Sprintf("%s-lsl-%d", family.name, shift),
					signed:      family.signed,
					condition:   14,
					width:       8,
					destination: 4,
					source:      5,
					shift:       shift,
				})
			}
			for _, shift := range []int{1, 16, 32} {
				forms = append(forms, armSaturationForm{
					name:        fmt.Sprintf("%s-asr-%d", family.name, shift),
					signed:      family.signed,
					condition:   14,
					width:       8,
					destination: 4,
					source:      5,
					shift:       shift % 32,
					arithmetic:  true,
				})
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT saturationforms(SB),$0-0\n\tCMP R0, R1\n")
	for _, form := range forms {
		word := encodeARMRawSaturation(
			form.signed, form.halfword, form.condition, form.width,
			form.destination, form.source, form.shift, form.arithmetic,
		)
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", word, form.name)
	}
	source.WriteString("\tRET\n")
	requireARMGoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{
			"saturationforms": {Name: "saturationforms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, intrinsic := range []string{
		"@llvm.arm.ssat", "@llvm.arm.usat",
		"@llvm.arm.ssat16", "@llvm.arm.usat16",
	} {
		if !strings.Contains(ir, intrinsic) {
			t.Fatalf("saturation family omitted %s", intrinsic)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"armv7-unknown-linux-gnueabihf",
		"armv7-none-eabi",
		"armv7-unknown-freebsd",
	} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "arm-saturation.ll", "arm-saturation.o", ir)
		})
	}
}

func TestARMRawSaturationRejectsInvalidOperandForms(t *testing.T) {
	for _, instruction := range []string{
		"SSAT R1, $0, R0",
		"SSAT R1, $33, R0",
		"USAT R1, $32, R0",
		"SSAT16 R1, $0, R0",
		"SSAT16 R1, $17, R0",
		"USAT16 R1, $16, R0",
		"SSAT R15, $8, R0",
		"USAT R1, $8, R15",
		"SSAT R1>>1, $8, R0",
		"SSAT R1<<R2, $8, R0",
		"SSAT R1<<32, $8, R0",
		"USAT R1->0, $8, R0",
		"USAT R1->33, $8, R0",
		"SSAT16 R1<<1, $8, R0",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT invalid(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				Goarch:       "arm",
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{
					"invalid": {Name: "invalid", Ret: Void},
				},
			})
			if err == nil {
				t.Fatalf("Translate accepted invalid saturation form %q", instruction)
			}
		})
	}
}

func armSaturationRuntimeFixture() (string, map[string]FuncSig, string) {
	forms := []struct {
		name       string
		signed     bool
		halfword   bool
		width      int
		shift      int
		arithmetic bool
		condition  int
	}{
		{name: "ssat_scalar", signed: true, width: 16, condition: 14},
		{name: "usat_scalar", width: 8, condition: 14},
		{name: "ssat_pair", signed: true, halfword: true, width: 8, condition: 14},
		{name: "usat_pair", halfword: true, width: 8, condition: 14},
		{name: "ssat_asr32", signed: true, width: 1, arithmetic: true, condition: 14},
		{name: "usat_lsl1", width: 8, shift: 1, condition: 14},
		{name: "ssat_equal", signed: true, width: 16, condition: 0},
		{name: "ssat_not_equal", signed: true, width: 16, condition: 1},
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig, len(forms))
	for _, form := range forms {
		fmt.Fprintf(&source, "TEXT %s(SB),$0-8\n", form.name)
		source.WriteString("\tMOVW value+0(FP), R1\n")
		if form.condition != 14 {
			source.WriteString("\tMOVW R1, R0\n\tCMP R1, R1\n")
		}
		word := encodeARMRawSaturation(
			form.signed, form.halfword, form.condition, form.width,
			0, 1, form.shift, form.arithmetic,
		)
		fmt.Fprintf(&source, "\tWORD $%#08x\n\tMOVW R0, ret+4(FP)\n\tRET\n", word)
		sigs[form.name] = FuncSig{
			Name: form.name, Args: []LLVMType{I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
			},
		}
	}
	const checks = `#include <stdint.h>
#include <stdio.h>

extern uint32_t ssat_scalar(uint32_t);
extern uint32_t usat_scalar(uint32_t);
extern uint32_t ssat_pair(uint32_t);
extern uint32_t usat_pair(uint32_t);
extern uint32_t ssat_asr32(uint32_t);
extern uint32_t usat_lsl1(uint32_t);
extern uint32_t ssat_equal(uint32_t);
extern uint32_t ssat_not_equal(uint32_t);

static int32_t signed_saturate(int32_t value, int width) {
    int32_t limit = (int32_t)(1u << (width - 1));
    if (value < -limit) {
        return -limit;
    }
    if (value > limit - 1) {
        return limit - 1;
    }
    return value;
}

static uint32_t unsigned_saturate(int32_t value, int width) {
    uint32_t limit = (1u << width) - 1;
    if (value < 0) {
        return 0;
    }
    if ((uint32_t)value > limit) {
        return limit;
    }
    return (uint32_t)value;
}

static uint32_t pair_saturate(uint32_t value, int is_signed) {
    uint32_t result = 0;
    for (int lane = 0; lane < 2; lane++) {
        int32_t input = (int16_t)(value >> (lane * 16));
        uint32_t output = is_signed
            ? (uint16_t)signed_saturate(input, 8)
            : unsigned_saturate(input, 8);
        result |= (output & 0xffffu) << (lane * 16);
    }
    return result;
}

int main(void) {
    const uint32_t inputs[] = {
        0u, 1u, 127u, 255u, 256u, 32767u, 32768u,
        0xffffffffu, 0x80000000u, 0x80008000u, 0x7fff7fffu, 0x1234fedcu,
    };
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        uint32_t value = inputs[i];
        if (ssat_scalar(value) != (uint32_t)signed_saturate((int32_t)value, 16)) {
            return 1;
        }
        if (usat_scalar(value) != unsigned_saturate((int32_t)value, 8)) {
            return 2;
        }
        if (ssat_pair(value) != pair_saturate(value, 1)) {
            return 3;
        }
        if (usat_pair(value) != pair_saturate(value, 0)) {
            return 4;
        }
        if (ssat_asr32(value) != (uint32_t)((int32_t)value < 0 ? -1 : 0)) {
            return 5;
        }
        if (usat_lsl1(value) != unsigned_saturate((int32_t)(value << 1), 8)) {
            return 6;
        }
        if (ssat_equal(value) != (uint32_t)signed_saturate((int32_t)value, 16)) {
            return 7;
        }
        if (ssat_not_equal(value) != value) {
            return 8;
        }
    }
    return 0;
}
`
	return source.String(), sigs, checks
}

func TestARMRawSaturationRuntimeCross(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("actual ARM execution is required by the Linux cross-runtime job")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatalf("cross-execution driver requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, name := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required tool %s: %v", name, err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, sigs, checks := armSaturationRuntimeFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(
		t, llc, []string{"arm-linux-gnueabihf-gcc"},
		"arm_raw_saturation", triple, ir, checks,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"},
	)
}
