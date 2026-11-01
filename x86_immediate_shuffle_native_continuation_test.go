package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The independent complete Go rows and selector oracle live in
// amd64_immediate_shuffle_family_test.go. This matrix closes the missing
// ordinary native-read consumer, not a caller, alignment or raw-entry role.
func x86ImmediateShuffleNativePrograms(arch string) (string, string, int) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source, declarations strings.Builder
	count := 0
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		legacy := !strings.HasPrefix(op, "V")
		for _, bank := range []string{"X", "Y", "Z"} {
			if legacy && bank != "X" {
				continue
			}
			for mode := 0; mode < 3; mode++ {
				if (legacy || arch == "386") && mode != 0 {
					continue // Go's named mode32 arity, not a physical raw restriction.
				}
				for _, broadcast := range []bool{false, true} {
					if broadcast && op != "VPSHUFD" {
						continue
					}
					name := fmt.Sprintf("NativeShuffle%d", count)
					count++
					suffix, mask := "", ""
					if broadcast {
						suffix = ".BCST"
					}
					if mode == 2 {
						suffix += ".Z"
					}
					if mode != 0 {
						mask = "K1,"
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),AX\n%s out+%d(FP),BX\n"+
						"KMOVQ mask+%d(FP),K1\nVXORPS X1,X1,X1\nSTC\n%s%s $27,(AX),%s%s1\n"+
						"VMOVUPS Z1,(BX)\nSETCS 64(BX)\nRET\n",
						name, 2*word+8, move, move, word, 2*word, op, suffix, mask, bank)
					fmt.Fprintf(&declarations, "func %s(input,out *byte,mask uint64)\n", name)
				}
			}
		}
	}
	return source.String(), declarations.String(), count
}

func TestX86ImmediateShuffleInitializedNativeReadCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete native shuffle objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, count := x86ImmediateShuffleNativePrograms(target.arch)
			want := 40
			if target.arch == "386" {
				want = 16
			}
			if count != want {
				t.Fatal("complete source-format denominator changed", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized full-tuple/broadcast shuffle lost its paired native read", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "native-shuffle.ll", "native-shuffle.o", text)
					}
				})
			}
		})
	}
}

func TestX86ImmediateShuffleNativeReadDoesNotInventInputsOrQueryRights(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source, declarations, _ := x86ImmediateShuffleNativePrograms(arch)
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, replacement := range []string{"", move + " $1,AX\n"} {
			changed := strings.ReplaceAll(source, move+" input+0(FP),AX\n", replacement)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("native tuple borrowed missing/merely numerical pointer inputs", arch, api, err)
				}
			}
		}
		instruction := x86ScalarLaneInstruction(t, "VPSHUFD.BCST $27,(AX),Z1")
		state := x86ResultState{flags: x86ByteFlagsAll}
		state.pointerGP[0], state.callerAddressGP[0] = true, true
		if accepted, known := x86ResultImmediateShuffleStep(instruction, &state, nil, arch); accepted || !known {
			t.Fatal("standalone result query acquired a paired native-read contract", arch, accepted, known)
		}
	}
	for _, mutation := range []struct{ before, after string }{
		{"KMOVQ mask+16(FP),K1\n", ""},
		{"VXORPS X1,X1,X1\n", ""},
	} {
		source, declarations, _ := x86ImmediateShuffleNativePrograms("amd64")
		changed := strings.ReplaceAll(source, mutation.before, mutation.after)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("merge shuffle invented actual mask/old-destination bytes", api, err)
			}
		}
	}
}
