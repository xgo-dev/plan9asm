package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func x86RawQQToFloatFixturePrior(t *testing.T, arch string) (string, []byte, int) {
	t.Helper()
	wantSource, wantCode, count := "2d0155befdd249df921df14f13a5be911e7f751dcc2835cb863731b711e15b3d",
		"d755acf6443648ef0cef5b99169df9b14649e5291ec25dfe6f690e7e8a1c4ad1", 76
	if arch == "386" {
		wantSource, wantCode, count = "cc6ced228c80f60bb4e83952a205844cbc1accb590cb54c6c756209cbb84af08",
			"affd0b32e9ed38660b94b8f6f8591c1867d9c5030e5e11f061187c412a664d55", 36
	}
	source := x86RawQQToFloatOriginalSource(arch)
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != wantSource {
		t.Fatal("the original uninitialized QQ-to-float source was changed", arch)
	}
	var code []byte
	for _, line := range strings.Split(source, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "BYTE" {
			value, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "$"), 0, 8)
			if err != nil {
				t.Fatal("original BYTE inventory", err)
			}
			code = append(code, byte(value))
		}
	}
	code = append(code, 0xc3) // Original textual RET, not a native-entry permission.
	if fmt.Sprintf("%x", sha256.Sum256(code)) != wantCode {
		t.Fatal("original raw physical encoding payload was shortened or replaced", arch)
	}
	file := mustParseX86RawReturn(t, source)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil || len(normalized.Funcs) != 1 || len(normalized.Funcs[0].Instrs) != count+2 {
		t.Fatal("original whole QQ-to-float instruction denominator changed", arch, err)
	}
	seen := make(map[string]int)
	for _, instruction := range normalized.Funcs[0].Instrs[1 : count+1] {
		name, _, _ := strings.Cut(string(instruction.Op), ".")
		seen[name]++
	}
	psXY, psZ, pd := 5, 9, 19
	if arch == "386" {
		psXY, psZ, pd = 3, 3, 9
	}
	want := map[string]int{
		"VCVTQQ2PSX": psXY, "VCVTUQQ2PSX": psXY,
		"VCVTQQ2PSY": psXY, "VCVTUQQ2PSY": psXY,
		"VCVTQQ2PS": psZ, "VCVTUQQ2PS": psZ,
		"VCVTQQ2PD": pd, "VCVTUQQ2PD": pd,
	}
	if len(seen) != len(want) {
		t.Fatal("original four semantic families lost one of their eight Go spellings", seen)
	}
	for name, expected := range want {
		if seen[name] != expected {
			t.Fatal("original source lost a width/register/memory/broadcast/mask/ER witness", arch, name, seen[name], expected)
		}
	}
	return source, code, count
}

func x86RawQQToFloatInitializedFixture(t *testing.T, arch string) (string, string, int) {
	t.Helper()
	original, _, count := x86RawQQToFloatFixturePrior(t, arch)
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	const oldHeader = "TEXT rawQQToFloat(SB),$0-0\n"
	header := fmt.Sprintf("TEXT ·rawQQToFloat(SB),4,$0-%d\n%s p+0(FP),AX\n", word, move) +
		"MOVL $1,CX\nKMOVD CX,K4\nKMOVD CX,K7\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
	// Only a separate typed entry/prefix is added. Every original BYTE and the
	// original final RET remain in their original order, including dead effects.
	return header + strings.TrimPrefix(original, oldHeader), "func rawQQToFloat(p *byte)", count
}

func TestX86RawQQToFloatOriginalFixtureInputContract(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, payload, count := x86RawQQToFloatFixturePrior(t, arch)
			actual := x86PackedShiftActualGoBytes(t, arch, source)
			// Go may add a stack-check prologue/tail to the unchanged 386
			// TEXT. Keep that complete object; require the entire original
			// physical instruction payload once, not a truncated prefix.
			if bytes.Count(actual, payload) != 1 {
				t.Fatal("actual Go object lost the complete original raw payload/RET", arch)
			}
			t.Logf("original rows=%d sourceSHA256=%x actualWholeGoCodeSHA256=%x", count,
				sha256.Sum256([]byte(source)), sha256.Sum256(actual))
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func rawQQToFloat()", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("the unchanged format-only Void fixture invented missing inputs", api, err)
					}
				})
			}
		})
	}
}

func TestX86RawQQToFloatInitializedSourceAndMissingInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, declaration, count := x86RawQQToFloatInitializedFixture(t, arch)
			triple, move := "x86_64-unknown-linux-gnu", "MOVQ"
			if arch == "386" {
				triple, move = "i386-unknown-linux-gnu", "MOVL"
			}
			x86LEAActualTargetGoObject(t, arch, triple, source)
			missing := []struct{ name, remove string }{
				{"source-vector", "VPXORD Z1,Z1,Z1\n"},
				{"incoming-pointer", move + " p+0(FP),AX\n"},
			}
			if arch == "amd64" {
				missing = append(missing, struct{ name, remove string }{"mask-K7", "KMOVD CX,K7\n"},
					struct{ name, remove string }{"rounding-mask-K4", "KMOVD CX,K4\n"})
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil || strings.Count(ir, "asm sideeffect") != count {
						t.Fatal("the same complete raw body lost initialized inputs or native MXCSR/access effects", api, err)
					}
					for _, control := range missing {
						t.Run(control.name, func(t *testing.T) {
							changed := strings.Replace(source, control.remove, "", 1)
							if changed == source {
								t.Fatal("missing-input control did not remove its real producer")
							}
							ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void raw conversion borrowed an absent actual input", control.name, api, err)
							}
						})
					}
					ir, err = x86ScalarFPBitViewAPI(t, source, "func rawQQToFloat(p uintptr)", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("an integer address minted incoming-pointer authority", api, err)
					}
				})
			}
		})
	}
}

func TestX86RawQQToFloatInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declaration, count := x86RawQQToFloatInitializedFixture(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized QQ-to-float public program", err)
					}
					optimized := x86DwordProductIROptimize(t, ir)
					for _, pipeline := range []struct{ name, ir, backend string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							if strings.Count(pipeline.ir, "asm sideeffect") != count {
								t.Fatal("optimization removed an original opcode/access/exception effect")
							}
							x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.backend)
						})
					}
				})
			}
		})
	}
}
