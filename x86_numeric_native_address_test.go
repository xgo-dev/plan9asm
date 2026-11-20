package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func x86RequireNumericNativeSourceContext(t *testing.T, source, declaration, arch string) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "numeric", "package numeric\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		if err := CheckX86ABI0ResultInitialization(fn, signatures[resolve(fn.Sym)], arch); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("paired numerical address became a standalone result or storage proof", err)
		}
	}
}

func x86NumericNativeAddressObject(t *testing.T, ir, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
}

// E4NF may load one typed tuple; masked E4 loads one integer per active
// lane. Count the potential bytes in either IR representation independently
// of the production memory-shape parser. This is not an execution count.
func x86NumericNativeVolatileReadBytes(t *testing.T, ir string) int {
	t.Helper()
	bytes := 0
	for _, match := range regexp.MustCompile(`load volatile (?:i([0-9]+)|<([0-9]+) x i([0-9]+)>),`).FindAllStringSubmatch(ir, -1) {
		lanes, bits := 1, match[1]
		if match[2] != "" {
			var err error
			lanes, err = strconv.Atoi(match[2])
			if err != nil {
				t.Fatal(err)
			}
			bits = match[3]
		}
		width, err := strconv.Atoi(bits)
		if err != nil || width%8 != 0 || width <= 0 {
			t.Fatal("unexpected volatile integer read type", match[0], err)
		}
		bytes += lanes * width / 8
	}
	return bytes
}

// A numerical-base variant changes address bits, not the original memory
// operations. Keep widths, access order/count, volatile markers and exact asm
// constraints equal to the initialized-pointer counterpart; SSA names differ.
func x86RequireSameNativeMemoryEffects(t *testing.T, before, after string) {
	t.Helper()
	effects := func(ir string) []string {
		var result []string
		pattern := regexp.MustCompile(`(?:load|store) volatile (?:<[^>]+>|i[0-9]+|float|double)|asm sideeffect "(?:\\.|[^"\\])*", "(?:\\.|[^"\\])*"`)
		for _, line := range strings.Split(ir, "\n") {
			if match := pattern.FindString(line); match != "" {
				if strings.HasPrefix(match, "asm ") && (!strings.Contains(match, "~{memory}") || strings.Contains(match, `asm sideeffect ""`)) {
					continue // Register-only FP exceptions and empty barriers are not memory accesses.
				}
				result = append(result, match)
			}
		}
		return result
	}
	want, got := effects(before), effects(after)
	if len(want) == 0 || !reflect.DeepEqual(want, got) {
		t.Fatal("numerical address changed its original native memory effects", want, got)
	}
}

// An initialized machine address can arrive as uintptr or as loaded bits.
// This does not turn it into a logical pointer or prove any pointee bytes.
func TestX86InitializedNumericNativeAddressesThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := x86ResultPointerWord(target.arch), "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		input := move + " p+0(FP),AX\n"
		rows := []struct {
			name, declaration, body string
			accept                  bool
		}{
			{"uintptr-load", "func Value(p uintptr) uint32", input + "MOVL (AX),CX\n", true},
			{"loaded-address", "func Value(p *uintptr) uint32", input + move + " (AX),AX\nMOVL (AX),CX\n", true},
			{"uintptr-store", "func Value(p uintptr) uint32", input + "MOVL $42,(AX)\nMOVL $42,CX\n", true},
			{"loaded-address-store", "func Value(p *uintptr) uint32", input + move + " (AX),AX\nMOVL $42,(AX)\nMOVL $42,CX\n", true},
			{"known-null-load", "func Value(p uintptr) uint32", move + " $0,AX\nMOVL (AX),CX\n", true},
			{"unknown-base", "func Value(p uintptr) uint32", "MOVL (AX),CX\n", false},
			{"partial-base", "func Value(p uintptr) uint32", "MOVB p+0(FP),AX\nMOVL (AX),CX\n", false},
			{"unknown-store-value", "func Value(p uintptr) uint32", input + "MOVL DX,(AX)\nMOVL $42,CX\n", false},
		}
		for _, row := range rows {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				body := row.body + fmt.Sprintf("MOVL CX,ret0+%d(FP)\nRET", word)
				_, file, sig, source := x86ResultInitializationFixture(t, target.arch, row.declaration, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone query acquired a native-memory observation", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
						if !row.accept {
							if err == nil || ir != "" {
								t.Fatal("undefined address/value input accepted", err)
							}
							return
						}
						if err != nil || !strings.Contains(ir, "volatile") {
							t.Fatal("initialized machine address lost its native memory effect", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					})
				}
			})
		}
	}
}
