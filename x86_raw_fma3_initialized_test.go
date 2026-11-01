package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RawFMA3InitializedSource(row x86RawFMA3SourceCase, arch, name, control string, dead bool) (string, string) {
	word, move, suffix := goWordSize(arch), "MOVQ", "Q"
	if arch == "386" {
		move, suffix = "MOVL", "L"
	}
	first, second, destination := row.registers()
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", name, 4*word+8)
	for index, input := range []struct{ name, register string }{
		{"first", "AX"}, {"second", "BX"}, {"old", "CX"}, {"out", "DI"},
	} {
		if control == "address" && index == 0 {
			continue
		}
		if control == "numeric address" && index == 0 {
			source.WriteString("MOVL $42,AX\n")
			continue
		}
		fmt.Fprintf(&source, "%s %s+%d(FP),%s\n", move, input.name, index*word, input.register)
	}
	if !row.memory && control != "first" {
		fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", first)
	}
	if control != "second" {
		fmt.Fprintf(&source, "VMOVUPS (BX),Z%d\n", second)
	}
	if control != "old" {
		fmt.Fprintf(&source, "VMOVUPS (CX),Z%d\n", destination)
	}
	if control != "mask" {
		fmt.Fprintf(&source, "KMOVW mask+%d(FP),K1\n", 4*word)
	}
	source.WriteString("MOVL $3,DX\nCMPL DX,$3\nSTD\n")
	if control == "named" {
		source.WriteString(row.instruction() + "\n")
	} else {
		source.WriteString(x86RawDisplacementDirectives(row.code()))
	}
	if !dead {
		fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\n", destination)
	}
	fmt.Fprintf(&source, "PUSHF%s\nPOP%s DX\nANDL $0xcd5,DX\nMOVL DX,64(DI)\nCLD\nRET\n", suffix, suffix)
	declaration := fmt.Sprintf("func %s(first,second,old,out *[128]byte,mask uint64)\n", name)
	return source.String(), declaration
}

// One representative per name plus twelve orthogonal memory/mask/BCST/ER
// witnesses. The complete 528-row directory is exercised by the independent
// physical prior and typed tests, not an unbounded object Cartesian product.
func x86RawFMA3ObjectCases() []x86RawFMA3SourceCase {
	var rows []x86RawFMA3SourceCase
	seen := make(map[string]bool)
	for _, row := range x86RawFMA3SourceCases() {
		if seen[row.op] {
			continue
		}
		seen[row.op] = true
		row.evex = len(rows)%2 != 0
		rows = append(rows, row)
	}
	for _, order := range []string{"132", "213", "231"} {
		for _, suffix := range []string{"PS", "PD", "SS", "SD"} {
			for _, candidate := range x86RawFMA3SourceCases() {
				if candidate.op != "VFMADD"+order+suffix || candidate.high {
					continue
				}
				if candidate.scalar() && candidate.control == "RU_SAE" ||
					!candidate.scalar() && candidate.control == "BCST" {
					rows = append(rows, candidate)
					break
				}
			}
		}
	}
	return rows
}

func TestX86RawFMA3SameSourceNamedInitializedControls(t *testing.T) {
	rows := x86RawFMA3ObjectCases()
	if len(rows) != 72 {
		t.Fatal("bounded complete-name object directory changed", len(rows))
	}
	var source, declarations strings.Builder
	for index, row := range rows {
		body, declaration := x86RawFMA3InitializedSource(row, "amd64", fmt.Sprint("Control", index), "named", index%2 != 0)
		source.WriteString(body)
		declarations.WriteString(declaration)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("same-source named FMA lost initialized arithmetic, native pointer, mask or FLAGS facts", err)
			}
		})
	}
}

func TestX86RawFMA3InitializedFiveTargetsBatch00(t *testing.T) {
	x86RawFMA3InitializedObjectBatch(t, 0)
}

func TestX86RawFMA3InitializedFiveTargetsBatch01(t *testing.T) {
	x86RawFMA3InitializedObjectBatch(t, 1)
}

func x86RawFMA3InitializedObjectBatch(t *testing.T, batch int) {
	t.Helper()
	rows := x86RawFMA3ObjectCases()
	if len(rows) != 72 || batch < 0 || batch > 1 {
		t.Fatal("incomplete bounded original raw FMA object directory", len(rows), batch)
	}
	rows = rows[batch*36 : (batch+1)*36]
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			expected := make(map[string]int)
			forced := make(map[string]int)
			for index, row := range rows {
				body, declaration := x86RawFMA3InitializedSource(row, target.arch,
					fmt.Sprint("RawFMA", batch*36+index), "", index%2 != 0)
				source.WriteString(body)
				declarations.WriteString(declaration)
				expected[strings.ToLower(row.op)]++
				if row.evex && row.bank != "Z" && row.mask == 0 && row.control == "" {
					forced[strings.ToLower(row.op)]++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized original raw FMA has no paired native result continuation", err)
					}
					for name, want := range expected {
						count, force := 0, 0
						for _, line := range strings.Split(ir, "\n") {
							if !strings.Contains(line, "asm sideeffect") || !strings.Contains(line, name+" ") {
								continue
							}
							count++
							if strings.Contains(line, "{evex} "+name+" ") {
								force++
							}
							if !strings.Contains(line, "~{fpsr}") || !strings.Contains(line, "~{memory}") || strings.Contains(line, "~{flags}") {
								t.Fatal("raw FMA lost native exceptions/access or changed FLAGS", name, line)
							}
						}
						if count != want || force != forced[name] {
							t.Fatal("raw FMA lost a live/dead opcode or its physical generation", name, count, want, force, forced[name])
						}
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "raw-fma-source.ll", "raw-fma-source.o", body)
					}
				})
			}
		})
	}
}

func TestX86RawFMA3DeadAndUnusedBoolRequireActualInputs(t *testing.T) {
	for _, row := range x86RawFMA3ObjectCases() {
		for _, control := range []string{"", "first", "second", "old", "mask", "address", "numeric address"} {
			if control == "first" && row.memory || control == "mask" && row.mask == 0 ||
				(control == "address" || control == "numeric address") && !row.memory {
				continue
			}
			t.Run(row.instruction()+"/"+control, func(t *testing.T) {
				for _, arch := range []string{"386", "amd64"} {
					for _, unused := range []bool{false, true} {
						source, declaration := x86RawFMA3InitializedSource(row, arch, "Value", control, true)
						if unused {
							extent := 4*goWordSize(arch) + 8
							source = strings.Replace(source, fmt.Sprintf("$0-%d\n", extent), fmt.Sprintf("$0-%d\n", extent+1), 1)
							declaration = strings.Replace(declaration, "mask uint64)", "mask uint64,unused bool)", 1)
						}
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api)
							if control == "" {
								if err != nil || ir == "" {
									t.Fatal("complete dead/unused-bool raw FMA must remain a positive", arch, unused, api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("raw FMA acquired an absent arithmetic input, old destination, mask or native pointer", arch, unused, api, err)
							}
						}
					}
				}
			})
		}
	}
}
