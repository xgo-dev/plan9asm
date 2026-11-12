package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86LockScalarRMWAddressLiteralIsNotMemory(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LockScalarOracleForms(arch) {
			body := strings.Replace(row.text, "1(SI)", "$·cell(SB)", 1)
			t.Run(arch+"/"+body, func(t *testing.T) {
				source := "GLOBL ·cell(SB),8,$16\n" +
					x86NamedLockOracleSource(arch, "CLC\nLOCK\n"+body)
				// An emitted address literal is Go TYPE_ADDR, not writable
				// memory. This is actual assembler rejection, not execution.
				goAssemblerOracleOutput(t, arch, source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[len(file.Funcs[0].Instrs)-2]
				form, recognized, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
				if !recognized || err == nil {
					t.Error("typed memory grammar accepted an address literal", form, err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86OrderingHintTranslateAPI(t, api, source,
						"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
					if err == nil || ir != "" {
						t.Error("address literal became a locked memory object", api, err)
					}
				}
				ordinary := strings.Replace(source, "$·cell(SB)", "·cell(SB)", 1)
				x86LockScalarOriginalInstruction(t, arch, ordinary)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86OrderingHintTranslateAPI(t, api, ordinary,
						"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
					// This exact original source declares RODATA. Go format
					// acceptance does not make its storage writable.
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Error("original readonly SB source acquired a write permission", api, err)
					}
				}
			})
		}
	}
}

func TestX86StaticBitStringLockedAndVolatileObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		for _, locked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/locked=%t", target.triple, locked), func(t *testing.T) {
				var source, declarations strings.Builder
				source.WriteString("DATA ·cell+0(SB)/8,$0x1234\nDATA ·cell+8(SB)/8,$0x5678\nGLOBL ·cell(SB),16,$16\n")
				declarations.WriteString("package ordering\n")
				var names []string
				for _, row := range x86LockScalarOracleForms(target.arch) {
					if !strings.HasPrefix(row.op, "BT") {
						continue
					}
					name := fmt.Sprintf("staticBit%d", len(names))
					names = append(names, name)
					body := strings.Replace(row.text, "1(SI)", "·cell(SB)", 1)
					if locked {
						body = "LOCK\n" + body
					}
					original := x86NamedLockOracleSource(target.arch, "CLC\n"+body)
					original = strings.Replace(original, "·locked", "·"+name, 1)
					// The register-indexed rows consume an actual unbounded Go
					// numerical input. No constant or fixed-span range is assumed.
					if target.arch == "amd64" {
						original = strings.Replace(original, "$0-8", "$0-16", 1)
						original = strings.Replace(original, "MOVL $4,CX", "MOVQ index+8(FP),CX", 1)
						fmt.Fprintf(&declarations, "func %s(p *[16]byte, index uint64)\n", name)
					} else {
						original = strings.Replace(original, "$0-4", "$0-8", 1)
						original = strings.Replace(original, "MOVL $4,CX", "MOVL index+4(FP),CX", 1)
						fmt.Fprintf(&declarations, "func %s(p *[16]byte, index uint32)\n", name)
					}
					source.WriteString(original)
				}
				want := 18
				if target.arch == "386" {
					want = 12
				}
				if len(names) != want || len(names) > 32 {
					t.Fatal("complete original bit-string object batch changed", len(names), want)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
						if err != nil {
							t.Fatal("complete native static bit-string source", err)
						}
						if !locked {
							for _, name := range names {
								body := x86StringMemoryFunction(t, ir, name)
								if !strings.Contains(body, "load volatile") || !strings.Contains(body, "store volatile") {
									t.Fatal("unlocked bit-string lost an actual native memory effect", name)
								}
							}
						}
						for _, level := range []int{0, 2} {
							text := ir
							if level == 2 {
								text = x86MulDivRoundOptimize(t, ir)
							}
							x86PackedStringCompileObject(t, llc, target.triple, text, fmt.Sprintf("-O%d", level))
						}
					})
				}
			})
		}
	}
}

// Keep the original readonly/address-literal source above. These are new
// positive TDD controls, not evidence that the current consumer supports them.
// Partitioning preserves all original forms, including signed dynamic indexes.
func TestX86LockScalarRMWMutableSBOriginalForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		forms := x86LockScalarOracleForms(arch)
		groups := make(map[string][]x86LockScalarOracleForm)
		for _, row := range forms {
			partition := "scalar"
			if strings.HasPrefix(row.op, "BTC") || strings.HasPrefix(row.op, "BTR") || strings.HasPrefix(row.op, "BTS") {
				operands := strings.SplitN(row.text, " ", 2)
				if len(operands) != 2 {
					t.Fatal("original bit-string row lost its operands", row.text)
				}
				index := strings.SplitN(operands[1], ",", 2)[0]
				switch index {
				case "$1":
					partition = "bit-immediate"
				case "CX":
					partition = "bit-register"
				default:
					t.Fatal("original bit-string index inventory changed", row.text)
				}
			}
			groups[partition] = append(groups[partition], row)
		}
		wantAll, wantScalar, wantBits := 90, 72, 9
		if arch == "386" {
			wantAll, wantScalar, wantBits = 66, 54, 6
		}
		if len(forms) != wantAll || len(groups["scalar"]) != wantScalar ||
			len(groups["bit-immediate"]) != wantBits || len(groups["bit-register"]) != wantBits {
			t.Fatal("complete original scalar/bit-string partition changed", arch,
				len(forms), len(groups["scalar"]), len(groups["bit-immediate"]), len(groups["bit-register"]))
		}
		for _, partition := range []string{"scalar", "bit-immediate", "bit-register"} {
			t.Run(arch+"/"+partition, func(t *testing.T) {
				for _, row := range groups[partition] {
					body := strings.Replace(row.text, "1(SI)", "·cell(SB)", 1)
					if body == row.text {
						t.Fatal("original memory operand was not replaced", row.text)
					}
					t.Run(body, func(t *testing.T) {
						// DATA covers the actual complete 16-byte mutable object.
						// This does not prove a register-indexed bit string's range.
						source := "DATA ·cell+0(SB)/8,$0x1234\n" +
							"DATA ·cell+8(SB)/8,$0x5678\n" +
							"GLOBL ·cell(SB),16,$16\n" +
							x86NamedLockOracleSource(arch, "CLC\nLOCK\n"+body)
						listing, err := x86ScalarLiteralGoListing(t, arch, source)
						if err != nil {
							t.Fatal("complete mutable original Go object", err)
						}
						x86GPSegmentListingBytes(t, listing, []string{"locked"})
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86OrderingHintTranslateAPI(t, api, source,
								"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
							if err != nil {
								t.Error("complete mutable original SB row lacks its atomic effect", api, err)
								continue
							}
							// A module containing an uncalled helper is not coverage.
							// Follow this exact public body to its actual native helper.
							caller := x86StringMemoryFunction(t, ir, "locked")
							const prefix = "@__plan9asm_lock_rmw_"
							if strings.Count(caller, prefix) != 1 {
								t.Error("mutable original SB body bypassed its complete helper", api)
								continue
							}
							call := caller[strings.Index(caller, prefix)+1:]
							end := strings.Index(call, "(")
							if end < 0 {
								t.Fatal("called native helper lacks its argument list", api)
							}
							helper := x86StringMemoryFunction(t, ir, call[:end])
							if !strings.Contains(helper, "asm sideeffect") ||
								!strings.Contains(helper, "lock; "+strings.ToLower(row.op)) {
								t.Error("actually called helper lost the exact native SB effect", api)
							}
						}
					})
				}
			})
		}
	}
}
