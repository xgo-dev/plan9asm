package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type x86GPSegmentFixture struct {
	x86GPFaultingFixture
	segment, address, equivalent string
}

func x86GPSegmentSource(row x86GPFaultingReadCase, arch, name, segment, address, omission string, live bool) x86GPSegmentFixture {
	kind := address
	if kind == "fixed-one" {
		kind = "fixed-zero"
	}
	setup, memory := x86SegmentMOVAddress(arch, segment, kind)
	if address == "fixed-one" {
		memory = "1(" + segment + ")"
	}
	memory = strings.ReplaceAll(memory, "BX", "DX")
	missing := omission
	if omission == "offset" {
		missing = "base"
	}
	fixture := x86GPFaultingSource(row, arch, name, missing, false, live)
	fixture.source = strings.Replace(fixture.source,
		strings.Replace(row.instruction, "MEM", "(DX)", 1),
		strings.Replace(row.instruction, "MEM", memory, 1), 1)
	if omission != "pointer-offset" {
		fixture.declaration = strings.Replace(fixture.declaration, "*[32]byte", "uintptr", 1)
	}
	if setup == "" {
		move := "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		fixture.source = strings.Replace(fixture.source, move+" p+0(FP),DX\n", "", 1)
	}
	fixture.accept = omission == ""
	fixture.label = fmt.Sprintf("%s/%s/live=%t/%s", segment, address, live, omission)
	equivalent := ""
	if strings.HasPrefix(address, "segment-index-scale") {
		equivalent = fmt.Sprintf("%s/%s/%s/live=%t/%s", row.family, row.instruction, segment, live, omission)
	}
	return x86GPSegmentFixture{fixture, segment, address, equivalent}
}

// Read bytes from the independent real Go assembler listing. This deliberately
// does not call a production source/operand-normalization observer.
func x86GPSegmentListingBytes(t *testing.T, listing string, names []string) map[string][]byte {
	t.Helper()
	header := regexp.MustCompile(`^(\S+) STEXT\b.*\bsize=(\d+)`)
	wanted := make(map[string]bool)
	for _, name := range names {
		wanted[name] = true
	}
	code := make(map[string][]byte)
	sizes := make(map[string]int)
	current := ""
	for _, line := range strings.Split(listing, "\n") {
		if match := header.FindStringSubmatch(line); len(match) != 0 {
			current = strings.TrimSuffix(match[1], "<ABI0>")
			// Go 1.20 retains the empty assembler package name in -S output.
			current = strings.TrimPrefix(strings.TrimPrefix(current, "literal."), `"".`)
			if wanted[current] {
				var err error
				sizes[current], err = strconv.Atoi(match[2])
				if err != nil || sizes[current] == 0 {
					t.Fatal("invalid actual Go text size", line, err)
				}
			}
			continue
		}
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			current = "" // A following data symbol is outside this TEXT body.
			continue
		}
		fields := strings.Fields(line)
		if !wanted[current] || len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") {
			continue
		}
		var row []byte
		for _, field := range fields[1:] {
			if len(field) != 2 {
				break
			}
			value, err := hex.DecodeString(field)
			if err != nil {
				break
			}
			row = append(row, value[0])
		}
		if len(row) == 0 {
			continue // Source instruction rows are not encoded-byte rows.
		}
		offset, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 64)
		if err != nil || int(offset) != len(code[current]) {
			t.Fatal("noncontiguous actual Go bytes", current, line, err)
		}
		code[current] = append(code[current], row...)
	}
	for _, name := range names {
		if len(code[name]) == 0 || len(code[name]) != sizes[name] {
			t.Fatal("actual Go listing lost a complete source function", name, len(code[name]), sizes[name])
		}
	}
	return code
}

func x86GPSegmentGoObjects(t *testing.T, arch string, fixtures []x86GPSegmentFixture) map[string][]byte {
	t.Helper()
	all := make(map[string][]byte)
	for start := 0; start < len(fixtures); start += 32 {
		end := start + 32
		if end > len(fixtures) {
			end = len(fixtures)
		}
		// The source/object helpers own TempDirs. Give each bounded batch
		// its own cleanup scope instead of retaining all objects at the root.
		if !t.Run(fmt.Sprintf("go-source-batch%d", start/32), func(t *testing.T) {
			var source strings.Builder
			var names []string
			for _, fixture := range fixtures[start:end] {
				source.WriteString(fixture.source)
				names = append(names, fixture.name)
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal("original complete segment source must assemble before classification", err)
			}
			for name, code := range x86GPSegmentListingBytes(t, listing, names) {
				all[name] = code
			}
		}) {
			t.Fatal("original complete segment source batch failed", start, end)
		}
	}
	return all
}

func TestX86GPFaultingReadSegmentInputs(t *testing.T) {
	x86GPSegmentInputs(t, x86GPFaultingReadCases, map[string]x86GPSegmentInputCount{
		"amd64": {95, 9112, 1424, 27336},
		"386":   {67, 6488, 1012, 19464},
	})
}

type x86GPSegmentInputCount struct {
	rows, fixtures, scaleClasses, apiChecks int
}

// Hash every original case and role in order, including the source and Go
// declaration. This is an observation of the test matrix, not a production
// instruction directory or a substitute for executing its API assertions.
func x86GPSegmentInputIdentity(fixtures []x86GPSegmentFixture) string {
	digest := sha256.New()
	for _, fixture := range fixtures {
		fmt.Fprintf(digest, "%q\n%q\n%q\n%q\n%q\n%q\n%q\n%t\n%#v\n",
			fixture.name, fixture.source, fixture.declaration,
			fixture.segment, fixture.address, fixture.equivalent,
			fixture.label, fixture.accept, fixture.row)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func x86GPSegmentInputs(t *testing.T, rows func(string) []x86GPFaultingReadCase, expected map[string]x86GPSegmentInputCount) {
	t.Helper()
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			want, found := expected[arch]
			if !found || len(expected) != 2 {
				t.Fatal("missing independent segment matrix count", arch)
			}
			originalRows := rows(arch)
			if len(originalRows) != want.rows {
				t.Fatal("complete segment source-row denominator changed", len(originalRows), want.rows)
			}
			var fixtures []x86GPSegmentFixture
			addresses := []string{"fixed-zero", "fixed-one", "fixed", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"}
			for _, row := range originalRows {
				for _, segment := range []string{"FS", "GS"} {
					for _, address := range addresses {
						omissions := []string{""}
						if address == "base" || strings.HasPrefix(address, "segment-index-") {
							omissions = append(omissions, "offset", "pointer-offset")
						}
						if row.partner {
							omissions = append(omissions, "partner")
						}
						if row.carry {
							omissions = append(omissions, "carry")
						}
						if row.accumulator {
							omissions = append(omissions, "accumulator")
						}
						if row.index {
							omissions = append(omissions, "bit-index")
						}
						for _, live := range []bool{false, true} {
							for _, omission := range omissions {
								name := fmt.Sprintf("Segment%d", len(fixtures))
								fixtures = append(fixtures, x86GPSegmentSource(row, arch, name, segment, address, omission, live))
							}
						}
					}
				}
			}
			if len(fixtures) != want.fixtures {
				t.Fatal("complete segment scenario denominator changed", len(fixtures), want.fixtures)
			}
			identity := x86GPSegmentInputIdentity(fixtures)
			goBytes := x86GPSegmentGoObjects(t, arch, fixtures)
			groups := make(map[string][]byte)
			groupCount := make(map[string]int)
			for _, fixture := range fixtures {
				if fixture.equivalent == "" {
					continue
				}
				if previous := groups[fixture.equivalent]; previous != nil && !bytes.Equal(previous, goBytes[fixture.name]) {
					t.Fatal("actual Go segment annotation scales changed machine bytes", fixture.equivalent)
				}
				groups[fixture.equivalent] = goBytes[fixture.name]
				groupCount[fixture.equivalent]++
			}
			for group, count := range groupCount {
				if count != 4 {
					t.Fatal("incomplete actual Go scale equivalence class", group, count)
				}
			}
			if len(groups) != want.scaleClasses {
				t.Fatal("complete segment scale-class denominator changed", len(groups), want.scaleClasses)
			}
			t.Logf("SEGMENT_ACTUAL_GO_ALL_ACCEPTED arch=%s functions=%d scale_classes=%d", arch, len(fixtures), len(groups))
			bodies := make(map[string]string)
			executed, verified := 0, 0
			for start := 0; start < len(fixtures); start += 32 {
				end := start + 32
				if end > len(fixtures) {
					end = len(fixtures)
				}
				t.Run(fmt.Sprintf("input-batch%d", start/32), func(t *testing.T) {
					current := "before first case"
					t.Cleanup(func() {
						if t.Failed() {
							t.Log("SEGMENT_CASE_WHEN_FAILED", current)
						}
					})
					for _, fixture := range fixtures[start:end] {
						for _, api := range []string{"text", "module", "Go"} {
							current = fmt.Sprintf("arch=%s function=%s family=%s instruction=%q %s api=%s target=%s",
								arch, fixture.name, fixture.row.family, fixture.row.instruction, fixture.label, api, testTargetTriple("linux", arch))
							ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, arch, testTargetTriple("linux", arch), api)
							executed++
							if !fixture.accept {
								if err == nil && ir != "" {
									t.Error("SEGMENT_MISSING_INPUT_ACCEPTED", current, fixture.source)
								} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
									t.Error("SEGMENT_NEGATIVE_WRONG_CLASS", current, err, fixture.source)
								} else {
									verified++
								}
								continue
							}
							if err != nil || ir == "" {
								t.Error("SEGMENT_INITIALIZED_POSITIVE_REJECTED", current, err, fixture.source)
								continue
							}
							if fixture.equivalent != "" {
								body := x86StringMemoryFunction(t, ir, fixture.name)
								body = strings.ReplaceAll(strings.SplitN(body, "\n", 2)[1], fixture.name, "FUNCTION")
								key := api + "/" + fixture.equivalent
								if previous, exists := bodies[key]; exists && previous != body {
									t.Error("PUBLIC_SEGMENT_SCALE_IR_DIVERGED", current, key, previous, body)
									continue
								}
								bodies[key] = body
							}
							verified++
						}
					}
				})
			}
			if executed != want.apiChecks || verified != want.apiChecks {
				t.Error("segment API matrix incomplete", arch, "executed", executed, "verified", verified, "expected", want.apiChecks)
			}
			if after := x86GPSegmentInputIdentity(fixtures); after != identity {
				t.Error("original segment source matrix changed during execution", identity, after)
			}
			t.Logf("SEGMENT_MATRIX_CLOSED arch=%s functions=%d api_checks=%d verified=%d source_sha256=%s",
				arch, len(fixtures), executed, verified, identity)
		})
	}
}

func TestX86GPFaultingReadSegmentObjects(t *testing.T) {
	x86GPSegmentObjects(t, x86GPFaultingReadCases)
}

func x86GPSegmentObjects(t *testing.T, rows func(string) []x86GPFaultingReadCase) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var fixtures []x86GPSegmentFixture
			for _, row := range rows(target.arch) {
				for _, segment := range []string{"FS", "GS"} {
					for _, address := range []string{"fixed-zero", "segment-index-scale8"} {
						name := fmt.Sprintf("Access%d", len(fixtures))
						fixtures = append(fixtures, x86GPSegmentSource(row, target.arch, name, segment, address, "", false))
					}
				}
			}
			for start := 0; start < len(fixtures); start += 32 {
				end := start + 32
				if end > len(fixtures) {
					end = len(fixtures)
				}
				t.Run(fmt.Sprintf("batch%d", start/32), func(t *testing.T) {
					batch := fixtures[start:end]
					x86GPSegmentGoObjects(t, target.arch, batch)
					var source, declarations strings.Builder
					var names []string
					for _, fixture := range batch {
						source.WriteString(fixture.source)
						declarations.WriteString(fixture.declaration + "\n")
						names = append(names, fixture.name)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("SEGMENT_INITIALIZED_BATCH_REJECTED", err)
							}
							for _, view := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
								bodies := x86StringMemoryFunctions(t, view, names)
								for _, fixture := range batch {
									body := bodies[fixture.name]
									space := 257
									if fixture.segment == "GS" {
										space = 256
									}
									if !strings.Contains(body, fmt.Sprintf("ptr addrspace(%d)", space)) ||
										fixture.row.native && !strings.Contains(body, "asm sideeffect") ||
										!fixture.row.native && !strings.Contains(body, fmt.Sprintf("load volatile i%d,", fixture.row.bytes*8)) {
										t.Fatal("complete source lost exact hardware-segment access", fixture.name, body)
									}
								}
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
}

func x86GPSegmentCompareRows(arch string) []x86GPFaultingReadCase {
	var rows []x86GPFaultingReadCase
	for i, suffix := range "BWLQ" {
		if arch == "386" && suffix == 'Q' {
			continue
		}
		for _, stem := range []string{"CMP", "TEST"} {
			instruction := stem + string(suffix) + " MEM,BX"
			if stem == "TEST" {
				instruction = stem + string(suffix) + " BX,MEM"
			}
			rows = append(rows, x86GPFaultingReadCase{
				family: "compare", instruction: instruction,
				bytes: []int{1, 2, 4, 8}[i], partner: true, flagsResult: true,
			})
		}
	}
	return rows
}

func TestX86GPFaultingReadSegmentCompareInputs(t *testing.T) {
	x86GPSegmentInputs(t, x86GPSegmentCompareRows, map[string]x86GPSegmentInputCount{
		"amd64": {8, 832, 128, 2496},
		"386":   {6, 624, 96, 1872},
	})
}

func TestX86GPFaultingReadSegmentCompareObjects(t *testing.T) {
	x86GPSegmentObjects(t, x86GPSegmentCompareRows)
}

func TestX86GPFaultingReadSegmentDoesNotAdmitPairCAS(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		ops := []string{"CMPXCHG8B", "CMPXCHG16B"}
		if target.arch == "386" {
			move, ops = "MOVL", ops[:1]
		}
		for _, op := range ops {
			for _, segment := range []string{"FS", "GS"} {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-0\n%s $1,AX\n%s $2,BX\n%s $3,CX\n%s $4,DX\nCMP%s AX,AX\n%s 0(%s)\nRET\n",
					move, move, move, move, strings.TrimPrefix(move, "MOV"), op, segment)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+segment+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("scalar segment continuation granted the separate pair-CAS role", err)
						}
					})
				}
			}
		}
	}
}
