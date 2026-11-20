//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedConversionCompleteNativeSemanticInventory(t *testing.T) {
	// Independent expected multiplicities: plain register/memory, alias/dead,
	// merge/zero/broadcast, explicit rounding/SAE and physical low-bank EVEX.
	want := map[string]int{
		"CVTPS2PL": 4, "CVTTPS2PL": 4, "CVTPD2PL": 4, "CVTTPD2PL": 4,
		"VCVTPS2DQ": 28, "VCVTTPS2DQ": 25,
		"VCVTPD2DQX": 8, "VCVTPD2DQY": 8, "VCVTPD2DQ": 12,
		"VCVTTPD2DQX": 8, "VCVTTPD2DQY": 8, "VCVTTPD2DQ": 9,
		"VCVTPD2QQ": 28, "VCVTPD2UQQ": 28, "VCVTTPD2QQ": 25, "VCVTTPD2UQQ": 25,
		"VCVTPS2UDQ": 28, "VCVTTPS2UDQ": 25, "VCVTUDQ2PS": 28,
		"VCVTQQ2PD": 28, "VCVTUQQ2PD": 28,
		"VCVTPS2QQ": 28, "VCVTPS2UQQ": 28, "VCVTTPS2QQ": 25, "VCVTTPS2UQQ": 25,
		"VCVTUDQ2PD":  24,
		"VCVTPD2UDQX": 8, "VCVTPD2UDQY": 8, "VCVTPD2UDQ": 12,
		"VCVTTPD2UDQX": 8, "VCVTTPD2UDQY": 8, "VCVTTPD2UDQ": 9,
		"VCVTQQ2PSX": 8, "VCVTQQ2PSY": 8, "VCVTQQ2PS": 12,
		"VCVTUQQ2PSX": 8, "VCVTUQQ2PSY": 8, "VCVTUQQ2PS": 12,
		"CVTPL2PS": 4, "CVTPL2PD": 4, "VCVTDQ2PS": 46, "VCVTDQ2PD": 34,
	}
	seen := make(map[string]int)
	physical := 0
	rows := x86PackedConversionCompleteRuntimeRows()
	for _, row := range rows {
		member := strings.Split(strings.Fields(row.instruction)[0], ".")[0]
		seen[member]++
		if !row.wide || row.inputBits != 32 && row.inputBits != 64 {
			t.Fatal("complete native fixture lost full alias storage or input bit type", row)
		}
		if row.rawOverride != "" {
			physical++
			if member != "VCVTDQ2PS" && member != "VCVTDQ2PD" {
				t.Fatal("unowned physical-generation override", row)
			}
		}
	}
	if len(rows) != 692 || len(seen) != 42 || physical != 2 {
		t.Fatal("incomplete42 native semantic inventory", len(rows), len(seen), physical)
	}
	for member, count := range want {
		if seen[member] != count {
			t.Error("changed native member semantic axes", member, seen[member], count)
		}
	}
	for member := range seen {
		if want[member] == 0 {
			t.Error("unexpected native member", member)
		}
	}
	assembly, _, goMain, cMain := x86PackedConversionRuntimeFixture(rows[len(rows)-2:])
	for _, required := range []string{"VMOVDQU64 (SI),Z0", "VMOVDQU64 (DI),Z1", "STMXCSR 72(DI)", "SETPC 68(DI)", "LDMXCSR saved-4(SP)"} {
		if !strings.Contains(assembly, required) {
			t.Fatal("native value oracle lost full inputs, aliases, status or MXCSR restoration", required)
		}
	}
	if !strings.Contains(goMain, "unsafe.Add(address,(-uintptr(address))&15)") ||
		!strings.Contains(cMain, "_Alignas(16) uint64_t input[8],out[12]") {
		t.Fatal("native legacy m128 values rely on accidental input alignment")
	}
}

func TestX86PackedConversionCompleteNativeFaultInventory(t *testing.T) {
	rows := x86PackedConversionCompleteFaultRows()
	if len(rows) != 222 {
		t.Fatal("complete42 memory-fault denominator changed", len(rows))
	}
	members := make(map[string]bool)
	signed := make(map[string]int)
	for _, row := range rows {
		member := strings.Split(row.name, ".")[0]
		members[member] = true
		if row.lanes < 2 || row.lanes > 16 || row.laneBytes != 4 && row.laneBytes != 8 {
			t.Fatal("fault mask domain lost active output lanes", row)
		}
		if row.name == "CVTPL2PD" && (row.width != 8 || row.aligned || row.precision || row.floating) {
			t.Fatal("exact signed32-to-double m64 inherited m128/precision semantics", row)
		}
		if row.name == "CVTPL2PS" && (row.width != 16 || !row.aligned || !row.precision || row.floating) {
			t.Fatal("signed32-to-single m128 lost alignment/precision", row)
		}
		if member == "VCVTDQ2PS" || member == "VCVTDQ2PD" || strings.HasPrefix(member, "CVTPL") {
			signed[fmt.Sprintf("%s/%d/%s", member, row.lanes, strings.TrimPrefix(row.name, member))]++
		}
	}
	if len(members) != 42 || len(signed) != 20 {
		t.Fatal("missing complete42 fault members or signed semantic shapes", len(members), len(signed))
	}
	for _, op := range []string{"VCVTDQ2PS", "VCVTDQ2PD"} {
		lanes := []int{4, 8, 16}
		if op == "VCVTDQ2PD" {
			lanes = []int{2, 4, 8}
		}
		for _, count := range lanes {
			for _, suffix := range []string{"", ".Z", ".BCST.Z"} {
				if signed[fmt.Sprintf("%s/%d/%s", op, count, suffix)] != 1 {
					t.Error("missing or duplicated native signed fault shape", op, count, suffix)
				}
			}
		}
	}
	for _, scope := range []struct{ count, limit int }{{692, 64}, {222, 16}} {
		seen := make([]int, scope.count)
		for owner := 0; owner < 8; owner++ {
			owned := 0
			for batch, start := 0, 0; start < scope.count; batch, start = batch+1, start+scope.limit {
				if batch%8 != owner {
					continue
				}
				for index := start; index < start+scope.limit && index < scope.count; index++ {
					seen[index]++
					owned++
				}
			}
			if owned == 0 || owned > 2*scope.limit {
				t.Fatal("empty or monolithic native scheduling owner", scope, owner, owned)
			}
		}
		for index, count := range seen {
			if count != 1 {
				t.Fatal("native scheduling changed complete denominator", scope, index, count)
			}
		}
	}
}

func TestX86PackedConversionSignedNativeRuntimeFixtureObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86PackedConversionCompleteRuntimeRows()
	if len(rows) != 692 {
		t.Fatal("complete native runtime fixture inventory changed")
	}
	// The604 older kernels retain their own whole fixture objects. These88
	// new signed/alias/dead/physical kernels compile the exact runtime wrapper,
	// not a reduced standalone instruction or a native execution certificate.
	for start := 604; start < len(rows); start += 64 {
		end := start + 64
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			batch := append([]x86PackedConversionRuntimeRow(nil), rows[start:end]...)
			var instructions []string
			for _, row := range batch {
				instructions = append(instructions, row.instruction)
			}
			raw := x86PackedConversionContinuationRawRows(t, "amd64", instructions)
			for _, spelling := range []string{"named", "raw"} {
				t.Run(spelling, func(t *testing.T) {
					if spelling == "raw" {
						for index := range batch {
							batch[index].instruction = raw[index]
							if batch[index].rawOverride != "" {
								batch[index].instruction = batch[index].rawOverride
							}
						}
					}
					source, declarations, _, _ := x86PackedConversionRuntimeFixture(batch)
					goAssemblerOracleOutput(t, "amd64", source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
							if err != nil {
								t.Fatal("new native runtime fixture lost initialized public path", err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							for _, pipeline := range []struct{ name, ir, backend string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", pipeline.ir, pipeline.backend)
								})
							}
						})
					}
				})
			}
		})
	}
}
