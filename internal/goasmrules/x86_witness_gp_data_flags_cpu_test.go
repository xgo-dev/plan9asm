package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// This is an independent source inventory, not a numerical consumer registry.
// Shared tables also contain ARPL, descriptor/state and FS/GS-base roles.
func gpDataFlagsCPUOriginalMember(entry X86LegacyOpcode) bool {
	switch entry.Ytab {
	case "yxorb", "ytestl", "ybtl", "ybswap":
		return true
	case "ym_rl":
		return strings.HasPrefix(entry.Opcode, "LEA")
	case "yrb_mb", "yrl_ml":
		return strings.HasPrefix(entry.Opcode, "XADD") || strings.HasPrefix(entry.Opcode, "CMPXCHG") ||
			strings.HasPrefix(entry.Opcode, "MOVNTI") || entry.Opcode == "MOVQL"
	case "yscond":
		return entry.Opcode == "CMPXCHG8B" || entry.Opcode == "CMPXCHG16B"
	case "ycrc32b", "ycrc32l":
		return strings.HasPrefix(entry.Opcode, "CRC32") || strings.HasPrefix(entry.Opcode, "TZCNT")
	case "yrdrand":
		return strings.HasPrefix(entry.Opcode, "RDRAND") || strings.HasPrefix(entry.Opcode, "RDSEED") || entry.Opcode == "RDPID"
	}
	return false
}

func gpDataFlagsCPUOriginalEntries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string][]string{
		"yxorb":   {"Zib_/1/Yi32,Yal", "Zibo_m/2/Yi32,Ymb", "Zr_m/1/Yrb,Ymb", "Zm_r/1/Ymb,Yrb"},
		"ytestl":  {"Zil_/1/Yi32,Yax", "Zilo_m/2/Yi32,Yml", "Zr_m/1/Yrl,Yml", "Zm_r/1/Yml,Yrl"},
		"ybtl":    {"Zibo_m/2/Yi8,Yml", "Zr_m/1/Yrl,Yml"},
		"ybswap":  {"Z_rp/2/Yrl"},
		"ym_rl":   {"Zm_r/1/Ym,Yrl"},
		"yrb_mb":  {"Zr_m/1/Yrb,Ymb"},
		"yrl_ml":  {"Zr_m/1/Yrl,Yml"},
		"yscond":  {"Zo_m/2/Ymb"},
		"ycrc32b": {"Zlitm_r/0/Ymb,Yrl"},
		"ycrc32l": {"Zlitm_r/0/Yml,Yrl"},
		"yrdrand": {"Zo_m/2/Yrl"},
	}
	var entries []X86LegacyOpcode
	counts, rows := map[string]int{}, 0
	for _, entry := range catalog.Optab {
		if !gpDataFlagsCPUOriginalMember(entry) {
			continue
		}
		want := schemas[entry.Ytab]
		if entry.Kind != "encoding" || len(entry.Rows) != len(want) {
			t.Fatal("complete GP original source table changed", entry)
		}
		offset := 0
		for i, row := range entry.Rows {
			schema := fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ","))
			if row.RowIndex != i || row.UnmatchedOffset != offset || schema != want[i] ||
				len(row.Classes) != strings.Count(strings.Split(want[i], "/")[2], ",")+1 {
				t.Fatal("original complete GP row/arity/order changed", entry, row)
			}
			offset += row.ZOffset + entry.EscapeAdjustment
			counts[entry.Ytab]++
			rows++
		}
		entries = append(entries, entry)
	}
	for table, count := range map[string]int{
		"yxorb": 32, "ytestl": 12, "ybtl": 24, "ybswap": 2, "ym_rl": 3,
		"yrb_mb": 2, "yrl_ml": 9, "yscond": 2, "ycrc32b": 1, "ycrc32l": 6,
	} {
		if counts[table] != count {
			t.Fatal("complete GP source family count changed", table, counts)
		}
	}
	if counts["yrdrand"] != 6 && counts["yrdrand"] != 7 || rows != 93+counts["yrdrand"] {
		t.Fatal("complete GP source union changed", rows, counts)
	}
	return entries
}

func TestX86GPDataFlagsCPUCompleteOriginalSourceInventory(t *testing.T) {
	gpDataFlagsCPUOriginalEntries(t)
}

func TestX86GPDataFlagsCPURegisterOpcodeCannotBePadding(t *testing.T) {
	for _, entry := range gpDataFlagsCPUOriginalEntries(t) {
		if entry.Ytab != "ybswap" {
			continue
		}
		t.Run(entry.Opcode, func(t *testing.T) {
			// Keep the full original schema, escape and source identity.
			// Only the register-in-opcode base is replaced by padding.
			changed := entry
			changed.OpBytes = []string{"0x0f", "0"}
			if got, err := x86ScalarRMWRowWitnesses(changed, entry.Rows[0], "amd64"); err == nil {
				t.Fatal("GP_DATA_FLAGS_CPU_REGISTER_OPCODE_PADDING_ACCEPTED", got)
			}
		})
	}
}

func TestX86GPDataFlagsCPUExistingTransportCompleteFamily(t *testing.T) {
	for _, entry := range gpDataFlagsCPUOriginalEntries(t) {
		for _, row := range entry.Rows {
			for _, arch := range []string{"amd64", "386"} {
				if arch == "386" && entry.Prefix == "Pw" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%d/%s", entry.Opcode, row.RowIndex, arch), func(t *testing.T) {
					before := fmt.Sprintf("%#v", entry)
					witnesses, err := x86ScalarRMWRowWitnesses(entry, row, arch)
					want := 2
					if entry.Ytab == "yrdrand" || entry.Ytab == "ym_rl" || entry.Ytab == "ybswap" ||
						row.ZCase == "Zib_" || row.ZCase == "Zil_" || row.ZCase == "Zm_r" {
						want = 1
					}
					if err != nil || len(witnesses) != want {
						t.Fatal("GP_DATA_FLAGS_CPU_SOURCE_TRANSPORT_FEATURE_GAP", err, len(witnesses), want)
					}
					for _, witness := range witnesses {
						if witness.Instruction == "" || witness.Destination == "" || len(witness.Encoding) == 0 ||
							entry.Ytab == "yrdrand" && strings.Contains(witness.Instruction, "(") {
							t.Fatal("source-only witness lost its complete operand roles", entry, witness)
						}
					}
					if before != fmt.Sprintf("%#v", entry) {
						t.Fatal("cold formatter modified original source")
					}
					for _, expression := range []string{"obj.A" + entry.Opcode, ""} {
						variant := entry
						variant.OpcodeExpression = expression
						got, err := x86ScalarRMWRowWitnesses(variant, row, arch)
						if err != nil || !reflect.DeepEqual(got, witnesses) {
							t.Fatal("captured obj enum or existing unobserved fixture contract changed", expression, err)
						}
					}
					if entry.Ytab == "ycrc32b" || entry.Ytab == "ycrc32l" {
						implicit := entry
						// Removing this explicit zero does not change the full
						// [31]byte Go array: its remaining cells are already zero.
						implicit.OpBytes = append([]string(nil), entry.OpBytes[:len(entry.OpBytes)-1]...)
						got, err := x86ScalarRMWRowWitnesses(implicit, row, arch)
						if err != nil || !reflect.DeepEqual(got, witnesses) {
							t.Fatal("GP_DATA_FLAGS_CPU_IMPLICIT_ZERO_EQUIVALENCE_GAP", entry.Opcode, row.RowIndex, arch, err)
						}
					}
				})
			}
		}
	}
}

func TestX86GPDataFlagsCPUCompleteOriginalMetadataBoundaries(t *testing.T) {
	for _, entry := range gpDataFlagsCPUOriginalEntries(t) {
		for _, original := range entry.Rows {
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, original.RowIndex), func(t *testing.T) {
				for _, field := range []string{
					"kind", "row-count", "original-arity", "selected-arity", "original-joined-arity", "selected-joined-arity", "original-class", "selected-class",
					"original-index", "selected-index", "original-zcase", "selected-zcase",
					"original-stride-negative", "original-stride-overflow", "selected-stride",
					"original-offset-negative", "selected-offset-overflow", "prefix",
					"escape-negative", "escape-overflow", "empty-payload", "truncated-payload",
				} {
					changed, row := entry, original
					changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					maxInt := int(^uint(0) >> 1)
					switch field {
					case "kind":
						changed.Kind = "reserved"
					case "row-count":
						changed.Rows = append(changed.Rows, original)
					case "original-arity":
						changed.Rows[0].Classes = append(append([]string(nil), changed.Rows[0].Classes...), "Ynone")
					case "selected-arity":
						row.Classes = append(append([]string(nil), row.Classes...), "Ynone")
					case "original-joined-arity":
						changed.Rows[0].Classes = []string{strings.Join(changed.Rows[0].Classes, ",")}
						if len(entry.Rows[0].Classes) == 1 {
							changed.Rows[0].Classes = nil
						}
					case "selected-joined-arity":
						row.Classes = []string{strings.Join(row.Classes, ",")}
						if len(original.Classes) == 1 {
							row.Classes = nil
						}
					case "original-class":
						changed.Rows[0].Classes = append([]string(nil), changed.Rows[0].Classes...)
						changed.Rows[0].Classes[0] = "Yinvalid"
					case "selected-class":
						row.Classes = append([]string(nil), row.Classes...)
						row.Classes[0] = "Yinvalid"
					case "original-index":
						changed.Rows[0].RowIndex = -1
					case "selected-index":
						row.RowIndex = maxInt
					case "original-zcase":
						changed.Rows[0].ZCase = "Zinvalid"
					case "selected-zcase":
						row.ZCase = "Zinvalid"
					case "original-stride-negative":
						changed.Rows[0].ZOffset = -maxInt - 1
					case "original-stride-overflow":
						changed.Rows[0].ZOffset = maxInt
					case "selected-stride":
						row.ZOffset = maxInt
					case "original-offset-negative":
						changed.Rows[0].UnmatchedOffset = -maxInt - 1
					case "selected-offset-overflow":
						row.UnmatchedOffset = maxInt
					case "prefix":
						changed.Prefix = "Pinvalid"
					case "escape-negative":
						changed.EscapeAdjustment = -1
					case "escape-overflow":
						changed.EscapeAdjustment = maxInt
					case "empty-payload":
						changed.OpBytes = nil
					case "truncated-payload":
						end := len(changed.OpBytes) - 1
						if entry.Ytab == "ycrc32b" || entry.Ytab == "ycrc32l" {
							// The final zero alone is implicit-padding equivalent;
							// remove an actual mandatory opcode byte as well.
							end--
						}
						changed.OpBytes = changed.OpBytes[:end]
					}
					func() {
						defer func() {
							if p := recover(); p != nil {
								t.Errorf("GP_DATA_FLAGS_CPU_METADATA_PANIC op=%s row=%d mutation=%s panic=%v", entry.Opcode, original.RowIndex, field, p)
							}
						}()
						if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
							t.Errorf("GP_DATA_FLAGS_CPU_MALFORMED_ACCEPTED op=%s row=%d mutation=%s", entry.Opcode, original.RowIndex, field)
						}
					}()
				}
				// Every payload atom, including later literal bytes and its
				// terminator, must be validated before any slice or emission.
				for index := range entry.OpBytes {
					for _, atom := range []string{"-1", "0x100", "not-a-byte"} {
						changed := entry
						changed.OpBytes = append([]string(nil), entry.OpBytes...)
						changed.OpBytes[index] = atom
						if _, err := x86ScalarRMWRowWitnesses(changed, original, "amd64"); err == nil {
							t.Errorf("GP_DATA_FLAGS_CPU_MALFORMED_ACCEPTED op=%s row=%d atomIndex=%d atom=%q", entry.Opcode, original.RowIndex, index, atom)
						}
					}
				}
				if entry.Ytab == "yxorb" {
					for _, axis := range [][2]string{{"W", "Pe"}, {"L", "Px"}, {"Q", "Pw"}} {
						changed := entry
						changed.Opcode = entry.Opcode[:len(entry.Opcode)-1] + axis[0]
						changed.Prefix = axis[1]
						// Keep enum/name consistent so the independent byte-width
						// grammar guard, not source identity, rejects this clone.
						changed.OpcodeExpression = "A" + changed.Opcode
						if _, err := x86ScalarRMWRowWitnesses(changed, original, "amd64"); err == nil {
							t.Errorf("GP_DATA_FLAGS_CPU_BYTE_SCHEMA_WIDENED op=%s row=%d changed=%s prefix=%s", entry.Opcode, original.RowIndex, changed.Opcode, axis[1])
						}
					}
				}
				if entry.Ytab == "ycrc32b" || entry.Ytab == "ycrc32l" {
					for index := range entry.OpBytes {
						changed := entry
						changed.OpBytes = append([]string(nil), entry.OpBytes...)
						changed.OpBytes[index] = "0"
						if index == len(entry.OpBytes)-1 {
							changed.OpBytes[index] = "1"
						}
						if _, err := x86ScalarRMWRowWitnesses(changed, original, "amd64"); err == nil {
							t.Errorf("GP_DATA_FLAGS_CPU_MALFORMED_ACCEPTED op=%s row=%d literalZeroIndex=%d", entry.Opcode, original.RowIndex, index)
						}
					}
				}
			})
		}
	}
}
