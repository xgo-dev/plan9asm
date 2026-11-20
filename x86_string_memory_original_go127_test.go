//go:build go1.27

package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// These are structural original-Go/LLVM observations. They neither execute a
// fault nor authenticate caller memory, bounds, a frame or an SDK function.
func TestX86StringImplicitMemoryOriginalGoAndLLVMO0O2(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete implicit string objects require LLVM22 llc")
	}
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		rows := x86StringMemoryModeRows(arch)
		for _, prefix := range []string{"", "REP", "REPN"} {
			counts := []int{1}
			if prefix != "" {
				counts = append(counts, 0)
			}
			for _, count := range counts {
				for _, backward := range []bool{false, true} {
					name := fmt.Sprintf("%s/prefix=%s/count=%d/backward=%t", arch, prefix, count, backward)
					t.Run(name, func(t *testing.T) {
						source, declarations := x86StringMemoryFixture(rows, arch, prefix, count, backward)
						file, err := Parse(ArchAMD64, source)
						if err != nil || len(file.Funcs) != len(rows) {
							t.Fatal("complete original source denominator changed", err)
						}
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
								if err != nil {
									t.Fatal("complete original source did not reach structural inspection", err)
								}
								for _, row := range rows {
									body := x86StringMemoryFunction(t, ir, x86StringMemoryHelper(row))
									x86StringMemoryCheckAccesses(t, body, row, row.reads, row.writes)
								}
								optimized := x86UndefinedTrapOptimizedIR(t, ir)
								for _, row := range rows {
									entry := "stringmem_" + strings.ToLower(row.op)
									body := x86StringMemoryReachableIR(t, optimized, entry, make(map[string]bool))
									reads, writes := row.reads, row.writes
									if count == 0 {
										reads, writes = 0, 0
									}
									x86StringMemoryCheckAccesses(t, body, row, reads, writes)
								}
								// O0 and O2 inspect the same complete translated source;
								// no filtering or replacement of a dead-result function.
								for _, row := range rows {
									x86StringMemoryFunction(t, optimized, "stringmem_"+strings.ToLower(row.op))
								}
								for _, stage := range []struct {
									name, ir string
								}{{"ir0", ir}, {"ir2", optimized}} {
									for _, backend := range []string{"-O0", "-O2"} {
										t.Run(stage.name+"/backend"+backend[2:], func(t *testing.T) {
											x86PackedStringCompileObject(t, llc, triple, stage.ir, backend)
										})
									}
								}
							})
						}
					})
				}
			}
		}
	}
}

func x86StringMemoryCheckAccesses(t *testing.T, body string, row x86StringMemoryRow, reads, writes int) {
	t.Helper()
	if err := x86StringMemoryIRAccessError(body, row.width, reads, writes); err != nil {
		t.Errorf("%s %v", row.op, err)
	}
}

// O2 may inline or specialize an internal helper. Count its reachable body if
// it remains instead of requiring one incidental inline decision. Only these
// fixed internal test-observed helper names are followed; cycles are errors.
func x86StringMemoryReachableIR(t *testing.T, ir, name string, active map[string]bool) string {
	t.Helper()
	if active[name] {
		t.Fatal("recursive string helper is outside the bounded observation", name)
	}
	active[name] = true
	defer delete(active, name)
	body := x86StringMemoryFunction(t, ir, name)
	calls := regexp.MustCompile(`\bcall [^\n]* @"?(__plan9asm_[A-Za-z0-9_.]+)"?\(`).FindAllStringSubmatch(body, -1)
	var complete strings.Builder
	complete.WriteString(body)
	for _, call := range calls {
		complete.WriteByte('\n')
		complete.WriteString(x86StringMemoryReachableIR(t, ir, call[1], active))
	}
	return complete.String()
}

func TestX86StringRepeatCFGOriginalGoKeepsCompleteFixtures(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, shape := range []string{"adjacent", "fallthrough-label", "fallthrough-label-chain",
			"branch-to-prefix", "pc-to-prefix", "loopback-to-prefix",
			"conditional-bypass", "unreachable-prefix", "backedge-to-body", "pc-bypass", "unknown-indirect"} {
			t.Run(arch+"/"+shape, func(t *testing.T) {
				var source strings.Builder
				for _, prefix := range []string{"REP", "REPN"} {
					for _, row := range x86StringMemoryModeRows(arch) {
						one, _ := x86StringRepeatCFGFixture(row, arch, prefix, shape)
						name := "cfg_" + strings.ToLower(prefix+"_"+row.op)
						one = strings.Replace(one, "·repeatcfg(SB)", "·"+name+"(SB)", 1)
						source.WriteString(one)
					}
				}
				file, err := Parse(ArchAMD64, source.String())
				if err != nil || len(file.Funcs) != 2*len(x86StringMemoryModeRows(arch)) {
					t.Fatal("original CFG batch lost a prefix, spelling or complete function", err)
				}
				goAssemblerOracleOutput(t, arch, source.String(), "", true)
			})
		}
	}
}
