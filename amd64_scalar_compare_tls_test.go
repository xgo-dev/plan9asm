package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TLS is an address annotation consumed by Go's OS/arch/-shared progedit,
// not a numerical SIB index. Exercise every comparison row without granting
// a native TLS source, relocation, layout, or caller-memory contract.
func x86ScalarCompareTLSRows(op, arch string, direct bool) []string {
	bases := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
	if arch == "amd64" {
		bases = append(bases, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	}
	var addresses []string
	for _, base := range bases {
		for _, scale := range []int{1, 2, 4, 8} {
			for _, offset := range []int{-8, 0, 8} {
				addresses = append(addresses, fmt.Sprintf("%d(%s)(TLS*%d)", offset, base, scale))
			}
		}
	}
	if direct {
		addresses = append(addresses, "-8(TLS)", "0(TLS)", "8(TLS)", "0(TLS)(TLS*1)")
	}
	addresses = append(addresses, "0(TLS*1)", "0(AX)(TLS)", "0(FS)(TLS*1)",
		"0(GS)(TLS*8)", "slot(FP)(TLS*1)", "slot(SP)(TLS*8)")
	if arch == "386" {
		addresses = append(addresses, "data(SB)(TLS*1)", "data(SB)(TLS)")
	}
	var rows []string
	for _, address := range addresses {
		rows = append(rows, op+" "+address+",AX", op+" AX,"+address,
			x86ScalarCompareInstruction(op, address, "$1"))
	}
	return rows
}

func x86ScalarCompareTLSGoObject(t *testing.T, source, arch, goos string, shared bool) {
	t.Helper()
	dir := t.TempDir()
	path, object := filepath.Join(dir, "tls.s"), filepath.Join(dir, "tls.o")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := []string{"tool", "asm", "-p", "tlsforms", "-o", object}
	if shared {
		args = append(args, "-shared")
	}
	args = append(args, path)
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch,
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(path, object, output, err, ctx.Err(), true, arch); failure != nil {
		t.Fatalf("%v\n%s", failure, output)
	}
}

func TestX86ScalarCompareTLSActualGoProfiles(t *testing.T) {
	for _, profile := range []struct {
		arch, goos     string
		shared, direct bool
	}{
		{"386", "linux", false, false}, {"386", "linux", true, false},
		{"386", "windows", false, false}, {"386", "freebsd", false, true},
		{"amd64", "linux", false, true}, {"amd64", "linux", true, false},
		{"amd64", "darwin", false, true}, {"amd64", "windows", false, false},
	} {
		t.Run(fmt.Sprintf("%s/%s/shared=%v", profile.goos, profile.arch, profile.shared), func(t *testing.T) {
			var source strings.Builder
			index := 0
			for _, op := range x86ScalarCompareNames(profile.arch) {
				for _, row := range x86ScalarCompareTLSRows(op, profile.arch, profile.direct) {
					fmt.Fprintf(&source, "TEXT ·tls%d(SB),4,$0-0\n%s\nRET\n", index, row)
					index++
				}
			}
			x86ScalarCompareTLSGoObject(t, source.String(), profile.arch, profile.goos, profile.shared)
			t.Logf("%d original Go TLS forms", index)
		})
	}
}

func TestX86ScalarCompareTLSRequiresContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ScalarCompareNames(arch) {
			for _, row := range x86ScalarCompareTLSRows(op, arch, true) {
				ins := x86PureGPUnknownInstruction(t, row)
				if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s: expected native TLS Context, got %v", arch, row, err)
				}
			}
		}
	}
}

func TestX86ScalarCompareTLSAPIsFailClosed(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86ScalarCompareNames(target.arch) {
			for _, address := range []string{"0(CX)(TLS*1)", "-8(SP)(TLS*8)", "8(TLS)"} {
				for _, row := range []string{op + " " + address + ",AX", op + " AX," + address,
					x86ScalarCompareInstruction(op, address, "$1")} {
					source := "TEXT ·probe(SB),4,$0-0\n" + row + "\nRET\n"
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func probe()", target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("TLS must return Context and no IR: error=%v, IR=%s", err, ir)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86ScalarCompareTLSMalformedRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ScalarCompareNames(arch) {
			rows := []string{"0(CX)(TLS*1),0(DX)(TLS*1)", "0(CX)(TLS*1),X0", "X0,0(CX)(TLS*1)",
				"TLS,AX", "AX,TLS", "0(CX)(TLS*1)", "0(CX)(TLS*1),AX,BX"}
			if strings.HasPrefix(op, "CMP") {
				rows = append(rows, "$1,0(CX)(TLS*1)")
			} else {
				rows = append(rows, "0(CX)(TLS*1),$1")
			}
			for _, row := range rows {
				body := op + " " + row
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
				ins := x86PureGPUnknownInstruction(t, body)
				if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("invalid row was hidden by TLS: %s %s: %v", arch, body, err)
				}
			}
		}
	}
}

func TestX86ScalarCompareTLSMalformedTypedBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ScalarCompareNames(arch) {
			for _, change := range []struct {
				name   string
				mutate func(*Instr)
			}{
				{"unknown-base", func(ins *Instr) { ins.Args[0].Mem.Base = "UNKNOWN" }},
				{"vector-base", func(ins *Instr) { ins.Args[0].Mem.Base = "X0" }},
				{"bad-scale", func(ins *Instr) { ins.Args[0].Mem.Scale = 3 }},
				{"unresolved-offset", func(ins *Instr) { ins.Args[0].Mem.OffRaw = "missing" }},
				{"extended-index", func(ins *Instr) { ins.Args[0].Mem.IndexExt = ExtendUXTW }},
				{"unknown-segment", func(ins *Instr) { ins.Args[0].Mem.Segment = "UNKNOWN" }},
				{"unknown-symbol-role", func(ins *Instr) { ins.Args[0].Mem.Sym = "data(UNKNOWN)" }},
				{"invalid-symbol", func(ins *Instr) { ins.Args[0].Mem.Sym = "$data(SB)" }},
				{"suffix", func(ins *Instr) { ins.Op += ".Z" }},
				{"float-immediate", func(ins *Instr) {
					ins.Args = []Operand{ins.Args[0], {Kind: OpImm, ImmIsFloat: true}}
					if strings.HasPrefix(op, "TEST") {
						ins.Args[0], ins.Args[1] = ins.Args[1], ins.Args[0]
					}
				}},
				{"unresolved-immediate", func(ins *Instr) {
					ins.Args = []Operand{ins.Args[0], {Kind: OpImm, ImmRaw: "$missing"}}
					if strings.HasPrefix(op, "TEST") {
						ins.Args[0], ins.Args[1] = ins.Args[1], ins.Args[0]
					}
				}},
			} {
				t.Run(arch+"/"+op+"/"+change.name, func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, op+" 0(CX)(TLS*1),AX")
					change.mutate(&ins)
					if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("malformed typed row was hidden by TLS: %v", err)
					}
				})
			}
		}
	}
}
