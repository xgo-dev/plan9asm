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

func x86TLSMoveRows(arch string, direct bool) []string {
	var rows []string
	word := "MOVQ"
	if arch == "386" {
		word = "MOVL"
	}
	rows = append(rows, word+" TLS,AX", word+" TLS,CX", word+" TLS,SP", word+" TLS,BP")
	addresses := []string{"0(CX)(TLS*1)", "-8(BP)(TLS*2)", "8(SP)(TLS*4)",
		"0(AX)(TLS)", "0(TLS*8)", "0(FS)(TLS*1)", "slot(FP)(TLS*1)", "slot(SP)(TLS*1)"}
	if arch == "386" {
		addresses = append(addresses, "data(SB)(TLS)", "data(SB)(TLS*1)")
	}
	if direct {
		addresses = append(addresses, "-8(TLS)", "0(TLS)", "8(TLS)")
		// Direct-TLS progedit removes both spellings before the special
		// movTLSReg emitter can enforce the machine's native pointer width.
		rows = append(rows, "MOVL TLS,DX", "MOVQ TLS,DX")
	}
	for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
		var registers []string
		if op == "MOVL" || op == "MOVQ" {
			registers = append(registers, "M0", "M7", "X0", "X7")
			if arch == "amd64" {
				registers = append(registers, "X8", "X15")
			}
		}
		if op == "MOVB" {
			registers = append(registers, "AL", "BL", "AH", "BH")
		}
		if op == "MOVW" {
			registers = append(registers, "CS", "SS", "DS", "ES", "FS", "GS")
		}
		if op != "MOVQ" || arch == "amd64" {
			registers = append(registers, "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI")
			if op == "MOVB" && arch == "386" {
				registers = []string{"AL", "BL", "AH", "BH", "AX", "CX", "DX", "BX", "BP", "SI", "DI"}
			}
			if arch == "amd64" {
				registers = append(registers, "R8", "R15")
			}
		}
		for _, address := range addresses {
			for _, register := range registers {
				rows = append(rows, op+" "+address+","+register, op+" "+register+","+address)
			}
			if op != "MOVQ" || arch == "amd64" {
				for _, immediate := range []string{"0", "1", "-2147483648", "4294967295"} {
					rows = append(rows, op+" $"+immediate+","+address)
				}
			}
		}
	}
	return rows
}

func TestX86TLSMoveActualGoProfiles(t *testing.T) {
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
			rows := x86TLSMoveRows(profile.arch, profile.direct)
			assembled, defects := 0, 0
			for index, row := range rows {
				// Go's shared 386 PIC rewrite borrows the destination register
				// for MOVL named SB loads. MMX/XMM cannot serve as an address
				// base there. Those native backend defects are tested separately;
				// the same source rows are accepted by non-shared Go profiles.
				if profile.arch == "386" && profile.shared && x86TLSMoveShared386SBVectorLoad(row) {
					defects++
					continue
				}
				fmt.Fprintf(&source, "TEXT ·tls%d(SB),4,$0-0\n%s\nRET\n", index, row)
				assembled++
			}
			x86ScalarCompareTLSGoObject(t, source.String(), profile.arch, profile.goos, profile.shared)
			t.Logf("%d actual Go TLS move rows; %d separately checked native backend defects", assembled, defects)
		})
	}
}

func x86TLSMoveShared386SBVectorLoad(row string) bool {
	return strings.HasPrefix(row, "MOVL data(SB)(TLS*1),") && (strings.Contains(row, ",M") || strings.Contains(row, ",X"))
}

func TestX86TLSMoveShared386SBBackendDefect(t *testing.T) {
	count := 0
	for _, row := range x86TLSMoveRows("386", false) {
		if !x86TLSMoveShared386SBVectorLoad(row) {
			continue
		}
		count++
		t.Run(row, func(t *testing.T) {
			dir := t.TempDir()
			path, object := filepath.Join(dir, "tls.s"), filepath.Join(dir, "tls.o")
			original := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, "go", "tool", "asm", "-shared", "-o", object, path)
			command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=386", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			exit, exited := err.(*exec.ExitError)
			register := strings.Split(row, ",")[1]
			want := "asm: asmand: bad address data(" + register + ")(TLS*1)\nasm: assembly failed\n"
			if ctx.Err() != nil || !exited || exit.ExitCode() != 1 || string(output) != want {
				t.Fatalf("unknown shared 386 TLS backend observation: %v\n%s", err, output)
			}
			if goAssemblerOracleOutcome(path, object, output, err, ctx.Err(), false, "386") == nil {
				t.Fatal("backend address failure became an illegal-source certificate")
			}
			if err := x86SourceTLSMoveError(x86PureGPUnknownInstruction(t, row), "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("missing native profile became accepted LLVM: %v", err)
			}
		})
	}
	if count != 4 {
		t.Fatalf("shared profile partition omitted native defects: %d", count)
	}
}

func TestX86TLSMoveTypedBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
			for _, mutation := range []struct {
				name   string
				mutate func(*Instr)
			}{
				{"scale", func(ins *Instr) { ins.Args[0].Mem.Scale = 3 }},
				{"offset", func(ins *Instr) { ins.Args[0].Mem.OffRaw = "missing" }},
				{"unknown-base", func(ins *Instr) { ins.Args[0].Mem.Base = "UNKNOWN" }},
				{"extension", func(ins *Instr) { ins.Args[0].Mem.IndexExt = ExtendUXTW }},
				{"symbol", func(ins *Instr) { ins.Args[0].Mem.Sym = "$data(SB)" }},
				{"suffix", func(ins *Instr) { ins.Op += ".Z" }},
				{"immediate-raw", func(ins *Instr) {
					ins.Args = []Operand{{Kind: OpImm, ImmRaw: "$missing"}, ins.Args[0]}
				}},
				{"immediate-float", func(ins *Instr) {
					ins.Args = []Operand{{Kind: OpImm, ImmIsFloat: true}, ins.Args[0]}
				}},
			} {
				t.Run(arch+"/"+op+"/"+mutation.name, func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, op+" 0(CX)(TLS*1),AX")
					mutation.mutate(&ins)
					if err := x86SourceTLSMoveError(ins, arch); err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("invalid typed row hidden by TLS: %v", err)
					}
				})
			}
			ins := x86PureGPUnknownInstruction(t, op+" 0(CX)(TLS*1),AX")
			if err := x86SourceTLSMoveError(ins, "unknown"); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown mode hidden by TLS: %v", err)
			}
		}
	}
	for _, op := range []string{"MOVL", "MOVQ"} {
		for _, body := range []string{op + " 0(CX)(TLS*1),X8", op + " X15,0(CX)(TLS*1)"} {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
			if err := x86SourceTLSMoveError(x86PureGPUnknownInstruction(t, body), "386"); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("386 high X bank hidden by TLS: %v", err)
			}
		}
	}
}

func TestX86TLSMoveMalformedSourceRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
			for _, operands := range []string{"AX,TLS", "TLS,TLS", "TLS,X0", "TLS,0(CX)(TLS*1)",
				"0(CX)(TLS*1),0(DX)(TLS*1)", "0(CX)(TLS*1),$1", "0(CX)(TLS*1),Y0", "0(CX)(TLS*1),K1",
				"$1.5,0(CX)(TLS*1)", "0(CX)(TLS*1)", "AX,0(CX)(TLS*1),BX"} {
				body := op + " " + operands
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
				ins := x86PureGPUnknownInstruction(t, body)
				if err := x86SourceTLSMoveError(ins, arch); err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("bad source row was hidden by TLS: %s %s: %v", arch, body, err)
				}
			}
		}
	}
}

func TestX86TLSMoveUnreachableSourceFailsClosed(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []string{"MOVB 8(TLS),AX", "MOVW AX,0(CX)(TLS*1)", "MOVL TLS,AX", "MOVQ 8(TLS),X0"} {
			for _, api := range []string{"text", "module", "Go"} {
				source := "TEXT ·probe(SB),4,$0-0\nJMP done\n" + row + "\ndone:\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func probe()", target.arch, target.triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s %s %s: unreachable TLS source escaped: %v\n%s", target.arch, row, api, err, ir)
				}
			}
		}
	}
}

func TestX86TLSAddressFallbackFailsClosed(t *testing.T) {
	for _, body := range []string{"ADDL 8(TLS),AX", "ANDL 8(TLS),AX", "ADDL 8(CX)(TLS*1),AX", "ANDL 8(CX)(TLS*1),AX"} {
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", true)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·probe(SB),4,$0-0\n"+body+"\nRET\n", "func probe()", "amd64", "x86_64-unknown-linux-gnu", api)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("%s %s: generic TLS address became zero: %v\n%s", body, api, err, ir)
			}
		}
	}
	context := &amd64Ctx{goarch: "amd64"}
	if value, err := context.loadReg(TLS); !errors.Is(err, ErrProbeNeedsContext) || value != "" {
		t.Fatalf("missing TLS slot invented a value: %q, %v", value, err)
	}
	if value, err := context.loadReg(AX); err != nil || value != "0" {
		t.Fatalf("ordinary missing-register behavior changed: %q, %v", value, err)
	}
}

func TestX86TLSMoveAPIsFailClosed(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86TLSMoveRows(target.arch, true) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row+"/"+api, func(t *testing.T) {
					source := "TEXT ·probe(SB),4,$0-0\n" + row + "\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func probe()", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("unbound TLS move must return Context and no IR: %v\n%s", err, ir)
					}
				})
			}
		}
	}
}
