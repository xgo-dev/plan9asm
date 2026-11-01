package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func x86LogicalOpcodeNames() []Op {
	names := make([]Op, 0, len(x86PackedLogicalSpecs))
	for opcode := range x86PackedLogicalSpecs {
		names = append(names, opcode)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}

func TestX86PackedLogicalSpecsBindEveryGoOpcodeAttribute(t *testing.T) {
	if len(x86PackedLogicalSpecs) != 32 {
		t.Fatal("incomplete packed logical family")
	}
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	dir := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range x86LogicalOpcodeNames() {
		spec := x86PackedLogicalSpecs[opcode]
		if spec.encoding <= x86PackedLogicalLegacyInteger {
			row := "{A" + string(opcode) + ", "
			start := strings.Index(string(legacy), row)
			if start < 0 {
				t.Fatalf("Go omits %s", opcode)
			}
			line := strings.SplitN(string(legacy)[start:], "\n", 2)[0]
			table := "yxm"
			if spec.encoding == x86PackedLogicalLegacyInteger {
				table = "ymm"
			}
			if !strings.Contains(line, ", "+table+",") {
				t.Fatalf("Go legacy row differs: %s", line)
			}
			continue
		}
		prefix := "{as: A" + string(opcode) + ", ytab: "
		start := strings.Index(string(avx), prefix)
		if start < 0 {
			t.Fatalf("Go omits %s", opcode)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		table := "_yvandnpd"
		if spec.encoding == x86PackedLogicalVEX {
			table = "_yvaddsubpd"
		}
		if spec.encoding == x86PackedLogicalEVEX {
			table = "_yvblendmpd"
		}
		if !strings.HasPrefix(row, prefix+table+",") {
			t.Fatalf("Go ytab changed for %s", opcode)
		}
		if spec.encoding == x86PackedLogicalVEX {
			if strings.Contains(row, "evex") || spec.broadcastBytes != 0 || spec.zeroing {
				t.Fatalf("VEX attributes changed: %s", row)
			}
			continue
		}
		for _, line := range strings.Split(row, "\n") {
			if !strings.Contains(line, "avxEscape | evex") {
				continue
			}
			if !strings.Contains(line, fmt.Sprintf("evexBcstN%d", spec.broadcastBytes)) || !strings.Contains(line, "evexZeroingEnabled") ||
				strings.Contains(line, "evexSae") || strings.Contains(line, "evexRounding") {
				t.Fatalf("%s opcode attributes disagree with Go: %s", opcode, line)
			}
		}
	}
}

// Rows come from the actual yxm/ymm, _yvaddsubpd, _yvandnpd and
// _yvblendmpd tables; memory and all opcode-specific suffix axes are included.
func x86LogicalAcceptedForms(opcode Op, arch string) []string {
	spec := x86PackedLogicalSpecs[opcode]
	if spec.encoding <= x86PackedLogicalLegacyInteger {
		last := 15
		if arch == "386" {
			last = 7
		}
		rows := []string{fmt.Sprintf("%s X0,X%d", opcode, last), fmt.Sprintf("%s 8(AX),X%d", opcode, last)}
		if spec.encoding == x86PackedLogicalLegacyInteger && arch == "amd64" {
			rows = append(rows, fmt.Sprintf("%s M0,M7", opcode), fmt.Sprintf("%s 8(AX),M7", opcode))
		}
		return rows
	}
	var rows []string
	widths := []string{"X", "Y", "Z"}
	if spec.encoding == x86PackedLogicalVEX {
		widths = widths[:2]
	}
	for _, width := range widths {
		last := 31
		if spec.encoding == x86PackedLogicalVEX {
			last = 15
		}
		if arch == "386" && width == "Z" {
			last = 7
		}
		dest := fmt.Sprintf("%s%d", width, last)
		rows = append(rows, fmt.Sprintf("%s %s0,%s1,%s", opcode, width, width, dest), fmt.Sprintf("%s 8(AX),%s1,%s", opcode, width, dest))
		if spec.broadcastBytes == 0 {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s.BCST 8(AX),%s1,%s", opcode, width, dest))
		if arch == "386" {
			continue
		}
		rows = append(rows,
			fmt.Sprintf("%s %s0,%s1,K7,%s", opcode, width, width, dest),
			fmt.Sprintf("%s.Z %s0,%s1,K1,%s", opcode, width, width, dest),
			fmt.Sprintf("%s 8(AX),%s1,K7,%s", opcode, width, dest),
			fmt.Sprintf("%s.Z 8(AX),%s1,K1,%s", opcode, width, dest),
			fmt.Sprintf("%s.BCST 8(AX),%s1,K7,%s", opcode, width, dest),
			fmt.Sprintf("%s.BCST.Z 8(AX),%s1,K1,%s", opcode, width, dest))
	}
	return rows
}

func TestX86PackedLogicalCompleteGoRowsAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source, goSource strings.Builder
			source.WriteString("TEXT logicalforms(SB),$0-0\n")
			goSource.WriteString("TEXT logicalforms(SB),$0-0\n")
			for _, op := range x86LogicalOpcodeNames() {
				for _, row := range x86LogicalAcceptedForms(op, target.arch) {
					fmt.Fprintln(&goSource, row)
					if target.arch == "386" {
						// Preserve Go's full source grammar independently. LLVM
						// object generation requires physically bound registers.
						row = strings.NewReplacer("X31", "X7", "Y31", "Y7", "X15", "X7", "Y15", "Y7").Replace(row)
					}
					fmt.Fprintln(&source, row)
					parsed, err := Parse(ArchAMD64, "TEXT one(SB),$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					if _, recognized, err := x86PackedLogicalProperties(parsed.Funcs[0].Instrs[1], target.arch); !recognized || err != nil {
						t.Fatalf("%s: %v", row, err)
					}
				}
			}
			source.WriteString("RET\n")
			goSource.WriteString("RET\n")
			requireX86GoAssemblerResult(t, target.arch, goSource.String(), true)
			ir := x86UnboundVoidScalarFormatObject(t, source.String(), "logicalforms", target.arch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "logical.ll", "logical.o", ir)
		})
	}
}

func TestX86PackedLogicalRejectsInvalidFormsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range x86LogicalOpcodeNames() {
			spec := x86PackedLogicalSpecs[opcode]
			args := "X0,X1,X2"
			if spec.encoding <= x86PackedLogicalLegacyInteger {
				args = "X0,X1"
			}
			rows := []string{string(opcode) + ".SAE " + args, string(opcode) + ".RN_SAE " + args, string(opcode) + ".Z.Z " + args,
				string(opcode) + " $3," + args, string(opcode) + " X0,(AX)", string(opcode) + " X0,Y1", string(opcode) + " X0,X1,X2,X3"}
			memoryTail := ",X0,X1"
			if spec.encoding <= x86PackedLogicalLegacyInteger {
				memoryTail = ",X0"
			}
			rows = append(rows, string(opcode)+" (AX)(CX*3)"+memoryTail, string(opcode)+" (AX)(SP*1)"+memoryTail)
			if spec.encoding <= x86PackedLogicalLegacyInteger {
				rows = append(rows, string(opcode)+" X16,X0", string(opcode)+".BCST 8(AX),X0")
				if spec.encoding == x86PackedLogicalLegacyFP {
					rows = append(rows, string(opcode)+" M0,M1")
				}
			} else {
				rows = append(rows, string(opcode)+".Z X0,X1,X2", string(opcode)+" X0,X1,K0,X2", string(opcode)+".BCST X0,X1,X2",
					string(opcode)+".Z.BCST (AX),X0,K1,X1")
				if spec.encoding == x86PackedLogicalVEX {
					rows = append(rows, string(opcode)+" Z0,Z1,Z2", string(opcode)+" X16,X1,X2", string(opcode)+".BCST (AX),X0,X1", string(opcode)+" X0,X1,K1,X2")
				}
			}
			if arch == "386" {
				rows = append(rows, string(opcode)+" 8(R9),"+args)
			}
			for _, row := range rows {
				t.Run(arch+"/"+row, func(t *testing.T) {
					assembly := "TEXT bad(SB),$0-0\n" + row + "\nRET\n"
					requireX86GoAssemblerResult(t, arch, assembly, false)
					file, err := Parse(ArchAMD64, assembly)
					if err != nil {
						return
					}
					instruction := file.Funcs[0].Instrs[1]
					ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := out.String()
					ok, term, err := ctx.lowerPackedLogicalFamily(instruction.Op, instruction)
					if !ok || term || err == nil || out.String() != before {
						t.Fatalf("invalid form emitted (%v,%v,%v)", ok, term, err)
					}
				})
			}
		}
	}
}

func TestX86PackedLogicalDispatchIdentityBeforeEmission(t *testing.T) {
	for _, opcode := range x86LogicalOpcodeNames() {
		for _, sourceOp := range []Op{"", opcode, Op(strings.ToLower(string(opcode))), "UNKNOWN", "MOVQ"} {
			row := x86LogicalAcceptedForms(opcode, "amd64")[0]
			file, err := Parse(ArchAMD64, "TEXT one(SB),$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			instruction.Op = sourceOp
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			ok, term, err := ctx.lowerPackedLogicalFamily(opcode, instruction)
			if sourceOp == "UNKNOWN" || sourceOp == "MOVQ" {
				if !ok || term || err == nil || out.String() != before {
					t.Fatalf("%s/%s conflicting helper identity emitted", opcode, sourceOp)
				}
			} else if !ok || term || err != nil {
				t.Fatalf("%s/%s helper compatibility lost: %v", opcode, sourceOp, err)
			}
			if instruction.Op != sourceOp {
				t.Fatal("helper rewrote source identity")
			}
		}
	}
}

func TestX86PackedLogicalSymbolAddressIsNotMemory(t *testing.T) {
	for _, opcode := range x86LogicalOpcodeNames() {
		t.Run(string(opcode), func(t *testing.T) {
			args := "X0,X1"
			if x86PackedLogicalSpecs[opcode].encoding <= x86PackedLogicalLegacyInteger {
				args = "X0"
			}
			source := "TEXT bad(SB),$0-0\n" + string(opcode) + " $symbol(SB)," + args + "\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			instruction := file.Funcs[0].Instrs[1]
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			ok, term, err := ctx.lowerPackedLogicalFamily(instruction.Op, instruction)
			if !ok || term || err == nil || out.String() != before {
				t.Fatalf("symbol address acquired memory load/emission: (%v,%v,%v)", ok, term, err)
			}
		})
	}
}

func TestX86PackedLogicalMemoryDisplacementMatchesGoEncoding(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range x86LogicalOpcodeNames() {
			args := "X0,X1"
			if x86PackedLogicalSpecs[opcode].encoding <= x86PackedLogicalLegacyInteger {
				args = "X0"
			}
			invalid := []int64{-2147483649, 4294967296}
			if arch == "amd64" {
				invalid = append(invalid, 2147483648, 4294967295)
			}
			for _, displacement := range invalid {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, opcode, displacement), func(t *testing.T) {
					source := fmt.Sprintf("TEXT bad(SB),$0-0\n%s %d(AX)(CX*2),%s\nRET\n", opcode, displacement, args)
					requireX86GoAssemblerResult(t, arch, source, false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					instruction := file.Funcs[0].Instrs[1]
					ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := out.String()
					ok, term, err := ctx.lowerPackedLogicalFamily(instruction.Op, instruction)
					if !ok || term || err == nil || out.String() != before {
						t.Fatalf("unencodable displacement emitted: (%v,%v,%v)", ok, term, err)
					}
				})
			}
		}
	}
}

func TestX86PackedLogicalBoundaryDisplacementsGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT boundaries(SB),$0-0\n")
			displacements := []int64{-2147483648, 2147483647}
			if target.arch == "386" {
				displacements = append(displacements, 2147483648, 4294967295)
			}
			for _, opcode := range x86LogicalOpcodeNames() {
				args := "X0,X1"
				if x86PackedLogicalSpecs[opcode].encoding <= x86PackedLogicalLegacyInteger {
					args = "X0"
				}
				for _, displacement := range displacements {
					fmt.Fprintf(&source, "%s %d(AX)(CX*2),%s\n", opcode, displacement, args)
				}
			}
			source.WriteString("RET\n")
			ir := x86UnboundVoidScalarFormatObject(t, source.String(), "boundaries", target.arch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "boundary.ll", "boundary.o", ir)
		})
	}
}
