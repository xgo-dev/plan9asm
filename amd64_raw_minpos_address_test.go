package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func x86MinimumPositionOriginalGoBytes(t *testing.T, arch, source string) []byte {
	t.Helper()
	listing, err := x86ScalarLiteralGoListing(t, arch, source)
	if err != nil {
		t.Fatal(err)
	}
	var code []byte
	for _, line := range strings.Split(listing, "\n") {
		text := strings.TrimLeft(line, "\t ")
		fields := strings.Fields(text)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		start := strings.IndexByte(text, ' ')
		if err != nil || int(offset) != len(code) || start < 0 || len(text) < start+48 {
			t.Fatalf("incomplete/noncontiguous stock Go hex row: %s", line)
		}
		gap := false
		for column := 0; column < 16; column++ {
			field := text[start+3*column : start+3*(column+1)]
			if field == "   " {
				gap = true
				continue
			}
			value, err := strconv.ParseUint(field[1:], 16, 8)
			if gap || field[0] != ' ' || err != nil {
				t.Fatalf("invalid stock Go hex column: %q", field)
			}
			code = append(code, byte(value))
		}
	}
	if len(code) == 0 {
		t.Fatal("stock Go omitted the original instruction bytes")
	}
	return code
}

func TestX86RawMinimumPositionInactiveSIBScalePhysicalWitness(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		for shift := byte(0); shift < 4; shift++ {
			// Original legacy PHMINPOSUW 8192(SP),X0. SIB.index=4
			// suppresses the index; all four scale bit patterns are ignored.
			code := []byte{0x66, 0x0f, 0x38, 0x41, 0x84, 0x24 | shift<<6, 0, 0x20, 0, 0}
			original := append([]byte(nil), code...)
			x86HandoffOriginalBytes(t, arch, code)
			physical, err := x86asm.Decode(code, mode)
			memory, ok := physical.Args[1].(x86asm.Mem)
			base := x86asm.RSP
			if mode == 32 {
				base = x86asm.ESP
			}
			if err != nil || physical.Len != len(code) || physical.Op != x86asm.PHMINPOSUW ||
				!ok || memory.Base != base || memory.Index != 0 || memory.Scale != 1<<shift || memory.Disp != 8192 {
				t.Fatalf("independent full SIB witness: %+v %v", physical, err)
			}
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			want := Operand{Kind: OpMem, Mem: MemRef{Base: SP, Scale: 1 << shift, Off: 8192}}
			if err != nil || len(decoded.Instrs) != 1 || len(decoded.Instrs[0].Args) != 2 ||
				!reflect.DeepEqual(decoded.Instrs[0].Args[0], want) {
				t.Fatalf("decoder discarded its physical SIB metadata: %+v %v", decoded, err)
			}
			if !bytes.Equal(code, original) {
				t.Fatal("physical witness modified its original instruction bytes")
			}
		}
	}
}

func x86MinimumPositionAddressSources(arch, name, terminal string) (complete, bounded string, completeCount, boundedCount int) {
	registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
	if arch == "amd64" {
		for i := 8; i < 16; i++ {
			registers = append(registers, fmt.Sprintf("R%d", i))
		}
	}
	var addresses, objectAddresses []string
	for _, base := range registers {
		for _, offset := range []int64{0, -128, 127, -129, 128, 8192, -2147483648, 2147483647} {
			addresses = append(addresses, fmt.Sprintf("%d(%s)", offset, base))
		}
		// Both extreme SP offsets belong to the Go encoding domain. Their
		// combined synthetic allocation exceeds 4 GiB, separately observed
		// below. Declare the finite LLVM object domain before translation;
		// never infer it from llc success. Other GP disp32 extremes remain.
		objectOffsets := []int64{0, -128, 127, -129, 128, 8192}
		if base != "SP" {
			objectOffsets = append(objectOffsets, -2147483648, 2147483647)
		}
		for _, offset := range objectOffsets {
			objectAddresses = append(objectAddresses, fmt.Sprintf("%d(%s)", offset, base))
		}
	}
	for _, index := range registers {
		if index == "SP" {
			continue // SIB.index=4 is the absent-index witness above.
		}
		for _, scale := range []int{1, 2, 4, 8} {
			indexed := []string{fmt.Sprintf("-7(BP)(%s*%d)", index, scale), fmt.Sprintf("8192(%s*%d)", index, scale)}
			addresses = append(addresses, indexed...)
			objectAddresses = append(objectAddresses, indexed...)
		}
	}
	build := func(addresses []string) string {
		var source strings.Builder
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
		for _, op := range []string{"PHMINPOSUW", "VPHMINPOSUW"} {
			for _, address := range addresses {
				fmt.Fprintf(&source, "%s %s,X0\n", op, address)
			}
		}
		fmt.Fprintln(&source, terminal)
		return source.String()
	}
	return build(addresses), build(objectAddresses), 2 * len(addresses), 2 * len(objectAddresses)
}

func TestX86RawMinimumPositionGoAddressFormsAllAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, objectSource, completeCount, boundedCount := x86MinimumPositionAddressSources(arch, "addresses", "RET")
			code := x86MinimumPositionOriginalGoBytes(t, arch, source)
			parsed, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil || len(decoded.Instrs) != len(parsed.Funcs[0].Instrs)-1 {
				t.Fatalf("complete original instruction sequence: %+v %v", decoded, err)
			}
			for i, instruction := range decoded.Instrs {
				want := parsed.Funcs[0].Instrs[i+1]
				if instruction.Op != want.Op || !x86RawOperandsMatchGoSource(instruction.Args, want.Args) {
					t.Fatalf("original Go address %d %s: physical=%#v source=%#v", i, want.Raw, instruction.Args, want.Args)
				}
			}
			objectCode := x86MinimumPositionOriginalGoBytes(t, arch, objectSource)
			file := x86RawStackObservingFormProbeFile(t, arch, "addresses", objectCode)
			before := fmt.Sprintf("%#v", file.Funcs)
			for _, target := range x86RawReturnTargets {
				if target.arch != arch {
					continue
				}
				t.Run(target.triple, func(t *testing.T) {
					// The helper first checks the complete Go object and all
					// three public Context APIs, then emits a private format unit.
					ir := x86UnboundBlendMinposProbeObject(t, file, arch, target.triple)
					if before != fmt.Sprintf("%#v", file.Funcs) {
						t.Fatal("public translation changed its original raw source")
					}
					compileLLVMToObject(t, llc, target.triple, "addresses.ll", "addresses.o", ir)
				})
			}
			t.Logf("actual Go address encodings=%d; bounded LLVM probe encodings=%d; original SP extremes remain an allocator limitation, not N/A or native stack/return permission", completeCount, boundedCount)
		})
	}
}
