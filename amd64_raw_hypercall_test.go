package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// KVM defines both vendor encodings of the same zero-operand hypercall ABI:
// https://docs.kernel.org/virt/kvm/x86/hypercalls.html
func TestX86RawKVMHypercallFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, op := range []struct {
		name string
		last byte
	}{
		{name: "VMCALL", last: 0xc1},
		{name: "VMMCALL", last: 0xd9},
	} {
		for _, target := range []struct {
			arch, triple string
		}{
			{"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-apple-darwin"},
			{"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"},
			{"386", "i686-pc-windows-msvc"},
		} {
			t.Run(op.name+"/"+target.triple, func(t *testing.T) {
				source := fmt.Sprintf(`TEXT hypercall(SB),$0-0
	MOVL $9, AX
	MOVL $17, BX
	MOVL $23, CX
	MOVL $29, DX
	MOVL $31, SI
	BYTE $0x0f; BYTE $0x01; BYTE $0x%02x
	RET
`, op.last)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := decodeX86RawDirectives(file.Funcs[0], target.arch)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.Instrs[len(decoded.Instrs)-2].Op != Op(op.name) {
					t.Fatalf("wrong hypercall decoding: %+v", decoded.Instrs)
				}
				word := I64
				if target.arch == "386" {
					word = I32
				}
				ir, err := Translate(file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"hypercall": {Name: "hypercall", Ret: word}},
				})
				if target.arch == "386" {
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("logical mode32 scalar result acquired a raw/native entry contract", err)
					}
					normalized, err := normalizeX86RawFile(file, target.arch)
					if err != nil {
						t.Fatal(err)
					}
					// Retain the actual hypercall opcode/constraints and AX
					// return as an object, not an executable logical ABI proof.
					ir = x86ScalarFormatObjectUnit(t, normalized,
						map[string]FuncSig{"hypercall": {Name: "hypercall", Ret: word}}, target.arch, target.triple, 0)
				} else if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{
					`asm sideeffect "` + strings.ToLower(op.name) + `"`,
					`={ax},0,{bx},{cx},{dx},{si},`, `~{memory}`,
				} {
					if !strings.Contains(ir, want) {
						t.Fatalf("missing hypercall ABI %q", want)
					}
				}
				compileLLVMToObject(t, llc, target.triple, "hypercall.ll", "hypercall.o", ir)
			})
		}
	}
}

func TestX86KVMHypercallRejectsExplicitOperandsAndSuffixes(t *testing.T) {
	for _, instruction := range []string{"VMCALL AX", "VMMCALL AX", "VMCALL.Z", "VMMCALL.Z"} {
		file, err := Parse(ArchAMD64, "TEXT invalid(SB),$0-0\n"+instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{
			Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}},
		})
		if err == nil {
			t.Fatalf("accepted invalid hypercall %q", instruction)
		}
	}
}
