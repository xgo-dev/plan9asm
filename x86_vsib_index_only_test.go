package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86VSIBIndexOnlySource(t *testing.T, name, operation, arch string) (source, declaration string) {
	t.Helper()
	form, known, err := x86VSIBProperties(x86ScalarLaneInstruction(t, operation), arch)
	if !known || err != nil || form.prefetch || form.memory.Mem.Base != "" {
		t.Fatalf("invalid original index-only form %s: %v", operation, err)
	}
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	var body strings.Builder
	fmt.Fprintf(&body, "TEXT ·%s(SB),4,$0-%d\n", name, 3*word)
	fmt.Fprintf(&body, "%s out+0(FP),DX\n%s indices+%d(FP),CX\n%s mask+%d(FP),SI\n", move, move, word, move, 2*word)
	fmt.Fprintf(&body, "VMOVUPS (CX),%s\nVMOVUPS (DX),%s\n", form.memory.Mem.Index, form.data.Reg)
	if form.evex {
		fmt.Fprintf(&body, "MOVL (SI),AX\nKMOVD AX,%s\n", form.mask.Reg)
	} else {
		fmt.Fprintf(&body, "VMOVUPS (SI),%s\n", form.mask.Reg)
	}
	fmt.Fprintln(&body, operation)
	if !form.scatter {
		fmt.Fprintf(&body, "VMOVUPS %s,(DX)\n", form.data.Reg)
	}
	body.WriteString("RET\n")
	return body.String(), fmt.Sprintf("func %s(out, indices, mask *[64]byte)\n", name)
}

func TestX86VSIBIndexOnlyOriginalGoObjects(t *testing.T) {
	rows := []string{
		"VPGATHERDQ Y0, 8(X4*1), Y6",
		"VPGATHERDQ Y0, 0(X4*1), Y6",
		"VGATHERDPD Y0, 8(X4*1), Y6",
		"VGATHERDPD Y0, 0(X4*1), Y6",
		"VGATHERDPS X3, 8(X4*1), X6",
		"VGATHERDPS X3, 0(X4*1), X6",
		"VPGATHERDD X3, 8(X4*1), X6",
		"VPGATHERDD X3, 0(X4*1), X6",
		"VPGATHERQQ X0, 0(X1*1), X2",
		"VPGATHERQQ Y0, 0(Y1*1), Y2",
		"VPGATHERDD 24(X4*2), K1, X6",
		"VPSCATTERQQ X6, K1, 8(X4*8)",
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var allSource, allDeclarations strings.Builder
			for index, row := range rows {
				source, declaration := x86VSIBIndexOnlySource(t, fmt.Sprintf("Value%d", index), row, target.arch)
				allSource.WriteString(source)
				allDeclarations.WriteString(declaration)
			}
			requireX86GoAssemblerResult(t, target.arch, allSource.String(), true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, allSource.String(), allDeclarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "load volatile i32") || !strings.Contains(ir, "load volatile i64") ||
						!strings.Contains(ir, "store volatile i64") {
						t.Fatal("index-only predicate lost an architectural memory effect")
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O0")
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86VSIBIndexOnlyActualInputs(t *testing.T) {
	const instruction = "VPGATHERDQ Y0, 8(X4*1), Y6"
	source, declaration := x86VSIBIndexOnlySource(t, "Value", instruction, "amd64")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			control := strings.Replace(source, instruction, "VPGATHERDQ Y0, 8(DX)(X4*1), Y6", 1)
			ir, err := x86ScalarFPBitViewAPI(t, control, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || !strings.Contains(ir, "load volatile i64") {
				t.Fatal("initialized GP-base control did not retain its native access", err)
			}
			for _, initializer := range []string{"VMOVUPS (CX),X4\n", "VMOVUPS (DX),Y6\n", "VMOVUPS (SI),Y0\n"} {
				mutated := strings.Replace(source, initializer, "", 1)
				if mutated == source {
					t.Fatal("input control did not remove an initializer")
				}
				ir, err := x86ScalarFPBitViewAPI(t, mutated, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("missing input %q received an index-only proof: %v", initializer, err)
				}
			}
		})
	}
}

func TestX86VSIBIndexOnlyDisplacementDomain(t *testing.T) {
	ins := x86ScalarLaneInstruction(t, "VPGATHERDQ Y0, 2147483648(X4*1), Y6")
	if _, known, err := x86VSIBProperties(ins, "amd64"); !known || err == nil {
		t.Fatalf("amd64 accepted a displacement outside signed disp32: %v", err)
	}
	if _, known, err := x86VSIBProperties(ins, "386"); !known || err != nil {
		t.Fatalf("386 rejected the unsigned disp32 spelling: %v", err)
	}
}
