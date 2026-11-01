//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixedLocalLogicalLiteralRequireBinding(t *testing.T, assembly string) {
	t.Helper()
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
		"func Value(input, output *byte)\n", "linux/amd64", "x86_64-unknown-linux-gnu")
	// A real successful original-Go observation precedes the translator
	// assertion. Assembler/tool failures cannot stand in for this RED.
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	if _, err := source.BindFixedLocal(ctx, pkg, file, options); err != nil {
		t.Fatal("complete original source lost constant-mask byte dependencies", err)
	}
}

func TestGoAMD64FixedLocalLogicalLiteralPartialInsert(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	fixedLocalLogicalLiteralRequireBinding(t,
		fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PAND", 0, 16, false}, false))
}

func TestGoAMD64FixedLocalLogicalLiteralCompleteFormats(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	rows := fixedLocalLogicalLiteralCases()
	if len(rows) != 36 {
		t.Fatal("independent logical family/legacy-X/VEX-X-Y inventory changed", len(rows))
	}
	for _, row := range rows {
		t.Run(fmt.Sprintf("%s/%d", row.opcode, row.width), func(t *testing.T) {
			fixedLocalLogicalLiteralRequireBinding(t, fixedLocalLogicalLiteralSource(row, false))
		})
	}
}

func TestGoAMD64FixedLocalLogicalLiteralNoRegisterRead(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	count := 0
	for _, row := range fixedLocalLogicalLiteralCases() {
		// Select the integer spelling once per operation and vector width.
		name := strings.TrimPrefix(row.opcode, "V")
		if name != "PAND" && name != "PANDN" && name != "POR" {
			continue
		}
		count++
		t.Run(fmt.Sprintf("%s/%d", row.opcode, row.width), func(t *testing.T) {
			fixedLocalLogicalLiteralRequireBinding(t, fixedLocalLogicalLiteralSource(row, true))
		})
	}
	if count != 9 {
		t.Fatal("complete constant annihilator inventory changed", count)
	}
}

func TestGoAMD64FixedLocalLogicalLiteralAccessGuards(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	and := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PAND", 0, 16, false}, false)
	andNot := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PANDN", 1, 16, false}, false)
	or := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"POR", 2, 16, false}, false)
	xor := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PXOR", 3, 16, false}, false)
	zero := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PAND", 0, 16, false}, true)
	for _, row := range []struct{ name, source string }{
		{"AND retains one unknown bit", strings.Replace(and, "/8,$0x0\n", "/8,$0x1\n", 1)},
		{"ANDNOT retains one unknown bit", strings.Replace(andNot, "/8,$0x0\n", "/8,$0x1\n", 1)},
		{"OR retains one unknown bit", strings.Replace(or, "$0xffffffffffffffff", "$0xfffffffffffffffe", 1)},
		{"XOR keeps every input", strings.Replace(xor, "MOVOU (DI),X5", "PINSRD $3,(DI),X5", 1)},
		{"missing selected lane", strings.Replace(and, "PINSRD $3,(DI),X5\n", "", 1)},
		{"zero still needs extent", strings.Replace(zero, "PAND mask<>(SB)", "PAND mask<>+1(SB)", 1)},
		{"zero still needs alignment", strings.Replace(strings.Replace(zero,
			"GLOBL mask<>(SB),8,$16", "GLOBL mask<>(SB),8,$32", 1), "PAND mask<>(SB)", "PAND mask<>+1(SB)", 1)},
		{"mutable bytes are not constants", strings.Replace(zero, "GLOBL mask<>(SB),8,", "GLOBL mask<>(SB),0,", 1)},
		{"native memory supplies no constant", strings.Replace(and, "PAND mask<>(SB)", "PAND (DI)", 1)},
		{"register value is not tracked constant", strings.Replace(and,
			"PAND mask<>(SB)", "MOVOU mask<>(SB),X7\nPAND X7", 1)},
		{"readonly write remains forbidden", strings.Replace(zero,
			"MOVOU X5,0(SP)", "MOVOU X5,mask<>(SB)\nMOVOU X5,0(SP)", 1)},
		{"numeric result supplies no pointer", strings.Replace(zero,
			"MOVOU X5,0(SP)", "MOVQ X5,BX\nMOVQ (BX),AX\nMOVOU X5,0(SP)", 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, request, file, options := fixedLocalTransportFixture(t, row.source,
				"func Value(input, output *byte)\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("constant mask removed an independent input or storage requirement", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalLogicalLiteralOwnerLifetime(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	assembly := fixedLocalLogicalLiteralSource(fixedLocalLogicalLiteralCase{"PAND", 0, 16, false}, false)
	for _, mutation := range []string{"unbound", "public DATA", "original DATA", "closed", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
				"func Value(input, output *byte)\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("valid owner control failed before lifetime mutation", err)
			}
			input := assembly
			switch mutation {
			case "unbound":
				bound = options
			case "public DATA":
				input = strings.Replace(assembly, "/8,$0x0\n", "/8,$0x1\n", 1)
				file, err = Parse(ArchAMD64, input)
				if err != nil {
					t.Fatal(err)
				}
			case "original DATA":
				path := filepath.Join(request.Directory, request.AssemblyFile)
				changed := strings.Replace(assembly, "/8,$0x0\n", "/8,$0x1\n", 1)
				if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			}
			// Retain the original binding, including its revoked lifetime.
			fixedLocalDataAPIs(t, pkg, file, input, bound, fixedLocalRequireContext)
		})
	}
}
