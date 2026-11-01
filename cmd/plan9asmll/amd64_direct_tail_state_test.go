package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
)

const amd64DirectTailDeclarations = `package p
func First(a uint64) uint64
func Second(a, b uint64) uint64
`

func amd64DirectTailSource(helper string, entryEffect, helperBody string) string {
	return fmt.Sprintf(`TEXT ·First<ABIInternal>(SB),NOSPLIT,$0-16
 MOVQ AX,SI
 MOVQ $7,DI
 %s
 JMP %s<>(SB)
TEXT ·Second<ABIInternal>(SB),NOSPLIT,$0-24
 MOVQ AX,SI
 MOVQ BX,DI
 %s
 JMP %s<>(SB)
TEXT %s<>(SB),NOSPLIT,$0-0
 %s
`, entryEffect, helper, entryEffect, helper, helper, helperBody)
}

func amd64DirectTailIR(t *testing.T, source, api string) (string, error) {
	t.Helper()
	return amd64DirectTailDeclaredIR(t, amd64DirectTailDeclarations, source, api)
}

func amd64DirectTailDeclaredIR(t *testing.T, declarations, source, api string) (string, error) {
	t.Helper()
	pkg, _ := continuationPackage(t, declarations, source)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
	if err != nil {
		return "", err
	}
	before, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve}
	// A private tail node has no independent callable frame. Start this
	// complete-source fixture from its actual typed roots and terminals; the
	// translator still proves every helper edge, input and return obligation.
	sigs, _, needed, err := x86SDKDirectTailDeclarationInventory(plan9asm.GoPackage{
		Path: pkg.PkgPath, Types: pkg.Types, Syntax: pkg.Syntax,
	}, file, options)
	if err == nil && !needed {
		sigs, _, err = sigsForAsmFile(pkg, file, resolve, "amd64")
	}
	if err != nil {
		return "", err
	}
	options.Sigs = sigs
	defer func() {
		if !reflect.DeepEqual(file, before) {
			t.Error("translation changed original TEXT/instruction/operand/Raw identity")
		}
	}()
	if api == "text" {
		return plan9asm.Translate(file, options)
	}
	var module llvm.Module
	if api == "module" {
		module, err = plan9asm.TranslateModule(file, options)
	} else {
		context := llvm.NewContext()
		defer context.Dispose()
		module, err = plan9asm.TranslateModuleInContext(context, file, options)
	}
	if err != nil {
		return "", err
	}
	defer module.Dispose()
	return module.String(), nil
}

// Both real ABI0 roots have result storage at +8, but different input widths
// and argument lists. The private TEXT has no callable parameter signature.
// This complete source is also the ordinary original-Go execution fixture;
// unlike an ABIInternal test probe, it needs no -std or SDK namespace override.
const amd64DirectTailABI0Declarations = `package p
func First(a uint64) uint64
func Second(a, b uint32) uint64
`

const amd64DirectTailABI0Source = `#include "textflag.h"
TEXT ·First(SB),NOSPLIT,$0-16
 MOVQ a+0(FP),SI
 MOVQ $7,DI
 JMP shared<>(SB)
TEXT ·Second(SB),NOSPLIT,$0-16
 MOVL a+0(FP),SI
 MOVL b+4(FP),DI
 JMP shared<>(SB)
TEXT shared<>(SB),NOSPLIT,$0-0
 MOVQ SI,AX
 ADDQ DI,AX
 MOVQ AX,ret+8(FP)
 RET
`

func TestAMD64DirectTailWholeSourceABI0DifferentWidthRoots(t *testing.T) {
	for _, api := range []string{"text", "module", "context"} {
		t.Run(api, func(t *testing.T) {
			ir, err := amd64DirectTailDeclaredIR(t, amd64DirectTailABI0Declarations, amd64DirectTailABI0Source, api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, `call i64 @"example.com/continuations.shared$local"()`) {
				t.Fatal("First(a)=a+7 / Second(a,b)=uint64(a)+uint64(b) lost SI/DI at a zero-argument helper call")
			}
		})
	}
}

func TestAMD64DirectTailWholeSourcePreservesTypedState(t *testing.T) {
	for _, test := range []struct {
		name, helper, entryEffect, helperBody string
	}{
		{"shared_GP", "shared", "NOP", "MOVQ SI,AX\n ADDQ DI,AX\n RET"},
		{"renamed_GP", "renamedTransport", "NOP", "MOVQ SI,AX\n ADDQ DI,AX\n RET"},
		{"shared_FLAGS", "flagTransport", "CMPQ SI,DI", "SETEQ AL\n MOVBLZX AL,AX\n RET"},
		{"shared_vector_and_FLAGS", "laneTransport", "MOVQ SI,X0\n CMPQ SI,DI", "MOVQ X0,AX\n ADCQ DI,AX\n RET"},
		{"vector_zero_extension", "zeroLane", "MOVL SI,X0", "MOVQ X0,AX\n ADDQ DI,AX\n RET"},
		{"chain", "head", "NOP", "JMP last<>(SB)\nTEXT last<>(SB),NOSPLIT,$0-0\n MOVQ SI,AX\n ADDQ DI,AX\n RET"},
		{"diamond", "fork", "CMPQ SI,DI", "JE left\n ADDQ $3,DI\n JMP joined<>(SB)\nleft:\n ADDQ $5,DI\n JMP joined<>(SB)\nTEXT joined<>(SB),NOSPLIT,$0-0\n MOVQ SI,AX\n ADDQ DI,AX\n RET"},
	} {
		for _, api := range []string{"text", "module", "context"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				source := amd64DirectTailSource(test.helper, test.entryEffect, test.helperBody)
				ir, err := amd64DirectTailIR(t, source, api)
				if err != nil {
					t.Fatalf("whole typed root/helper state cannot reach RET: %v", err)
				}
				// Every helper reads root-written state. A zero-argument call
				// to a separately initialized helper loses that state; neither
				// successful parsing nor object compilation repairs the loss.
				lost := regexp.MustCompile(`call i64 @"[^"\n]+\$local"\(\)`)
				if call := lost.FindString(ir); call != "" {
					t.Fatalf("root GP/vector/FLAGS transport is absent: %s; expected First(a)=a+7 and Second(a,b)=a+b for the shared GP body, not fresh helper state", call)
				}
			})
		}
	}
}

func TestAMD64DirectTailWholeSourceRejectsUnclosedRoles(t *testing.T) {
	base := amd64DirectTailSource("shared", "NOP", "MOVQ SI,AX\n ADDQ DI,AX\n RET")
	for _, test := range []struct{ name, source string }{
		{"missing", strings.ReplaceAll(base, "JMP shared<>(SB)", "JMP absent<>(SB)")},
		{"duplicate", base + "TEXT shared<>(SB),NOSPLIT,$0-0\n RET\n"},
		{"offset", strings.ReplaceAll(base, "JMP shared<>(SB)", "JMP shared<>+1(SB)")},
		{"CALL", strings.Replace(base, " MOVQ SI,AX", " CALL foreign(SB)\n MOVQ SI,AX", 1)},
		{"address_escape", strings.Replace(base, " JMP shared<>(SB)", " LEAQ shared<>(SB),CX\n JMP shared<>(SB)", 1)},
		{"DATA_escape", base + "DATA address<>+0(SB)/8,$shared<>(SB)\nGLOBL address<>(SB),RODATA,$8\n"},
		{"raw", strings.Replace(base, " MOVQ SI,AX", " BYTE $0x90\n MOVQ SI,AX", 1)},
		{"SP", strings.Replace(base, " MOVQ SI,AX", " MOVQ SP,AX", 1)},
		{"frame", strings.Replace(base, "TEXT shared<>(SB),NOSPLIT,$0-0", "TEXT shared<>(SB),NOSPLIT,$8-0", 1)},
		{"unknown_GP", strings.Replace(base, " MOVQ SI,AX", " MOVQ R15,AX", 1)},
		{"unknown_FLAGS", strings.Replace(base, " ADDQ DI,AX", " ADCQ DI,AX", 1)},
		{"unknown_vector", strings.Replace(base, " MOVQ SI,AX", " MOVQ X0,AX", 1)},
		{"partial_GP", strings.Replace(base, " MOVQ SI,AX", " MOVB $1,R15\n MOVQ R15,AX", 1)},
		{"unknown_vector_upper", strings.Replace(base, " MOVQ SI,AX", " MOVQ SI,X0\n VEXTRACTI128 $1,Y0,X1\n MOVQ X1,AX", 1)},
		{"root_join", strings.Replace(base, " MOVQ AX,SI", " CMPQ AX,AX\n JE joined\n MOVQ AX,SI\njoined:", 1)},
		{"closure_DX", strings.Replace(base, " MOVQ SI,AX", " MOVQ 8(DX),AX", 1)},
		{"native_g", strings.Replace(base, " MOVQ SI,AX", " MOVQ 8(R14),AX", 1)},
		{"foreign_ret_frame", strings.Replace(base, "TEXT shared<>(SB),NOSPLIT,$0-0", "TEXT shared<>(SB),NOSPLIT,$0-8", 1)},
		{"helper_storage_identity", base + "GLOBL shared<>(SB),RODATA,$8\n"},
		{"combined_budget", strings.Replace(base, " MOVQ SI,AX", strings.Repeat(" NOP\n", 4097)+" MOVQ SI,AX", 1)},
	} {
		for _, api := range []string{"text", "module", "context"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				if _, err := amd64DirectTailIR(t, test.source, api); err == nil {
					t.Fatal("unclosed whole-source tail role acquired state/continuation permission")
				}
			})
		}
	}
}
