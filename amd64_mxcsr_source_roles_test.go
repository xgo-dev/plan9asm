package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

type x86MXCSRBoundMemoryForm struct {
	name, source, declaration, intrinsic string
	local                                bool
}

func x86MXCSRBoundMemoryForms(t *testing.T, arch string) []x86MXCSRBoundMemoryForm {
	t.Helper()
	const declaration = "func view(input uint32) uint32"
	var rows []x86MXCSRBoundMemoryForm
	for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
		write := strings.Contains(op, "STMXCSR")
		intrinsic := "@llvm.x86.sse.ldmxcsr"
		if write {
			intrinsic = "@llvm.x86.sse.stmxcsr"
		}
		for _, role := range []string{"AUTO", "FP"} {
			body := op + " input+0(FP)\nSTMXCSR ret+RESULT(FP)"
			if write {
				body = op + " ret+RESULT(FP)"
			}
			if role == "AUTO" {
				body = "MOVL $0x1f80,saved-4(SP)\n" + op + " saved-4(SP)\nSTMXCSR ret+RESULT(FP)"
				if write {
					body = op + " saved-4(SP)\nMOVL saved-4(SP),AX\nMOVL AX,ret+RESULT(FP)"
				}
			}
			source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
			if role == "AUTO" {
				source = strings.Replace(source, ",$0-", ",$8-", 1)
			}
			rows = append(rows, x86MXCSRBoundMemoryForm{op + "/" + role, source, declaration, intrinsic, role == "AUTO"})
		}
	}
	for _, op := range []string{"LDMXCSR", "VLDMXCSR"} {
		const data = "DATA control<>+0(SB)/4,$0x1f80\nGLOBL control<>(SB),8,$4\n"
		body := op + " control<>(SB)\nSTMXCSR ret+RESULT(FP)"
		source := data + x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
		rows = append(rows, x86MXCSRBoundMemoryForm{op + "/DATA", source, declaration, "@llvm.x86.sse.ldmxcsr", false})
	}
	if len(rows) != 10 {
		t.Fatal("complete independent MXCSR storage-role denominator changed")
	}
	return rows
}

// Preserve the exact former mixed-syntax source. Neither its zero frame,
// undefined GP inputs nor external SB symbol supplies initialized storage.
const x86MXCSRUnboundOriginalSource = `
TEXT mxcsrstateforms(SB),NOSPLIT,$0-8
	LDMXCSR (AX)
	LDMXCSR -8(SP)
	LDMXCSR control(SB)
	LDMXCSR input+0(FP)
	VLDMXCSR (AX)
	VLDMXCSR control(SB)
	STMXCSR 4(BX)
	STMXCSR -8(SP)
	STMXCSR control(SB)
	STMXCSR output+4(FP)
	VSTMXCSR (AX)
	VSTMXCSR output+4(FP)
	RET
`

func TestTranslateAMD64MXCSRStateOriginalUnboundSourceRetainsContext(t *testing.T) {
	file, err := Parse(ArchAMD64, x86MXCSRUnboundOriginalSource)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{TargetTriple: "x86_64-unknown-linux-gnu", Goarch: "amd64",
		Sigs: map[string]FuncSig{"mxcsrstateforms": {
			Name: "mxcsrstateforms", Args: []LLVMType{I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
			},
		}},
	}
	if ir, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
		t.Fatalf("original unbound mixed source acquired frame/native memory: %v", err)
	}
}

func TestX86MXCSRStorageRolesCannotBorrowSyntaxAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
			write := strings.Contains(op, "STMXCSR")
			rows := []struct{ name, declaration, body, data string }{
				{"unbound GP", "func view() uint32", op + " (AX)\nMOVL $7,ret+RESULT(FP)", ""},
				{"overwritten typed native pointer", "func view(p *[2]uint32) uint32", move + " p+0(FP),AX\nMOVW $0,AX\n" + op + " 4(AX)\nMOVL $7,ret+RESULT(FP)", ""},
				{"undefined SB", "func view() uint32", op + " control(SB)\nMOVL $7,ret+RESULT(FP)", ""},
			}
			if write {
				rows = append(rows, struct{ name, declaration, body, data string }{
					"defined mutable DATA store", "func view() uint32", op + " control<>+4(SB)\nMOVL $7,ret+RESULT(FP)",
					"DATA control<>+0(SB)/4,$0x1f80\nGLOBL control<>(SB),0,$8\n",
				})
			} else {
				rows = append(rows, struct{ name, declaration, body, data string }{
					"insufficient emitted DATA", "func view() uint32", op + " control<>(SB)\nSTMXCSR ret+RESULT(FP)",
					"GLOBL control<>(SB),8,$3\n",
				})
			}
			for _, row := range rows {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+op+"/"+row.name+"/"+api, func(t *testing.T) {
						source := row.data + x86ResultGPSIMDAdmissionSource(t, arch, row.declaration, row.body)
						if ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("MXCSR operand syntax granted an unclosed storage role: %v", err)
						}
					})
				}
			}
		}
	}
}
