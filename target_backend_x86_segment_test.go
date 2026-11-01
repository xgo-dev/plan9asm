package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestTargetBackendX86SegmentCompleteGPInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := append(x86GPFaultingReadCases(arch), x86GPSegmentCompareRows(arch)...)
			var fixtures []x86GPSegmentFixture
			for _, row := range rows {
				for _, segment := range []string{"FS", "GS"} {
					for _, live := range []bool{false, true} {
						name := fmt.Sprintf("Hardware%d", len(fixtures))
						fixtures = append(fixtures, x86GPSegmentSource(row, arch, name, segment, "fixed-zero", "", live))
					}
				}
			}
			x86GPSegmentGoObjects(t, arch, fixtures)
			for _, fixture := range fixtures {
				for _, triple := range []string{testTargetTriple("linux", arch), "", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fixture.row.family+"/"+fixture.row.instruction+"/"+fixture.label+"/"+triple+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, arch, triple, api)
							if triple == testTargetTriple("linux", arch) {
								if err != nil || !strings.Contains(ir, "ptr addrspace(") {
									t.Fatal("fully initialized segment source lost its matching target", err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("ACTUAL_SEGMENT_ACCESS_ESCAPED_BACKEND", len(ir), err)
							}
						})
					}
				}
			}
		})
	}
}

func TestTargetBackendX86SegmentActualMemoryUses(t *testing.T) {
	type memoryUse struct {
		name, declaration, body string
		hardware                bool
	}
	rows := []memoryUse{
		{"load", "", "%v = load volatile i32, ptr addrspace(SEG) null\nret void", true},
		{"store", "", "store volatile i32 1, ptr addrspace(SEG) null\nret void", true},
		{"atomic-rmw", "", "%v = atomicrmw add ptr addrspace(SEG) null, i32 1 seq_cst\nret void", true},
		{"atomic-cas", "", "%v = cmpxchg ptr addrspace(SEG) null, i32 1, i32 2 seq_cst seq_cst\nret void", true},
		{"called-address", "declare void @consumer(ptr addrspace(SEG))", "call void @consumer(ptr addrspace(SEG) null)\nret void", true},
		{"memory-intrinsic", "declare void @llvm.memcpy.pSEG.p0.i64(ptr addrspace(SEG), ptr, i64, i1)",
			"call void @llvm.memcpy.pSEG.p0.i64(ptr addrspace(SEG) null, ptr null, i64 1, i1 false)\nret void", true},
		{"memory-source", "declare void @llvm.memcpy.p0.pSEG.i64(ptr, ptr addrspace(SEG), i64, i1)",
			"call void @llvm.memcpy.p0.pSEG.i64(ptr null, ptr addrspace(SEG) null, i64 1, i1 false)\nret void", true},
		{"memory-move-source", "declare void @llvm.memmove.p0.pSEG.i64(ptr, ptr addrspace(SEG), i64, i1)",
			"call void @llvm.memmove.p0.pSEG.i64(ptr null, ptr addrspace(SEG) null, i64 1, i1 false)\nret void", true},
		{"memory-set", "declare void @llvm.memset.pSEG.i64(ptr addrspace(SEG), i8, i64, i1)",
			"call void @llvm.memset.pSEG.i64(ptr addrspace(SEG) null, i8 0, i64 1, i1 false)\nret void", true},
		{"zero-memory-copy", "declare void @llvm.memcpy.pSEG.p0.i64(ptr addrspace(SEG), ptr, i64, i1)",
			"call void @llvm.memcpy.pSEG.p0.i64(ptr addrspace(SEG) null, ptr null, i64 0, i1 false)\nret void", false},
		{"zero-memory-move", "declare void @llvm.memmove.p0.pSEG.i64(ptr, ptr addrspace(SEG), i64, i1)",
			"call void @llvm.memmove.p0.pSEG.i64(ptr null, ptr addrspace(SEG) null, i64 0, i1 true)\nret void", false},
		{"zero-memory-set", "declare void @llvm.memset.pSEG.i64(ptr addrspace(SEG), i8, i64, i1)",
			"call void @llvm.memset.pSEG.i64(ptr addrspace(SEG) null, i8 0, i64 0, i1 false)\nret void", false},
		{"bundle-pointer-transport", "declare void @consumer()",
			"call void @consumer() [\"deopt\"(ptr addrspace(SEG) null)]\nret void", false},
		{"pure-pointer-transport", "declare void @consumer(ptr addrspace(SEG)) memory(none)",
			"call void @consumer(ptr addrspace(SEG) null)\nret void", false},
		{"pure-callsite-transport", "declare void @consumer(ptr addrspace(SEG))",
			"call void @consumer(ptr addrspace(SEG) null) memory(none)\nret void", false},
		{"unused-declaration", "declare void @consumer(ptr addrspace(SEG))", "ret void", false},
		{"unused-pointer-constant", "@address = private constant ptr addrspace(SEG) null", "ret void", false},
		{"address-without-access", "", "%v = getelementptr i8, ptr addrspace(SEG) null, i64 1\nret void", false},
		{"pointer-value-in-ordinary-memory", "", "%v = load ptr addrspace(SEG), ptr null\nret void", false},
		{"stored-pointer-in-ordinary-memory", "", "store ptr addrspace(SEG) null, ptr null\nret void", false},
		{"ordinary-load", "", "%v = load volatile i32, ptr null\nret void", false},
	}
	for _, length := range []struct {
		name, typ, value string
		hardware         bool
	}{
		{"zero-wide", "i128", "0", false},
		{"nonzero-wide", "i128", "18446744073709551616", true},
		{"unknown", "i64", "%length", true},
	} {
		for _, source := range []bool{false, true} {
			destination, input, suffix := "ptr addrspace(SEG)", "ptr", "pSEG.p0"
			if source {
				destination, input, suffix = input, destination, "p0.pSEG"
			}
			intrinsic := "llvm.memcpy." + suffix + "." + length.typ
			declaration := fmt.Sprintf("declare void @%s(%s, %s, %s, i1)", intrinsic, destination, input, length.typ)
			prefix := ""
			if length.name == "unknown" {
				declaration += "\ndeclare i64 @length()"
				prefix = "%length = call i64 @length()\n"
			}
			rows = append(rows, memoryUse{fmt.Sprintf("%s-memory-source=%t", length.name, source), declaration,
				prefix + fmt.Sprintf("call void @%s(%s null, %s null, %s %s, i1 false)\nret void",
					intrinsic, destination, input, length.typ, length.value), length.hardware})
		}
	}
	for _, shape := range []struct{ name, width, suffix string }{
		{"fixed", "2", "v2"}, {"scalable", "vscale x 2", "nxv2"},
	} {
		value := "<" + shape.width + " x i32>"
		mask := "<" + shape.width + " x i1>"
		pointers := "<" + shape.width + " x ptr addrspace(SEG)>"
		gather := "llvm.masked.gather." + shape.suffix + "i32." + shape.suffix + "pSEG"
		scatter := "llvm.masked.scatter." + shape.suffix + "i32." + shape.suffix + "pSEG"
		rows = append(rows, memoryUse{shape.name + "-gather",
			fmt.Sprintf("declare %s @%s(%s, i32, %s, %s)", value, gather, pointers, mask, value),
			fmt.Sprintf("%%v = call %s @%s(%s zeroinitializer, i32 4, %s splat (i1 true), %s zeroinitializer)\nret void",
				value, gather, pointers, mask, value), true}, memoryUse{shape.name + "-scatter",
			fmt.Sprintf("declare void @%s(%s, %s, i32, %s)", scatter, value, pointers, mask),
			fmt.Sprintf("call void @%s(%s zeroinitializer, %s zeroinitializer, i32 4, %s splat (i1 true))\nret void",
				scatter, value, pointers, mask), true}, memoryUse{shape.name + "-pure-pointer-transport",
			fmt.Sprintf("declare void @consumer(%s) memory(none)", pointers),
			fmt.Sprintf("call void @consumer(%s zeroinitializer)\nret void", pointers), false})
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, space := range []int{256, 257} {
			for _, row := range rows {
				other := "386"
				if arch == "386" {
					other = "amd64"
				}
				for _, triple := range []string{testTargetTriple("linux", arch), testTargetTriple("linux", other), "", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					t.Run(fmt.Sprintf("%s/%d/%s/%s", arch, space, row.name, triple), func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						source := fmt.Sprintf("target triple = %q\n%s\ndefine void @ordinary() {\n%s\n}\n", triple, row.declaration, row.body)
						source = strings.ReplaceAll(source, "SEG", fmt.Sprint(space))
						module, err := parseIRModuleInContext(ctx, source)
						if err != nil {
							t.Fatal("independent hardware-use fixture is invalid LLVM IR", err)
						}
						defer module.Dispose()
						if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
							t.Fatal("independent hardware-use fixture failed LLVM verification", err)
						}
						err = validateTranslatedBackend(&File{Arch: ArchAMD64}, Options{Goarch: arch}, module)
						if row.hardware && triple != testTargetTriple("linux", arch) {
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("ACTUAL_SEGMENT_MEMORY_USE_ESCAPED_BACKEND", err)
							}
						} else if err != nil {
							t.Fatal("unused address space, ordinary memory or matching hardware target was rejected", err)
						}
					})
				}
			}
		}
	}
}
