package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestLLVMIRParsingRetainsDistinctModuleIdentity(t *testing.T) {
	const body = `@cell = private global i32 7
define i32 @read_cell() {
  %value = load volatile i32, ptr @cell
  ret i32 %value
}
`
	for _, test := range []struct {
		name   string
		header string
	}{
		{"default", ""},
		{"explicit", "source_filename = \"original-observer.s\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			context := llvm.NewContext()
			defer context.Dispose()
			first, err := parseIRModuleInContext(context, test.header+body)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Dispose()
			second, err := parseIRModuleInContext(context, test.header+body)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Dispose()
			for _, module := range []llvm.Module{first, second} {
				if module.Context() != context || module.NamedFunction("read_cell").IsNil() {
					t.Fatal("module lost its caller context or private-global reader")
				}
				cell := module.NamedGlobal("cell")
				if cell.IsNil() || cell.Linkage() != llvm.PrivateLinkage {
					t.Fatal("module lost its actual private global")
				}
				if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
					t.Fatal(err)
				}
			}
			field := func(module llvm.Module, prefix string) string {
				for _, line := range strings.Split(module.String(), "\n") {
					if strings.HasPrefix(line, prefix) {
						value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
						if value == "" || value == "''" || value == "\"\"" {
							t.Fatalf("module has an empty %s", prefix)
						}
						return value
					}
				}
				t.Fatalf("module lacks %s", prefix)
				return ""
			}
			firstID, secondID := field(first, "; ModuleID = "), field(second, "; ModuleID = ")
			if firstID == secondID {
				t.Errorf("separately parsed modules reused ModuleID %s", firstID)
			}
			firstSource, secondSource := field(first, "source_filename = "), field(second, "source_filename = ")
			if test.header == "" {
				if firstSource == secondSource {
					t.Errorf("separately parsed modules reused default source_filename %s", firstSource)
				}
			} else if firstSource != "\"original-observer.s\"" || secondSource != firstSource {
				t.Errorf("explicit source_filename changed: %s, %s", firstSource, secondSource)
			}
		})
	}
}
