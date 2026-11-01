package plan9asm

import (
	"testing"

	"github.com/xgo-dev/llvm"
)

// These independent IR fixtures exercise only footprint observation. They
// cannot produce an input-pointer, source, raw or native-memory permission.
func TestX86X87ENVFootprintReaderHandlesOptimizedPointerValues(t *testing.T) {
	for _, row := range []struct {
		name, body string
		good       bool
	}{
		{"pointer-argument", `entry:
%v = load volatile i224, ptr %a, align 1
ret void`, true},
		{"selected-arguments", `entry:
%p = select i1 %gate, ptr %a, ptr %b
%v = load volatile i224, ptr %p, align 1
ret void`, true},
		{"joined-arguments", `entry:
br i1 %gate, label %left, label %right
left:
br label %join
right:
br label %join
join:
%p = phi ptr [%a, %left], [%b, %right]
%v = load volatile i224, ptr %p, align 1
ret void`, true},
		{"selected-different-offsets", `entry:
%offset = getelementptr i8, ptr %b, i64 1
%p = select i1 %gate, ptr %a, ptr %offset
%v = load volatile i224, ptr %p, align 1
ret void`, false},
		{"selected-null", `entry:
%p = select i1 %gate, ptr %a, ptr null
%v = load volatile i224, ptr %p, align 1
ret void`, false},
		{"joined-different-offsets", `entry:
%offset = getelementptr i8, ptr %b, i64 1
br i1 %gate, label %left, label %right
left:
br label %join
right:
br label %join
join:
%p = phi ptr [%a, %left], [%offset, %right]
%v = load volatile i224, ptr %p, align 1
ret void`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ir := "define void @EnvRead(ptr %a, ptr %b, i1 %gate) {\n" + row.body + "\n}\n"
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := parseIRModuleInContext(context, ir)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal("independent reader fixture must parse", err)
			}
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal("independent reader fixture must be valid LLVM IR", err)
			}
			if err := x86X87ENVReadFootprint(ir, 0); (err == nil) != row.good {
				t.Fatal("footprint reader confused pointer normalization with a complete read", err)
			}
		})
	}
}
