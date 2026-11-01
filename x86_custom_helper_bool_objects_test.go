package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RegisterHelperCanonicalBoolCompleteSETccObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			_, options := x86CustomHelperBoolFixture(t, "", triple)
			root, helper := options.Sigs["compare"], options.Sigs["comparebody"]
			options.Sigs = make(map[string]FuncSig)
			var assembly strings.Builder
			for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
				name, body := "compare"+condition, "body"+condition
				fmt.Fprintf(&assembly, "TEXT %s(SB),NOSPLIT,$0-12\nMOVL a+0(FP),SI\nMOVL b+4(FP),DI\n"+
					"LEAL ret+8(FP),AX\nJMP %s<>(SB)\nTEXT %s<>(SB),NOSPLIT,$0-0\nCMPL SI,DI\nSET%s (AX)\nRET\n", name, body, body, condition)
				root.Name, helper.Name = name, body
				options.Sigs[name], options.Sigs[body] = root, helper
			}
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil || len(file.Funcs) != 32 || len(options.Sigs) != 32 {
				t.Fatal("complete sixteen-condition root/helper family changed", err)
			}
			receipt := x86LEAActualTargetGoObject(t, "386", triple, "#define NOSPLIT 4\n"+assembly.String())
			t.Logf("actual original Go object: %+v", receipt)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86CustomHelperBoolAPI(t, file, options, api)
					if err != nil || strings.Count(ir, "call void @body") != 16 {
						t.Fatal("actual explicit register calls were changed or omitted", err)
					}
					for _, optimized := range []bool{false, true} {
						t.Run(fmt.Sprint("O2=", optimized), func(t *testing.T) {
							input := ir
							if optimized {
								input = x86UndefinedTrapOptimizedIR(t, input)
							}
							compileLLVMToObject(t, llc, triple, "register-bool.ll", "register-bool.o", input)
						})
					}
				})
			}
		})
	}
}
