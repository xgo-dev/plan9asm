package plan9asm

import "strconv"

// Clang binds the raw LLVM symbol, while GNU emits the label into assembler
// text, where qualified Go symbols need another quoting layer. Keep those
// distinct roles without adding quotes to the symbol itself.
const runtimeCAsmLabelPreamble = `
#ifdef __clang__
#define PLAN9ASM_C_ASM_LABEL(name) name
#else
#define PLAN9ASM_C_ASM_LABEL(name) "\"" name "\""
#endif
`

func runtimeCAsmLabel(symbol string) string {
	return "PLAN9ASM_C_ASM_LABEL(" + strconv.Quote(symbol) + ")"
}
