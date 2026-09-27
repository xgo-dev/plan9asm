package plan9asm

// Set VL only in a non-SVE frame, then enter a fresh, non-inlined test frame.
// Changing VL inside an SVE-compiled C function can invalidate the compiler's
// scalable spill slots. In particular, the integer-unary oracle reproduced a
// stack-canary failure when its loop changed VL inside that same frame.
func arm64SVEVectorLengthMain(declarations, checks string) string {
	return arm64SVEVectorLengthsMain(declarations, checks, "16, 32, 48, 64, 128, 256")
}

func arm64SVEVectorLengthsMain(declarations, checks, lengths string) string {
	return "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <sys/prctl.h>\n" + declarations + `
__attribute__((noinline)) static int check_length(unsigned vl) {
` + checks + `
  return 0;
}

__attribute__((target("arch=armv8-a")))
int main(void) {
  const unsigned lengths[] = {` + lengths + `};
  for (unsigned i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
    unsigned vl = lengths[i];
    if (prctl(PR_SVE_SET_VL, vl) != (int)vl) return 99;
    int result = check_length(vl);
    if (result) return result;
  }
  return 0;
}
`
}
