package preprocess

import "testing"

func TestHasDirective(t *testing.T) {
	for src, want := range map[string]bool{
		"// #include \"missing.h\"\nTEXT f(SB),4,$0\n": false,
		"/*\n#define X 3\n*/":                          false,
		"DATA foo(SB)/2, $\"#x\"":                      false,
		"/* comment */ #include \"table.h\"":           true,
		"// text\n  #ifdef GOOS_linux\n":               true,
	} {
		if got := HasDirective([]byte(src)); got != want {
			t.Errorf("%q: %v", src, got)
		}
	}
}
