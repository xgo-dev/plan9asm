//go:build go1.27

package gotoolprofile

import "testing"

func TestAMD64DownloadedDefaultLanguageLLVM22Objects(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, target := range []struct{ goos, triple string }{
		{"linux", "x86_64-unknown-linux-gnu"},
		{"darwin", "x86_64-apple-macosx"},
		{"windows", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			fixture := captureAMD64DownloadedLLVMVariantFixture(t, ctx, target.goos, target.triple, "fixed-local-no-go")
			if fixture.observed.state.packages[fixture.pkg.Path].Module.GoVersion != "1.16" {
				t.Fatal("object consumer lost the actual implicit main-module language")
			}
			llc := amd64DownloadedLLVM22Tool(t, ctx, fixture, "llc")
			for _, api := range []string{"Translate", "Module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir := fixture.ir(t, api)
					for _, level := range []string{"-O0", "-O2"} {
						fixture.object(t, ctx, llc, ir, level)
					}
				})
			}
			if err := fixture.binding.Verify(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
