package gooriginalsrc

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileProxyURLPreservesLocalPathAndSeparators(t *testing.T) {
	for _, path := range []string{
		"/tmp/module proxy", "C:/module proxy", "D:/a,b|c#d%20/中文",
		"//server/share/proxy", "/tmp/a,b|c#d%20/中文",
	} {
		encoded := fileProxyURL(path)
		parsed, err := url.Parse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		want := path
		if !strings.HasPrefix(want, "/") {
			want = "/" + want
		}
		if parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != want ||
			parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(encoded, ",|") {
			t.Fatalf("%q changed local proxy identity: %q", path, encoded)
		}
	}
	directory := filepath.Join(t.TempDir(), "local,proxy|only")
	if got, err := FileProxyURL(directory); err != nil || got != fileProxyURL(filepath.ToSlash(directory)) {
		t.Fatal("host path conversion differs", got, err)
	}
	for _, relative := range []string{"", ".", "proxy"} {
		if _, err := FileProxyURL(relative); err == nil {
			t.Fatal("relative proxy directory accepted", relative)
		}
	}
}
