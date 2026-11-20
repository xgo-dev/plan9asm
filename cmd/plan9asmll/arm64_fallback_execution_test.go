package main

import "testing"

func TestFallbackARM64OracleExecutionModes(t *testing.T) {
	for _, row := range []struct {
		goos, goarch, cross string
		want                string
		failure             bool
	}{
		{"darwin", "arm64", "", "native", false},
		{"linux", "arm64", "", "native", false},
		{"linux", "arm64", "1", "native", false},
		{"linux", "amd64", "1", "cross", false},
		{"linux", "amd64", "", "", false},
		{"linux", "amd64", "0", "", false},
		{"windows", "arm64", "", "", false},
		{"windows", "amd64", "", "", false},
		{"darwin", "arm64", "1", "", true},
		{"windows", "amd64", "1", "", true},
		{"linux", "386", "1", "", true},
		{"linux", "amd64", "true", "", true},
	} {
		t.Run(row.goos+"/"+row.goarch+"/cross="+row.cross, func(t *testing.T) {
			got, err := fallbackARM64OracleExecution(row.goos, row.goarch, row.cross)
			if got != row.want || (err != nil) != row.failure {
				t.Fatalf("execution mode=%q, error=%v; want %q, failure=%t", got, err, row.want, row.failure)
			}
		})
	}
}
