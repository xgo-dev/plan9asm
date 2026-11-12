package plan9asm

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64FrameSDKSourcePCPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sdk")
	file := filepath.Join(root, "src", "sample", "input.s")
	directory := filepath.Dir(file)
	for _, mutation := range []string{
		"original", "absolute", "ordinary source", "different root", "missing input",
		"wrong line", "wrong listing", "dot segment", "parent segment", "double slash",
		"foreign file", "invalid origin",
	} {
		t.Run(mutation, func(t *testing.T) {
			text := gostaticstorage.TextRecord{Name: "sample.Value", Positions: []gostaticstorage.TextPosition{
				{Start: 0, End: 1, File: "$GOROOT/src/sample/input.s", Line: 2},
			}}
			fn := goAMD64FrameFunction{code: []byte{0xc3}, sourcePositions: map[int][]goAMD64FrameSourcePosition{
				0: {{file: file, line: 2}},
			}}
			origins := map[string]int{file: 3}
			capturedRoot := root
			switch mutation {
			case "absolute":
				text.Positions[0].File = file
			case "ordinary source":
				capturedRoot = ""
			case "different root":
				capturedRoot = filepath.Join(root, "other")
			case "missing input":
				delete(origins, file)
			case "wrong line":
				text.Positions[0].Line = 4
			case "wrong listing":
				fn.sourcePositions[0][0].line = 3
			case "dot segment":
				text.Positions[0].File = "$GOROOT/src/sample/./input.s"
			case "parent segment":
				text.Positions[0].File = "$GOROOT/src/sample/../sample/input.s"
			case "double slash":
				text.Positions[0].File = "$GOROOT/src//sample/input.s"
			case "foreign file":
				text.Positions[0].File = "$GOROOT/src/sample/foreign.s"
			case "invalid origin":
				text.Positions[0].File = "$GOROOT/src/sample/./input.s"
				origins[text.Positions[0].File] = 3
				fn.sourcePositions[0][0].file = text.Positions[0].File
			}
			err := goAMD64FrameSourcePCs(text, fn, directory, origins, capturedRoot)
			wantPass := mutation == "original" || mutation == "absolute"
			if wantPass && err != nil || !wantPass && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("captured original object/listing source paths: %v", err)
			}
		})
	}
}
