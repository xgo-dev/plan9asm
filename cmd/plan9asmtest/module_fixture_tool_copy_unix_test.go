//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Tools in a relocated fixture must own independent inodes. Hard-linking a
// host library makes fixture cleanup mutate that library's change time.
func copyModuleFixtureTool(source, destination string) error {
	return copyModuleFixtureToolExtent(source, destination, moduleFixtureToolMaxBytes)
}

func copyModuleFixtureToolExtent(source, destination string, limit int64) (resultErr error) {
	if limit < 0 || limit > moduleFixtureToolMaxBytes {
		return fmt.Errorf("invalid fixture tool copy extent bound")
	}
	before, err := observeModuleFixtureTool(source)
	if err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit ||
		!reflect.DeepEqual(before.Metadata, moduleFixtureStableMetadata(info)) {
		return fmt.Errorf("fixture source tool role or extent changed")
	}
	parentName := filepath.Dir(destination)
	parent, err := os.Stat(parentName)
	if err != nil || !parent.IsDir() {
		return fmt.Errorf("fixture tool destination parent is unavailable: %w", err)
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	outputOpen := true
	defer func() {
		if outputOpen {
			resultErr = errors.Join(resultErr, output.Close())
		}
	}()
	created, err := output.Stat()
	if err != nil {
		return err
	}
	if !created.Mode().IsRegular() || os.SameFile(info, created) {
		return fmt.Errorf("fixture copy did not create an independent regular inode")
	}
	digest := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, info.Size()))
	var extra [1]byte
	n, eofErr := input.Read(extra[:])
	end, statErr := input.Stat()
	closeErr := output.Close()
	outputOpen = false
	if err := errors.Join(copyErr, statErr, closeErr); err != nil {
		return err
	}
	if count != info.Size() || n != 0 || eofErr != io.EOF {
		return fmt.Errorf("fixture tool copy did not consume its exact extent and complete EOF: %v", eofErr)
	}
	if !os.SameFile(info, end) || !reflect.DeepEqual(before.Metadata, moduleFixtureStableMetadata(end)) {
		return fmt.Errorf("fixture source tool changed during streaming copy")
	}
	after, err := observeModuleFixtureTool(source)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("fixture source tool bytes or metadata changed during copy")
	}
	parentAfter, err := os.Stat(parentName)
	if err != nil || !os.SameFile(parent, parentAfter) {
		return fmt.Errorf("fixture destination parent identity changed: %w", err)
	}
	actual, err := os.Stat(destination)
	if err != nil || !os.SameFile(created, actual) || os.SameFile(info, actual) {
		return fmt.Errorf("fixture destination tool identity changed: %w", err)
	}
	copied, err := observeModuleFixtureTool(destination)
	if err != nil {
		return err
	}
	if copied.SHA256 != before.SHA256 || copied.SHA256 != hex.EncodeToString(digest.Sum(nil)) || actual.Size() != info.Size() {
		return fmt.Errorf("fixture destination tool bytes differ from the complete selected source")
	}
	return nil
}

func TestModuleFixtureToolCopyIndependentInodeAndCompleteBytes(t *testing.T) {
	for _, size := range []int{0, 1, 17, 32768, 32769} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			directory := t.TempDir()
			source, destination := filepath.Join(directory, "host"), filepath.Join(directory, "owned")
			data := make([]byte, size)
			for index := range data {
				data[index] = byte(index*73 + index/251)
			}
			if err := os.WriteFile(source, data, 0700); err != nil {
				t.Fatal(err)
			}
			before, err := observeModuleFixtureTool(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := copyModuleFixtureToolExtent(source, destination, int64(size)); err != nil {
				t.Fatal(err)
			}
			copied, err := os.ReadFile(destination)
			if err != nil || !reflect.DeepEqual(copied, data) {
				t.Fatal("independent copy omitted source bytes", err)
			}
			originalInfo, originalErr := os.Stat(source)
			copyInfo, copyErr := os.Stat(destination)
			if originalErr != nil || copyErr != nil || os.SameFile(originalInfo, copyInfo) {
				t.Fatal("fixture copy still shares the original inode")
			}
			if err := os.Remove(destination); err != nil {
				t.Fatal(err)
			}
			after, err := observeModuleFixtureTool(source)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("owned copy removal changed original tool", err)
			}
		})
	}
}

func TestModuleFixtureToolCopyRejectsInvalidRolesAndBounds(t *testing.T) {
	for _, row := range []string{"missing source", "directory source", "over bound", "negative bound", "existing destination", "destination symlink", "missing parent"} {
		t.Run(row, func(t *testing.T) {
			directory := t.TempDir()
			source, destination := filepath.Join(directory, "host"), filepath.Join(directory, "owned")
			if err := os.WriteFile(source, []byte("actual fixture bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := observeModuleFixtureTool(source)
			if err != nil {
				t.Fatal(err)
			}
			limit := moduleFixtureToolMaxBytes
			switch row {
			case "missing source":
				source = filepath.Join(directory, "missing")
			case "directory source":
				source = directory
			case "over bound":
				limit = 1
			case "negative bound":
				limit = -1
			case "existing destination":
				if err := os.WriteFile(destination, []byte("foreign destination"), 0600); err != nil {
					t.Fatal(err)
				}
			case "destination symlink":
				if err := os.Symlink(source, destination); err != nil {
					t.Fatal(err)
				}
			case "missing parent":
				destination = filepath.Join(directory, "missing", "owned")
			}
			if err := copyModuleFixtureToolExtent(source, destination, limit); err == nil {
				t.Fatal("invalid source/destination role or bound accepted")
			}
			after, err := observeModuleFixtureTool(filepath.Join(directory, "host"))
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failed copy altered original physical tool", err)
			}
			if row == "existing destination" {
				data, err := os.ReadFile(destination)
				if err != nil || string(data) != "foreign destination" {
					t.Fatal("failed exclusive creation altered foreign destination", err)
				}
			}
		})
	}
}
